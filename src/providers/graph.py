"""
providers/graph.py — Microsoft Graph mailbox provider.

Authenticates via the n8n token broker (CALENDAR_URL + B2B_TOKEN),
matching the protocol the existing email-engine uses so the same broker
is reused. The broker is a POST that returns
  [{"bearer_token": "...", "minutes_left": 50}]
which we cache in-memory until 2 min before expiry.

This file is the Python port of email-engine's internal/graph/{token,client}.go.
Endpoints reused without modification — same Graph $select, same retry,
same folder-locate logic.
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests

from .base import Message, Provider

log = logging.getLogger(__name__)


GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"


# Outlook master-category preset colors. Mapped from the leading digit
# of the verdict name so 1-Critical = red, 5-Low-Ignore = green, etc.
# Matches the dashboard's verdict_class CSS buckets in web.py.
# Preset reference: https://learn.microsoft.com/en-us/graph/api/resources/outlookcategory
_PRESET_COLOR_BY_DIGIT = {
    "1": "preset0",  # Red    — critical
    "2": "preset1",  # Orange — high
    "3": "preset8",  # Purple — personal
    "4": "preset3",  # Yellow — medium
    "5": "preset4",  # Green  — low / ignore
}
_PRESET_COLOR_FALLBACK = "preset12"  # Gray


def _preset_color_for(name: str) -> str:
    """First digit in the category name picks the color. Anything with no
    digit gets gray — keeps non-conforming taxonomies functional but
    visually distinct from the bucketed ones."""
    for ch in name:
        if ch.isdigit():
            return _PRESET_COLOR_BY_DIGIT.get(ch, _PRESET_COLOR_FALLBACK)
    return _PRESET_COLOR_FALLBACK

MESSAGE_SELECT = (
    "id,conversationId,internetMessageId,subject,bodyPreview,body,from,"
    "toRecipients,ccRecipients,receivedDateTime,sentDateTime,categories,"
    "parentFolderId"
)


# --- Token broker ----------------------------------------------------------

class TokenBroker:
    """Caches a Graph bearer token between calls. Thread-safe.

    Protocol (matches email-engine's existing broker):
      POST {url}
      Headers: Content-Type: application/json, bearer: {bearer}
      Body: [{"token_check":"start"}]
      → 200, body: [{"bearer_token": "...", "minutes_left": 50}]
    """

    def __init__(self, url: str, bearer: str):
        self.url = url
        self.bearer = bearer
        self._cache: str | None = None
        self._expires: float = 0
        self._lock = threading.Lock()

    def token(self) -> str:
        with self._lock:
            now = time.time()
            # Refresh 2 minutes before expiry so a long-running call doesn't
            # fall off the cliff mid-request.
            if self._cache and now + 120 < self._expires:
                return self._cache
            if not self.url or not self.bearer:
                raise RuntimeError("CALENDAR_URL and B2B_TOKEN must be set")

            resp = requests.post(
                self.url,
                headers={"Content-Type": "application/json", "bearer": self.bearer},
                data='[{"token_check":"start"}]',
                timeout=15,
            )
            if resp.status_code != 200:
                raise RuntimeError(f"token broker returned {resp.status_code}: {resp.text[:200]}")
            arr = resp.json()
            if not arr or not arr[0].get("bearer_token"):
                raise RuntimeError("no bearer_token in broker response")
            mins = float(arr[0].get("minutes_left") or 50)
            self._cache = arr[0]["bearer_token"]
            self._expires = now + (mins * 60)
            return self._cache


def broker_from_env() -> TokenBroker:
    return TokenBroker(
        url=os.getenv("CALENDAR_URL", ""),
        bearer=os.getenv("B2B_TOKEN", ""),
    )


# --- HTTP helper -----------------------------------------------------------

def _do_json(
    broker: TokenBroker,
    method: str,
    endpoint: str,
    body: dict | None = None,
    max_attempts: int = 4,
) -> dict | None:
    last_err: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            tok = broker.token()
            headers = {
                "Authorization": f"Bearer {tok}",
                "Accept": "application/json",
                "Prefer": 'outlook.body-content-type="text"',
            }
            if body is not None:
                headers["Content-Type"] = "application/json"
            resp = requests.request(
                method, endpoint,
                headers=headers,
                data=json.dumps(body) if body is not None else None,
                timeout=30,
            )
            if resp.status_code in (429,) or resp.status_code >= 500:
                wait = _retry_after(resp.headers.get("Retry-After")) or _backoff(attempt)
                log.warning("graph %s %s -> %d, retry in %.1fs", method, endpoint, resp.status_code, wait)
                last_err = RuntimeError(f"graph {method} {endpoint} -> {resp.status_code}: {resp.text[:300]}")
                time.sleep(wait)
                continue
            if not (200 <= resp.status_code < 300):
                raise RuntimeError(f"graph {method} {endpoint} -> {resp.status_code}: {resp.text[:300]}")
            if resp.status_code == 204 or not resp.content:
                return None
            return resp.json()
        except requests.RequestException as e:
            last_err = e
            time.sleep(_backoff(attempt))
    if last_err:
        raise last_err
    return None


def _retry_after(h: str | None) -> float:
    if not h:
        return 0
    try:
        return float(int(h))
    except ValueError:
        return 0


def _backoff(attempt: int) -> float:
    base = 0.5 * (2 ** (attempt - 1))
    base = min(base, 8.0)
    jitter = random.uniform(-base * 0.25, base * 0.25)
    return base + jitter


# --- Provider implementation ----------------------------------------------

class GraphProvider(Provider):
    def __init__(self, mailbox: str, broker: TokenBroker | None = None):
        self._email = mailbox
        self._broker = broker or broker_from_env()
        self._folder_cache: dict[str, str] = {}  # name -> id

    @property
    def email(self) -> str:
        return self._email

    # --- reads --------------------------------------------------------------

    def list_inbox(self, since: datetime | None, limit: int) -> list[Message]:
        return self.list_folder("inbox", since, limit, descending=False)

    def list_folder(
        self,
        folder_name: str,
        since: datetime | None,
        limit: int,
        descending: bool = False,
    ) -> list[Message]:
        """List messages in a folder. `folder_name` is either a well-known
        Graph alias ('inbox') or a displayName we locate. Returns [] if the
        folder doesn't exist (so the reclassify sweep can safely walk a list
        of legacy folder names without crashing on the ones that aren't there).

        Order + filter semantics flip with `descending` — see Provider.list_folder."""
        # Resolve folder identifier: 'inbox' is a Graph well-known alias;
        # everything else needs a displayName lookup.
        if folder_name.lower() == "inbox":
            folder_id = "inbox"
        else:
            folder_id = self._find_folder_id(folder_name)
            if not folder_id:
                return []

        endpoint = (
            f"{GRAPH_API_BASE}/users/{quote(self._email)}"
            f"/mailFolders/{quote(folder_id, safe='')}/messages"
        )
        q = {
            "$select": MESSAGE_SELECT,
            "$orderby": "receivedDateTime desc" if descending else "receivedDateTime asc",
            "$top": str(max(1, min(limit, 100))),
        }
        if since:
            iso = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            op = "lt" if descending else "gt"
            q["$filter"] = f"receivedDateTime {op} {iso}"
        url = endpoint + "?" + _qs(q)
        data = _do_json(self._broker, "GET", url) or {}
        return [_msg_from_graph(m) for m in data.get("value", [])]

    def _find_folder_id(self, name: str) -> str:
        """Best-effort lookup: check inbox children first, then root folders."""
        if name in self._folder_cache:
            return self._folder_cache[name]
        inbox_id = self._get_folder_id("inbox")
        fid = self._search_folder(
            f"{GRAPH_API_BASE}/users/{quote(self._email)}/mailFolders/{inbox_id}/childFolders",
            name,
        )
        if not fid:
            fid = self._search_folder(
                f"{GRAPH_API_BASE}/users/{quote(self._email)}/mailFolders",
                name,
            )
        if fid:
            self._folder_cache[name] = fid
        return fid

    def get_message(self, message_id: str) -> Message | None:
        endpoint = (
            f"{GRAPH_API_BASE}/users/{quote(self._email)}/messages/{quote(message_id, safe='')}?"
            f"$select={MESSAGE_SELECT}"
        )
        try:
            data = _do_json(self._broker, "GET", endpoint)
            return _msg_from_graph(data) if data else None
        except RuntimeError as e:
            if "-> 404" in str(e):
                return None
            raise

    def get_thread(self, conversation_id: str) -> list[Message]:
        endpoint = f"{GRAPH_API_BASE}/users/{quote(self._email)}/messages"
        # Graph rejects $filter conversationId + $orderby receivedDateTime as
        # "InefficientFilter". Filter only, then sort client-side.
        q = {
            "$select": MESSAGE_SELECT,
            "$top": "50",
            "$filter": f"conversationId eq '{_escape_odata(conversation_id)}'",
        }
        out: list[Message] = []
        url = endpoint + "?" + _qs(q)
        while url:
            data = _do_json(self._broker, "GET", url) or {}
            out.extend(_msg_from_graph(m) for m in data.get("value", []))
            url = data.get("@odata.nextLink") or ""
        out.sort(key=lambda m: m.received_at or datetime.min.replace(tzinfo=timezone.utc))
        return out

    # --- mutations ----------------------------------------------------------

    def set_categories(self, message_id: str, categories: list[str]) -> None:
        endpoint = f"{GRAPH_API_BASE}/users/{quote(self._email)}/messages/{quote(message_id, safe='')}"
        _do_json(self._broker, "PATCH", endpoint, body={"categories": categories})

    def append_to_body(
        self, message_id: str, *, html_snippet: str, text_snippet: str,
    ) -> bool:
        """GET current body + contentType, append the matching snippet,
        PATCH back. Best-effort: returns False (and logs) on any Graph
        error so the poller continues even if a message can't be modified
        (rare: messages stuck in remote folders, message moved out from
        under us between cycles, etc.)."""
        endpoint = (
            f"{GRAPH_API_BASE}/users/{quote(self._email)}"
            f"/messages/{quote(message_id, safe='')}"
        )
        try:
            data = _do_json(self._broker, "GET", endpoint + "?$select=body") or {}
        except Exception as e:
            log.warning("[%s] append_to_body GET failed for %s: %s",
                        self._email, message_id[:24], e)
            return False
        body = data.get("body") or {}
        content_type = (body.get("contentType") or "html").lower()
        content = body.get("content") or ""

        if content_type == "html":
            new_content = _append_html_footer(content, html_snippet)
        else:
            new_content = (content.rstrip() + "\n\n" + text_snippet).strip()

        try:
            _do_json(self._broker, "PATCH", endpoint, body={
                "body": {"contentType": content_type, "content": new_content},
            })
            return True
        except Exception as e:
            log.warning("[%s] append_to_body PATCH failed for %s: %s",
                        self._email, message_id[:24], e)
            return False

    def ensure_master_categories(self, names: list[str]) -> dict:
        """Register `names` in Outlook's Master Category List so they show
        up in the categories management UI / picker (and render with the
        digit-mapped color, not a blank/default).

        Without this, `set_categories` still works — Outlook accepts the
        string on the message — but the category is invisible in the
        Categories management view and rendered without a color. Master
        list registration is a separate Graph resource.

        Idempotent: GETs the existing list once, POSTs only missing
        names. Color is auto-derived from the leading digit of the name
        (matches the dashboard's verdict color buckets).

        Returns a dict with counts AND error messages so a Graph
        permission failure (commonly: app doesn't have the
        MailboxSettings.ReadWrite scope, which is REQUIRED for this
        endpoint even though Mail.ReadWrite is enough for messages +
        folders) surfaces visibly instead of dying in logs."""
        endpoint = (
            f"{GRAPH_API_BASE}/users/{quote(self._email)}/outlook/masterCategories"
        )
        out: dict = {
            "created": 0, "existed": 0, "errors": 0,
            "error_messages": [],
            "existing_names": [],
            "registered_names": [],
        }
        try:
            data = _do_json(self._broker, "GET", endpoint) or {}
            existing_list = [c.get("displayName") for c in data.get("value", [])
                             if c.get("displayName")]
            existing = set(existing_list)
            out["existing_names"] = existing_list
        except Exception as e:
            msg = (
                f"GET /outlook/masterCategories failed: {e}. "
                "If this is a 403 / Forbidden, the Graph app needs the "
                "'MailboxSettings.ReadWrite' application permission — "
                "Mail.ReadWrite alone doesn't cover the master category list."
            )
            log.warning("[%s] %s", self._email, msg)
            out["errors"] += 1
            out["error_messages"].append(msg)
            return out
        for name in names:
            if not name:
                continue
            if name in existing:
                out["existed"] += 1
                continue
            body = {"displayName": name, "color": _preset_color_for(name)}
            try:
                _do_json(self._broker, "POST", endpoint, body=body)
                out["created"] += 1
                out["registered_names"].append(name)
                log.info(
                    "[%s] registered master category %r color=%s",
                    self._email, name, body["color"],
                )
            except Exception as e:
                msg = f"POST {name!r}: {e}"
                log.exception(
                    "[%s] masterCategories %s", self._email, msg,
                )
                out["errors"] += 1
                out["error_messages"].append(msg)
        return out

    def ensure_search_folders(self, names: list[str]) -> dict:
        """Create or update one Outlook mail search folder per category
        name. Each search folder is a saved-query view that auto-lists
        messages tagged with that category — appears in Outlook's folder
        tree like a normal folder, no UI dance through the categories
        management panel.

        Why this is better than relying on the master category list:
          - search folders show up directly in the user's folder tree
            (one click to see "all 1-Critical messages")
          - they auto-update as the engine tags new mail
          - they're filterable, sortable, drag-droppable like real folders
          - the master category list (and its color UX) becomes optional
            polish rather than the primary affordance

        Source = Inbox (with includeNestedFolders=True). NOT
        msgfolderroot. Why: when a user clicks Archive in Outlook the
        message moves to the Archive folder, which is a SIBLING of
        Inbox, not a child. So an Inbox-rooted search folder naturally
        excludes archived items — operator clears the view by archiving,
        which is exactly the requested "todo list with archive-to-clear"
        UX. The verdict folders (1-Critical etc.) live under Inbox so
        they're included; Sent / Drafts / Junk / Outbox are excluded
        (they're siblings of Inbox, not children).

        State-convergent (not just create-if-missing): if a search
        folder with the same name already exists, GET its current
        sourceFolderIds + filterQuery + includeNestedFolders, and PATCH
        it back into engine spec when any drift is detected. This means
        older folders created with the wrong source (e.g.
        msgfolderroot from an earlier build) get auto-corrected on the
        next sync click. Only mailSearchFolder typed folders are
        touched — regular folders with the same name are left alone.

        Graph API refs:
          POST  /users/{id}/mailFolders/searchfolders/childFolders
          PATCH /users/{id}/mailFolders/{searchFolderId}
          docs: https://learn.microsoft.com/en-us/graph/api/mailsearchfolder-post
                https://learn.microsoft.com/en-us/graph/api/mailsearchfolder-update

        Returns counts + error messages in the same shape as
        ensure_master_categories so the UI plumbing matches. `updated`
        counts drift-corrections (existed-but-needed-PATCH)."""
        list_endpoint = (
            f"{GRAPH_API_BASE}/users/{quote(self._email)}"
            f"/mailFolders/searchfolders/childFolders"
        )
        single_endpoint_base = (
            f"{GRAPH_API_BASE}/users/{quote(self._email)}/mailFolders"
        )
        out: dict = {
            "created": 0, "existed": 0, "updated": 0, "errors": 0,
            "error_messages": [],
            "existing_names": [],
            "created_names": [],
            "updated_names": [],
        }

        # 1) List current search folders WITH their config so we can
        # detect drift on the ones that already exist.
        #
        # No $select: Graph validates $select against the BASE type
        # `mailFolder`. `filterQuery`, `sourceFolderIds`, and
        # `includeNestedFolders` are all subtype-specific
        # (mailSearchFolder) properties, so naming them in $select
        # returns 400 BadRequest ("Could not find a property named
        # 'filterQuery' on type 'microsoft.graph.mailFolder'").
        # Using the cast syntax `microsoft.graph.mailSearchFolder/<prop>`
        # works but is fiddly; just GET everything — the response is
        # tiny (≤10 folders typically) and these calls are infrequent.
        # Everything under the `searchfolders` parent is by definition
        # a mailSearchFolder so all subtype fields come through.
        try:
            data = _do_json(
                self._broker, "GET",
                list_endpoint + "?$top=100",
            ) or {}
            existing_folders: dict[str, dict] = {}
            for f in data.get("value", []):
                disp = f.get("displayName")
                if disp:
                    existing_folders[disp] = f
            out["existing_names"] = list(existing_folders.keys())
        except Exception as e:
            msg = (
                f"GET searchfolders failed: {e}. "
                "If this is a 403 / Forbidden, the Graph app needs "
                "Mail.ReadWrite (application permission)."
            )
            log.warning("[%s] %s", self._email, msg)
            out["errors"] += 1
            out["error_messages"].append(msg)
            return out

        # 2) Resolve the Inbox id (sourceFolderIds requires real ids,
        # not the well-known string "inbox"). With includeNestedFolders
        # = True this covers Inbox + any subfolders the engine made
        # (verdict folders) + any custom subfolders the user created.
        try:
            inbox_id = self._get_folder_id("inbox")
            if not inbox_id:
                raise RuntimeError("inbox returned empty id")
        except Exception as e:
            msg = f"GET inbox id failed: {e}"
            log.warning("[%s] %s", self._email, msg)
            out["errors"] += 1
            out["error_messages"].append(msg)
            return out

        # 3) For each requested name: PATCH if drifted, POST if missing,
        # skip if already in spec.
        desired_sources_set = {inbox_id}
        for name in names:
            if not name:
                continue
            desired_filter = f"categories/any(c:c eq '{_escape_odata(name)}')"

            existing = existing_folders.get(name)
            if existing:
                cur_filter = existing.get("filterQuery") or ""
                cur_sources = set(existing.get("sourceFolderIds") or [])
                cur_nested = bool(existing.get("includeNestedFolders"))
                in_spec = (
                    cur_filter == desired_filter
                    and cur_sources == desired_sources_set
                    and cur_nested is True
                )
                if in_spec:
                    out["existed"] += 1
                    continue
                # Drift detected → PATCH back into spec
                patch_url = f"{single_endpoint_base}/{quote(existing['id'], safe='')}"
                try:
                    _do_json(self._broker, "PATCH", patch_url, body={
                        "includeNestedFolders": True,
                        "sourceFolderIds": [inbox_id],
                        "filterQuery": desired_filter,
                    })
                    out["updated"] += 1
                    out["updated_names"].append(name)
                    log.info(
                        "[%s] patched search folder %r to inbox-source + canonical filter",
                        self._email, name,
                    )
                except Exception as e:
                    msg = f"PATCH {name!r}: {e}"
                    log.exception("[%s] searchfolders %s", self._email, msg)
                    out["errors"] += 1
                    out["error_messages"].append(msg)
                continue

            # Missing → POST to create
            body = {
                "@odata.type": "microsoft.graph.mailSearchFolder",
                "displayName": name,
                "includeNestedFolders": True,
                "sourceFolderIds": [inbox_id],
                "filterQuery": desired_filter,
            }
            try:
                _do_json(self._broker, "POST", list_endpoint, body=body)
                out["created"] += 1
                out["created_names"].append(name)
                log.info(
                    "[%s] created search folder %r filter=%r",
                    self._email, name, desired_filter,
                )
            except Exception as e:
                msg = f"POST {name!r}: {e}"
                log.exception("[%s] searchfolders %s", self._email, msg)
                out["errors"] += 1
                out["error_messages"].append(msg)
        return out

    def move_message(self, message_id: str, dest_folder: str) -> str:
        folder_id = self.ensure_folder(dest_folder)
        endpoint = f"{GRAPH_API_BASE}/users/{quote(self._email)}/messages/{quote(message_id, safe='')}/move"
        data = _do_json(self._broker, "POST", endpoint, body={"destinationId": folder_id}) or {}
        return data.get("id") or message_id

    def ensure_folder(self, name: str) -> str:
        if name in self._folder_cache:
            return self._folder_cache[name]
        # Well-known aliases: "inbox" (any case) resolves to the user's real
        # Inbox via Graph's reserved name, NOT to a child folder named "Inbox".
        # Without this, move_message(_, "INBOX") would silently create a fresh
        # folder literally called INBOX as a sibling of the real Inbox.
        if name.lower() == "inbox":
            inbox_id = self._get_folder_id("inbox")
            self._folder_cache[name] = inbox_id
            return inbox_id
        # Look under inbox first, then root.
        inbox_id = self._get_folder_id("inbox")
        fid = self._search_folder(
            f"{GRAPH_API_BASE}/users/{quote(self._email)}/mailFolders/{inbox_id}/childFolders",
            name,
        )
        if not fid:
            fid = self._search_folder(
                f"{GRAPH_API_BASE}/users/{quote(self._email)}/mailFolders",
                name,
            )
        if not fid:
            # Create under inbox.
            endpoint = (
                f"{GRAPH_API_BASE}/users/{quote(self._email)}/mailFolders/"
                f"{inbox_id}/childFolders"
            )
            data = _do_json(self._broker, "POST", endpoint, body={"displayName": name}) or {}
            fid = data["id"]
        self._folder_cache[name] = fid
        return fid

    # --- helpers ------------------------------------------------------------

    def _get_folder_id(self, name_or_id: str) -> str:
        endpoint = f"{GRAPH_API_BASE}/users/{quote(self._email)}/mailFolders/{quote(name_or_id)}?$select=id"
        data = _do_json(self._broker, "GET", endpoint) or {}
        return data.get("id", "")

    def _search_folder(self, endpoint: str, name: str) -> str:
        q = {
            "$select": "id,displayName",
            "$top": "100",
            "$filter": f"displayName eq '{_escape_odata(name)}'",
        }
        data = _do_json(self._broker, "GET", endpoint + "?" + _qs(q)) or {}
        for f in data.get("value", []):
            if f.get("displayName") == name:
                return f["id"]
        return ""


# --- Wire conversion --------------------------------------------------------

def _msg_from_graph(m: dict) -> Message:
    body = m.get("body") or {}
    body_content = body.get("content") or ""
    body_type = (body.get("contentType") or "").lower()
    if body_type == "html":
        body_text = _strip_html(body_content)
    else:
        body_text = body_content or m.get("bodyPreview") or ""

    from_ = (m.get("from") or {}).get("emailAddress") or {}

    received = m.get("receivedDateTime")
    if received:
        # Graph returns RFC 3339 with Z; parse to aware datetime.
        if received.endswith("Z"):
            received = received.replace("Z", "+00:00")
        try:
            received_dt = datetime.fromisoformat(received)
        except ValueError:
            received_dt = None
    else:
        received_dt = None

    return Message(
        id=m.get("id", ""),
        conversation_id=m.get("conversationId", ""),
        internet_message_id=m.get("internetMessageId", ""),
        subject=m.get("subject", "") or "",
        body_text=body_text,
        body_preview=m.get("bodyPreview", "") or "",
        from_address=from_.get("address", "") or "",
        from_name=from_.get("name", "") or "",
        to_recipients=[(r.get("emailAddress") or {}).get("address", "")
                       for r in m.get("toRecipients") or []],
        cc_recipients=[(r.get("emailAddress") or {}).get("address", "")
                       for r in m.get("ccRecipients") or []],
        received_at=received_dt,
        categories=m.get("categories") or [],
        parent_folder=m.get("parentFolderId", "") or "",
    )


# --- Odata + HTML helpers --------------------------------------------------

def _qs(params: dict[str, str]) -> str:
    return "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())


def _escape_odata(s: str) -> str:
    return s.replace("'", "''")


_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"(?is)<script.*?</script>")
_STYLE_RE = re.compile(r"(?is)<style.*?</style>")
_WS_RE = re.compile(r"\s{2,}")

_HTML_ENTITIES = [
    ("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"),
    ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'"),
]


def _append_html_footer(original: str, footer_html: str) -> str:
    """Insert `footer_html` just before </body> if a body tag exists,
    else append at the end. Idempotent: if the footer's sentinel class
    is already present in the message, leave the message untouched
    (protects against double-injection if a reclassify re-runs over a
    message we already touched)."""
    if "ee2-feedback-footer" in original:
        return original
    lower = original.lower()
    idx = lower.rfind("</body>")
    if idx != -1:
        return original[:idx] + footer_html + original[idx:]
    return original + footer_html


def _strip_html(h: str) -> str:
    h = _SCRIPT_RE.sub("", h)
    h = _STYLE_RE.sub("", h)
    for br in ("<br>", "<br/>", "<br />"):
        h = h.replace(br, "\n")
    for blk in ("</p>", "</div>", "</tr>"):
        h = h.replace(blk, "\n")
    h = h.replace("</td>", " | ")
    t = _TAG_RE.sub("", h)
    for a, b in _HTML_ENTITIES:
        t = t.replace(a, b)
    t = _WS_RE.sub(" ", t)
    return t.strip()
