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
        endpoint = f"{GRAPH_API_BASE}/users/{quote(self._email)}/mailFolders/inbox/messages"
        q = {
            "$select": MESSAGE_SELECT,
            "$orderby": "receivedDateTime asc",
            "$top": str(max(1, min(limit, 100))),
        }
        if since:
            iso = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            q["$filter"] = f"receivedDateTime gt {iso}"
        url = endpoint + "?" + _qs(q)
        data = _do_json(self._broker, "GET", url) or {}
        return [_msg_from_graph(m) for m in data.get("value", [])]

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

    def move_message(self, message_id: str, dest_folder: str) -> str:
        folder_id = self.ensure_folder(dest_folder)
        endpoint = f"{GRAPH_API_BASE}/users/{quote(self._email)}/messages/{quote(message_id, safe='')}/move"
        data = _do_json(self._broker, "POST", endpoint, body={"destinationId": folder_id}) or {}
        return data.get("id") or message_id

    def ensure_folder(self, name: str) -> str:
        if name in self._folder_cache:
            return self._folder_cache[name]
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
