"""
providers/imap.py — IMAP mailbox provider for Gmail / Workspace.

This is the "other side" of the provider interface: same contract as
GraphProvider, talking to a vanilla IMAP server with optional Gmail
extensions for labels (X-GM-LABELS) and thread ids (X-GM-THRID).

Connection model: a fresh IMAP connection per operation. IMAP has no
real long-running session model that survives idle servers, and our
poll cadence is tens of seconds, so opening a connection on each call
is the simpler / more reliable design. The trade-off vs. holding open
IDLE sessions is latency, not correctness.

Why Gmail specifically:
  - "Categories" on Gmail are LABELS. They aren't IMAP flags or keywords;
    they're Gmail-specific and we set them via the X-GM-LABELS extension
    (STORE +X-GM-LABELS / -X-GM-LABELS / X-GM-LABELS).
  - "Thread" on Gmail is X-GM-THRID, returned by FETCH alongside RFC822.
  - "Folder" on Gmail is an IMAP folder. Moving a message to a folder is
    actually how Gmail's "label and archive" mechanic works at the
    protocol layer.

For non-Gmail IMAP servers (Outlook.com IMAP, Fastmail, etc.) the label
operations degrade to IMAP keywords, which most clients render as flags
rather than nice category chips. Use Gmail or Graph for the cleanest UX.
"""

from __future__ import annotations

import email as email_lib
import imaplib
import logging
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from typing import Iterable

from .base import Message, Provider

log = logging.getLogger(__name__)


# --- Connection settings ----------------------------------------------------

class IMAPConfig:
    def __init__(self, server: str, port: int, username: str, password: str, use_ssl: bool = True):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl


def _open(cfg: IMAPConfig) -> imaplib.IMAP4:
    c: imaplib.IMAP4
    if cfg.use_ssl:
        c = imaplib.IMAP4_SSL(cfg.server, cfg.port)
    else:
        c = imaplib.IMAP4(cfg.server, cfg.port)
    c.login(cfg.username, cfg.password)
    return c


def _capabilities(c: imaplib.IMAP4) -> set[bytes]:
    typ, data = c.capability()
    if typ != "OK":
        return set()
    return set(b" ".join(data).upper().split())


# --- Provider implementation ----------------------------------------------

class IMAPProvider(Provider):
    def __init__(self, mailbox: str, cfg: IMAPConfig):
        self._email = mailbox
        self._cfg = cfg

    @property
    def email(self) -> str:
        return self._email

    # --- reads --------------------------------------------------------------

    def list_inbox(self, since: datetime | None, limit: int) -> list[Message]:
        c = _open(self._cfg)
        try:
            typ, _ = c.select("INBOX", readonly=True)
            if typ != "OK":
                return []
            criteria = ["ALL"]
            if since:
                # IMAP SINCE granularity is date-only and >= (not >). Filter
                # client-side after fetch for exclusive-since semantics.
                d = since.astimezone(timezone.utc).strftime("%d-%b-%Y")
                criteria = ["SINCE", d]

            typ, data = c.uid("SEARCH", None, *criteria)
            if typ != "OK" or not data or not data[0]:
                return []
            uids = data[0].split()
            # Newest last after IMAP SEARCH (uid order); cap at limit.
            if limit and len(uids) > limit:
                uids = uids[-limit:]

            out: list[Message] = []
            for raw_uid in uids:
                uid = raw_uid.decode() if isinstance(raw_uid, bytes) else raw_uid
                m = self._fetch_one(c, uid, source_folder="INBOX")
                if not m:
                    continue
                if since and m.received_at and m.received_at <= since:
                    continue
                out.append(m)
            return out
        finally:
            try:
                c.logout()
            except Exception:
                pass

    def get_message(self, message_id: str) -> Message | None:
        # message_id here is a "folder|uid" composite; we keep the source
        # folder in the message id so move_message can find it.
        folder, uid = _split_id(message_id)
        c = _open(self._cfg)
        try:
            typ, _ = c.select(folder, readonly=True)
            if typ != "OK":
                return None
            return self._fetch_one(c, uid, source_folder=folder)
        finally:
            try:
                c.logout()
            except Exception:
                pass

    def get_thread(self, conversation_id: str) -> list[Message]:
        """conversation_id is the Gmail X-GM-THRID or our synthetic id.
        For Gmail, search by X-GM-THRID; otherwise return empty."""
        c = _open(self._cfg)
        try:
            caps = _capabilities(c)
            typ, _ = c.select("[Gmail]/All Mail", readonly=True)
            if typ != "OK":
                # Fall back to All Mail variations or just INBOX.
                typ, _ = c.select("INBOX", readonly=True)
                if typ != "OK":
                    return []
            if b"X-GM-EXT-1" not in caps and b"X-GM-EXT1" not in caps:
                return []  # not Gmail — we don't have a thread model
            typ, data = c.uid("SEARCH", None, "X-GM-THRID", conversation_id)
            if typ != "OK" or not data or not data[0]:
                return []
            out: list[Message] = []
            for raw_uid in data[0].split():
                uid = raw_uid.decode() if isinstance(raw_uid, bytes) else raw_uid
                m = self._fetch_one(c, uid, source_folder="[Gmail]/All Mail")
                if m:
                    out.append(m)
            out.sort(key=lambda mm: mm.received_at or datetime.min.replace(tzinfo=timezone.utc))
            return out
        finally:
            try:
                c.logout()
            except Exception:
                pass

    # --- mutations ----------------------------------------------------------

    def set_categories(self, message_id: str, categories: list[str]) -> None:
        folder, uid = _split_id(message_id)
        c = _open(self._cfg)
        try:
            typ, _ = c.select(folder)
            if typ != "OK":
                raise RuntimeError(f"cannot select {folder}")
            caps = _capabilities(c)
            if b"X-GM-EXT-1" in caps or b"X-GM-EXT1" in caps:
                # Gmail labels. Replace (not merge): set X-GM-LABELS to the
                # full final list.
                wire = "(" + " ".join(_quote_imap(c) for c in categories) + ")"
                typ, _ = c.uid("STORE", uid, "X-GM-LABELS", wire)
                if typ != "OK":
                    raise RuntimeError("X-GM-LABELS STORE failed")
                return
            # Generic IMAP keywords fallback. Strip non-ASCII / spaces — IMAP
            # keywords are atoms, not strings. Clears existing keywords first.
            kw = [_keyword_safe(c) for c in categories]
            c.uid("STORE", uid, "-FLAGS.SILENT", "(\\Flagged)")  # no-op-ish
            if kw:
                wire = "(" + " ".join(kw) + ")"
                c.uid("STORE", uid, "+FLAGS.SILENT", wire)
        finally:
            try:
                c.logout()
            except Exception:
                pass

    def move_message(self, message_id: str, dest_folder: str) -> str:
        src_folder, uid = _split_id(message_id)
        if src_folder == dest_folder:
            return message_id
        c = _open(self._cfg)
        try:
            self._ensure_folder_inner(c, dest_folder)
            typ, _ = c.select(src_folder)
            if typ != "OK":
                raise RuntimeError(f"cannot select source {src_folder}")
            caps = _capabilities(c)
            if b"MOVE" in caps:
                typ, _ = c.uid("MOVE", uid, dest_folder)
                if typ != "OK":
                    raise RuntimeError("UID MOVE failed")
            else:
                typ, _ = c.uid("COPY", uid, dest_folder)
                if typ != "OK":
                    raise RuntimeError("UID COPY failed")
                c.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
                c.expunge()
            # We don't know the new UID without an extra SELECT + SEARCH;
            # callers must re-fetch by Message-ID if they need it. Return a
            # synthetic id so downstream tagging still works for the in-flight
            # message (in dest now).
            return _make_id(dest_folder, uid)
        finally:
            try:
                c.logout()
            except Exception:
                pass

    def ensure_folder(self, name: str) -> str:
        c = _open(self._cfg)
        try:
            return self._ensure_folder_inner(c, name)
        finally:
            try:
                c.logout()
            except Exception:
                pass

    def _ensure_folder_inner(self, c: imaplib.IMAP4, name: str) -> str:
        # CREATE; if it exists IMAP returns NO with ALREADYEXISTS, harmless.
        c.create(_quote_mailbox(name))
        c.subscribe(_quote_mailbox(name))
        return name

    # --- internals ----------------------------------------------------------

    def _fetch_one(self, c: imaplib.IMAP4, uid: str, source_folder: str) -> Message | None:
        caps = _capabilities(c)
        # Always fetch RFC822 + flags; on Gmail also pull X-GM-THRID, X-GM-LABELS.
        fetch_parts = "(FLAGS RFC822"
        if b"X-GM-EXT-1" in caps or b"X-GM-EXT1" in caps:
            fetch_parts = "(FLAGS X-GM-THRID X-GM-LABELS RFC822"
        fetch_parts += ")"
        typ, data = c.uid("FETCH", uid, fetch_parts)
        if typ != "OK" or not data or data[0] is None:
            return None
        # imaplib returns a list of mixed tuples; pull the RFC822 body and the
        # parenthesized metadata.
        rfc822, meta = _parse_fetch(data)
        if not rfc822:
            return None
        msg = email_lib.message_from_bytes(rfc822)
        return _msg_from_email(msg, uid=uid, source_folder=source_folder, meta=meta)


# --- ID composite -----------------------------------------------------------

def _make_id(folder: str, uid: str) -> str:
    """IMAP UIDs are scoped per-folder. We carry the folder in the id so
    the apply step can look the message back up after a move."""
    return f"{folder}\x1f{uid}"


def _split_id(message_id: str) -> tuple[str, str]:
    if "\x1f" in message_id:
        folder, uid = message_id.split("\x1f", 1)
        return folder, uid
    # Bare uid — assume INBOX.
    return "INBOX", message_id


# --- Wire helpers -----------------------------------------------------------

def _quote_mailbox(name: str) -> str:
    if " " in name or '"' in name or "/" in name:
        return f'"{name}"'
    return name


def _quote_imap(s: str) -> str:
    """Quote a string for IMAP — wraps in double quotes and escapes."""
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def _keyword_safe(s: str) -> str:
    # IMAP keywords are atoms: ASCII, no spaces, no quotes.
    out = []
    for ch in s:
        if ch.isalnum() or ch in "-_":
            out.append(ch)
        else:
            out.append("_")
    return "".join(out) or "_"


def _parse_fetch(data: Iterable) -> tuple[bytes | None, dict]:
    """imaplib's FETCH return is messy. We look for the (parenthesized
    metadata, RFC822 body) tuple and any trailing `)` literal."""
    rfc822: bytes | None = None
    meta: dict = {}
    for item in data:
        if isinstance(item, tuple) and len(item) >= 2:
            head = item[0]
            body = item[1]
            if isinstance(head, bytes):
                meta = _parse_meta(head)
            if isinstance(body, (bytes, bytearray)):
                rfc822 = bytes(body)
    return rfc822, meta


def _parse_meta(head: bytes) -> dict:
    """Best-effort: pull FLAGS, X-GM-THRID, X-GM-LABELS from the FETCH header."""
    text = head.decode("utf-8", errors="replace")
    meta: dict = {}
    # X-GM-THRID is a 64-bit int.
    if "X-GM-THRID" in text:
        i = text.index("X-GM-THRID")
        rest = text[i + len("X-GM-THRID"):].strip()
        thrid = ""
        for ch in rest:
            if ch.isdigit():
                thrid += ch
            else:
                break
        if thrid:
            meta["thread_id"] = thrid
    if "FLAGS" in text:
        i = text.index("FLAGS")
        s = text.find("(", i)
        e = text.find(")", s)
        if s > 0 and e > s:
            meta["flags"] = [t for t in text[s + 1:e].split() if t]
    if "X-GM-LABELS" in text:
        i = text.index("X-GM-LABELS")
        s = text.find("(", i)
        e = text.find(")", s)
        if s > 0 and e > s:
            raw = text[s + 1:e]
            labels: list[str] = []
            cur = ""
            in_q = False
            for ch in raw:
                if ch == '"':
                    in_q = not in_q
                    continue
                if ch == " " and not in_q:
                    if cur:
                        labels.append(cur)
                        cur = ""
                    continue
                cur += ch
            if cur:
                labels.append(cur)
            meta["labels"] = labels
    return meta


def _msg_from_email(msg, *, uid: str, source_folder: str, meta: dict) -> Message:
    subject = msg.get("Subject") or ""
    from_addrs = getaddresses([msg.get("From", "")])
    from_name, from_address = (from_addrs[0] if from_addrs else ("", ""))
    to_addrs = [a for _, a in getaddresses(msg.get_all("To") or [])]
    cc_addrs = [a for _, a in getaddresses(msg.get_all("Cc") or [])]

    received_at = None
    date_hdr = msg.get("Date")
    if date_hdr:
        try:
            received_at = parsedate_to_datetime(date_hdr)
        except (TypeError, ValueError):
            received_at = None

    body_text = _extract_text_body(msg)
    body_preview = body_text[:200] if body_text else ""

    return Message(
        id=_make_id(source_folder, uid),
        conversation_id=meta.get("thread_id") or msg.get("References") or msg.get("Message-ID") or "",
        internet_message_id=msg.get("Message-ID") or "",
        subject=subject,
        body_text=body_text,
        body_preview=body_preview,
        from_address=from_address,
        from_name=from_name or from_address,
        to_recipients=to_addrs,
        cc_recipients=cc_addrs,
        received_at=received_at,
        categories=meta.get("labels") or meta.get("flags") or [],
        parent_folder=source_folder,
    )


def _extract_text_body(msg) -> str:
    if msg.is_multipart():
        # Prefer text/plain; fall back to text/html stripped.
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                try:
                    return payload.decode(charset, errors="replace")
                except LookupError:
                    return payload.decode("utf-8", errors="replace")
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                try:
                    return _strip_html_basic(payload.decode(charset, errors="replace"))
                except LookupError:
                    return _strip_html_basic(payload.decode("utf-8", errors="replace"))
        return ""
    payload = msg.get_payload(decode=True) or b""
    charset = msg.get_content_charset() or "utf-8"
    try:
        text = payload.decode(charset, errors="replace")
    except LookupError:
        text = payload.decode("utf-8", errors="replace")
    if msg.get_content_type() == "text/html":
        return _strip_html_basic(text)
    return text


def _strip_html_basic(h: str) -> str:
    """Bare-bones HTML stripper for the IMAP path. We don't pull in
    BeautifulSoup just for this."""
    import re as _re
    h = _re.sub(r"(?is)<script.*?</script>", "", h)
    h = _re.sub(r"(?is)<style.*?</style>", "", h)
    h = h.replace("<br>", "\n").replace("<br/>", "\n").replace("<br />", "\n")
    h = h.replace("</p>", "\n").replace("</div>", "\n").replace("</tr>", "\n")
    h = h.replace("</td>", " | ")
    h = _re.sub(r"<[^>]+>", "", h)
    for a, b in [("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"),
                 ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'")]:
        h = h.replace(a, b)
    h = _re.sub(r"\s{2,}", " ", h)
    return h.strip()
