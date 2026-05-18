"""
providers/base.py — mailbox provider abstraction.

Every backend (Microsoft Graph, IMAP) implements the same Provider
interface. The poller talks to providers; providers hide the API.

The contract is intentionally minimal: list_inbox, get_message,
get_thread, ensure_folder, set_categories, move_message. Provider
implementations decide what "folder" and "category" mean in their
native model:

  Graph:  folder = mailFolder displayName under Inbox
          category = Outlook category (color category)
  IMAP:   folder = IMAP mailbox name (with hierarchy delimiter)
          category = Gmail label, set via X-GM-LABELS for Gmail,
                     or via IMAP keywords for vanilla servers

Apply-mode mapping is the apply step's responsibility (lib/apply.py),
not the provider's. Providers expose primitives; the apply step
composes them according to mailbox_config.apply_mode.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# --- Wire types -------------------------------------------------------------

@dataclass
class Message:
    """Provider-agnostic message representation. Providers translate from
    their native shape (Graph JSON / parsed RFC822) into this. Fields
    that don't apply on a given provider are left empty strings or None."""

    id: str                          # provider-native message id (Graph id, IMAP UID)
    conversation_id: str             # threading key (Graph conversationId, Gmail X-GM-THRID)
    internet_message_id: str         # RFC 5322 Message-ID header
    subject: str
    body_text: str                   # plain text, HTML stripped if needed
    body_preview: str                # short preview, may equal body_text[:200]
    from_address: str
    from_name: str
    to_recipients: list[str] = field(default_factory=list)
    cc_recipients: list[str] = field(default_factory=list)
    received_at: datetime | None = None
    categories: list[str] = field(default_factory=list)
    parent_folder: str = ""          # native folder id (Graph) or mailbox name (IMAP)

    def is_to_only_me(self) -> bool:
        """Best-effort: addressed solely to this mailbox (no CCs)."""
        return len(self.to_recipients) == 1 and len(self.cc_recipients) == 0


# --- Provider interface -----------------------------------------------------

class Provider(ABC):
    """A bound mailbox. One Provider instance == one mailbox connection."""

    # Some operations (tag, move) need to mutate the message in place. Graph
    # mints a new id on move; IMAP keeps the UID stable inside a folder but
    # changes it on move. Apply step always uses the id RETURNED by mutating
    # ops, never the one it had before.

    @property
    @abstractmethod
    def email(self) -> str:
        """The mailbox email this provider is bound to."""

    @abstractmethod
    def list_inbox(self, since: datetime | None, limit: int) -> list[Message]:
        """Return inbox messages received after `since` (exclusive), oldest
        first, capped at `limit`. Pass since=None to fetch the most-recent
        `limit` messages."""

    @abstractmethod
    def list_folder(
        self,
        folder_name: str,
        since: datetime | None,
        limit: int,
        descending: bool = False,
    ) -> list[Message]:
        """Like list_inbox but for ANY folder by display name. Used by the
        reclassify-all sweep to walk legacy v1 folders alongside INBOX so
        every email gets reprocessed through the new (thread-aware) logic.
        Returns [] if the folder doesn't exist.

        When descending=False (default, used by the forward-walking poller):
          `since` is the lower bound — return messages with
          receivedDateTime > since, oldest first.
        When descending=True (used by reclassify so the newest threads
        appear in the dashboard first):
          `since` is the UPPER bound — return messages with
          receivedDateTime < since, newest first.
        Pass since=None to start from the absolute newest / oldest edge."""

    @abstractmethod
    def get_message(self, message_id: str) -> Message | None:
        """Fetch one message by its native id. Returns None on 404."""

    @abstractmethod
    def get_thread(self, conversation_id: str) -> list[Message]:
        """All messages in the same thread, oldest first."""

    @abstractmethod
    def ensure_folder(self, name: str) -> str:
        """Make sure the folder exists; return the native folder id."""

    @abstractmethod
    def set_categories(self, message_id: str, categories: list[str]) -> None:
        """Replace the message's categories/labels with this exact list.
        Pass [] to clear. Operation is idempotent."""

    @abstractmethod
    def move_message(self, message_id: str, dest_folder: str) -> str:
        """Move the message into `dest_folder` (folder NAME, not id).
        Returns the new message id (some backends mint a fresh one).
        If the message is already there, no-op and returns the original id."""

    def sweep_folder_to_inbox(
        self,
        source_folder: str,
        progress: dict | None = None,
    ) -> dict:
        """Move every message in `source_folder` to the well-known Inbox.
        Per-message Graph/IMAP MOVE — there's no bulk endpoint, so this
        loops. Counts are returned (and optionally mirrored to `progress`
        as it runs so the UI can show live progress).

        Default implementation walks list_folder() in pages and calls
        move_message(). Providers can override for native bulk APIs if
        any backend ever adds one."""
        from datetime import datetime, timezone
        out = {
            "source_folder": source_folder,
            "moved": 0,
            "errors": 0,
            "last_error": None,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "done": False,
        }
        if progress is not None:
            progress.update(out)

        # We don't paginate by cursor here because every iteration removes
        # the messages we just processed — the next list_folder call
        # naturally returns the next batch from the (now-shrinking) folder.
        while True:
            try:
                batch = self.list_folder(source_folder, since=None, limit=100, descending=True)
            except Exception as e:
                out["errors"] += 1
                out["last_error"] = f"list_folder: {e}"
                if progress is not None:
                    progress.update(out)
                break
            if not batch:
                break
            for m in batch:
                try:
                    self.move_message(m.id, "INBOX")
                    out["moved"] += 1
                except Exception as e:
                    out["errors"] += 1
                    out["last_error"] = f"move {m.id[:24]}: {e}"
                if progress is not None:
                    progress["moved"] = out["moved"]
                    progress["errors"] = out["errors"]
                    progress["last_error"] = out["last_error"]

        from datetime import datetime as _dt, timezone as _tz
        out["finished_at"] = _dt.now(_tz.utc).isoformat()
        out["done"] = True
        if progress is not None:
            progress.update(out)
        return out

    def ensure_master_categories(self, names: list[str]) -> dict:
        """Register tag names in the provider's master / canonical category
        list so they show up in the client UI's category management view
        (Outlook: Master Category List; Gmail: no equivalent — labels are
        first-class and auto-listed). Default no-op for providers that
        have no separate registry. Implementations should be idempotent.

        Returns a dict like {'created': int, 'existed': int, 'errors': int}
        for logging."""
        return {"created": 0, "existed": 0, "errors": 0, "skipped": True}

    # Optional capabilities — providers may override for richer behavior.

    def supports_categories(self) -> bool:
        """True if this provider can attach categories/labels without
        moving the message. Graph: yes (Outlook categories). Gmail IMAP:
        yes (labels via X-GM-LABELS). Vanilla IMAP: partial (keywords)."""
        return True


# --- Utilities --------------------------------------------------------------

def sanitize_mailbox(mailbox: str) -> str:
    """Stable filename stem for a mailbox: lowercase, non-alnum → '_'.
    Used for per-mailbox hierarchy JSON files."""
    return re.sub(r"[^A-Za-z0-9]+", "_", mailbox.strip().lower()).strip("_")


# Legacy v1 folder names. Reclassify-all sweeps these too so emails the
# previous engine sorted get reprocessed by the new (thread-aware) logic.
# When the taxonomy changes again, append the retired names here.
LEGACY_RULE_FOLDERS = (
    "1-CRITICAL-X",
    "2-HIGH-PRIORITY-X",
    "3-PERSONAL-&-IMPORTANT-X",
    "4-MEDIUM-/-BATCH-X",
    "5-LOW-IGNORE-X",
    # Earlier underscore-prefixed v1 generation
    "_1-CRITICAL-X",
    "_2-HIGH-PRIORITY-X",
    "_3-PERSONAL-&-IMPORTANT-X",
    "_4-MEDIUM-/-BATCH-X",
    "_5-LOW-IGNORE-X",
)
