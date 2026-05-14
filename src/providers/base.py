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
