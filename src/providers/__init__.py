"""providers/__init__.py — registry that constructs the right Provider
for a (mailbox, kind, credentials) triple.

Mailbox config is stored in SQLite (see lib/storage.py: mailbox_config
table) plus a small env contract for the credentials that should NEVER
go into a database (IMAP app passwords, the Graph broker bearer). That
split keeps the database swappable + safe to back up while keeping
secrets in Railway's secret store.

Env contract:
  CALENDAR_URL, B2B_TOKEN       — Graph broker (one set, every Graph mailbox)
  IMAP_<EMAIL>_PASSWORD          — per-IMAP-mailbox app password (sanitized email)
"""

from __future__ import annotations

import os

from .base import Provider, sanitize_mailbox
from .graph import GraphProvider, broker_from_env
from .imap import IMAPConfig, IMAPProvider


def make_provider(mailbox: str, kind: str, *, imap_server: str = "", imap_port: int = 993) -> Provider:
    kind = kind.strip().lower()
    if kind == "graph":
        return GraphProvider(mailbox, broker=broker_from_env())
    if kind == "imap":
        env_key = f"IMAP_{sanitize_mailbox(mailbox).upper()}_PASSWORD"
        pw = os.getenv(env_key, "")
        if not pw:
            raise RuntimeError(
                f"missing env {env_key}: IMAP mailboxes need a per-mailbox app password "
                "in Railway secrets"
            )
        cfg = IMAPConfig(
            server=imap_server or "imap.gmail.com",
            port=imap_port or 993,
            username=mailbox,
            password=pw,
        )
        return IMAPProvider(mailbox, cfg)
    raise RuntimeError(f"unknown provider kind: {kind!r}")


__all__ = ["Provider", "make_provider", "sanitize_mailbox"]
