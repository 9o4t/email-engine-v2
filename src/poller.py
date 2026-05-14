"""
poller.py — multi-provider mailbox poller daemon.

For each ENABLED mailbox in mailbox_config:
  1. Build the right Provider (Graph via token broker, IMAP via app password).
  2. List inbox messages since the watermark.
  3. Classify each via the RAG pipeline.
  4. apply_verdict() according to that mailbox's apply_mode.
  5. Log a decision row, advance the watermark.

The mailbox list comes from SQLite (UI-editable) — env vars seed the
table on first boot via init_from_env() but the database is the source
of truth once it has rows.
"""

from __future__ import annotations

import logging
import os
import signal
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

from classifier import LLMConfig, classify, list_folders
from lib.apply import apply_verdict
from lib.storage import MailboxConfig, Store
from providers import make_provider, sanitize_mailbox

load_dotenv()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("poller")


_STOP = False


def _on_signal(_sig, _frame):
    global _STOP
    _STOP = True
    log.info("shutdown signal received")


# --- Seeding mailbox_config from env (first boot only) ---------------------

def init_from_env(store: Store) -> None:
    """Seed mailbox_config from env on first boot. After that, the UI is the
    source of truth — env additions don't override existing rows.

    Env format (comma-separated):
      MAILBOXES_GRAPH=dave@9o4t.com,quotes@9o4t.com
      MAILBOXES_IMAP=shared@gmail.com|imap.gmail.com|993
    """
    existing = {m.mailbox for m in store.list_mailboxes()}

    for raw in os.getenv("MAILBOXES_GRAPH", "").split(","):
        mb = raw.strip()
        if not mb or mb in existing:
            continue
        store.upsert_mailbox(MailboxConfig(
            mailbox=mb, provider="graph",
            apply_mode=os.getenv("DEFAULT_APPLY_MODE", "tag_and_move"),
            enabled=True, imap_server="", imap_port=993,
            poll_interval=int(os.getenv("POLL_INTERVAL_SEC", "30")),
            notes="seeded from MAILBOXES_GRAPH",
        ))
        log.info("seeded graph mailbox: %s", mb)

    for raw in os.getenv("MAILBOXES_IMAP", "").split(","):
        row = raw.strip()
        if not row:
            continue
        parts = row.split("|")
        if len(parts) < 1:
            continue
        mb = parts[0].strip()
        if not mb or mb in existing:
            continue
        server = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "imap.gmail.com"
        port = int(parts[2].strip()) if len(parts) > 2 and parts[2].strip() else 993
        store.upsert_mailbox(MailboxConfig(
            mailbox=mb, provider="imap",
            apply_mode=os.getenv("DEFAULT_APPLY_MODE", "tag_and_move"),
            enabled=True, imap_server=server, imap_port=port,
            poll_interval=int(os.getenv("POLL_INTERVAL_SEC", "30")),
            notes="seeded from MAILBOXES_IMAP",
        ))
        log.info("seeded imap mailbox: %s (%s:%d)", mb, server, port)


# --- Per-mailbox poll cycle -------------------------------------------------

def poll_mailbox(mb: MailboxConfig, store: Store, llm: LLMConfig) -> int:
    if not mb.enabled:
        return 0

    try:
        provider = make_provider(
            mb.mailbox, mb.provider,
            imap_server=mb.imap_server, imap_port=mb.imap_port,
        )
    except Exception as e:
        log.error("[%s] cannot construct provider: %s", mb.mailbox, e)
        return 0

    watermark = store.get_watermark(mb.mailbox)
    try:
        msgs = provider.list_inbox(watermark, limit=25)
    except Exception as e:
        log.exception("[%s] list_inbox failed: %s", mb.mailbox, e)
        return 0
    if not msgs:
        return 0

    # Build the set of rule-managed categories so we can strip stale ones
    # when tagging. The set is the leaf id list from this mailbox's
    # hierarchy.
    rule_categories = [f["id"] or f["name"] for f in list_folders(mb.mailbox)]

    processed = 0
    latest = watermark
    for m in msgs:
        if _STOP:
            break
        if m.received_at and (latest is None or m.received_at > latest):
            latest = m.received_at
        try:
            _classify_and_apply(provider, mb, m, store, llm, rule_categories)
            processed += 1
        except Exception as e:
            log.exception("[%s/%s] process failed: %s", mb.mailbox, m.id[:24], e)

    if latest:
        store.set_watermark(mb.mailbox, latest)
    if processed:
        log.info("[%s] processed %d, watermark→%s", mb.mailbox, processed, latest)
    return processed


def _classify_and_apply(provider, mb, m, store, llm, rule_categories):
    # 1. Classify.
    verdict = classify(
        mailbox=mb.mailbox,
        sender=m.from_address or m.from_name,
        subject=m.subject,
        body=m.body_text,
        cfg=llm,
    )

    # 2. Apply per the mailbox's mode. category == folder name here; future
    # taxonomies could decouple them.
    folder_name = verdict.folder
    result = apply_verdict(
        provider,
        message_id=m.id,
        src_folder=_friendly_src_folder(m, provider),
        dest_folder=folder_name,
        category=folder_name,
        apply_mode=mb.apply_mode,
        existing_categories=m.categories,
        all_rule_categories=rule_categories,
    )

    # 3. Log.
    store.insert_decision(
        mailbox=mb.mailbox, provider=mb.provider,
        message_id=result.new_message_id,
        internet_message_id=m.internet_message_id,
        conversation_id=m.conversation_id,
        sender=m.from_address,
        subject=m.subject,
        body_preview=(m.body_text or "")[:500],
        src_folder=_friendly_src_folder(m, provider),
        verdict_folder=folder_name,
        retrieved=verdict.retrieved,
        llm_raw=verdict.raw,
        apply_mode=result.apply_mode,
        tagged=result.tagged,
        moved=result.moved,
        apply_error=result.error,
    )
    log.info(
        "[%s] %s → %s (mode=%s, tagged=%s, moved=%s%s)",
        mb.mailbox, (m.subject or "")[:60], folder_name,
        result.apply_mode, result.tagged, result.moved,
        f", err={result.error}" if result.error else "",
    )


def _friendly_src_folder(m, provider) -> str:
    """For logs: the provider-native folder, or "INBOX" if not exposed."""
    if not m.parent_folder:
        return "INBOX"
    # IMAP messages carry the folder NAME in parent_folder; Graph carries
    # the folder ID. We surface what we have; this is informational only.
    return m.parent_folder


# --- Main loop -------------------------------------------------------------

def run(store: Store, llm: LLMConfig) -> None:
    interval = int(os.getenv("POLL_INTERVAL_SEC", "30"))
    log.info("starting poller (llm=%s @ %s, interval=%ds)", llm.model, llm.base_url, interval)
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    while not _STOP:
        cycle_start = time.time()
        mailboxes = [m for m in store.list_mailboxes() if m.enabled]
        if not mailboxes:
            log.info("no enabled mailboxes; sleeping")
        for mb in mailboxes:
            if _STOP:
                break
            try:
                poll_mailbox(mb, store, llm)
            except Exception as e:
                log.exception("[%s] cycle failed: %s", mb.mailbox, e)
        elapsed = time.time() - cycle_start
        deadline = time.time() + max(1.0, interval - elapsed)
        while not _STOP and time.time() < deadline:
            time.sleep(min(1.0, deadline - time.time()))
    log.info("poller exited cleanly")


def main() -> None:
    store = Store()
    init_from_env(store)
    llm = LLMConfig.from_env()
    run(store, llm)


if __name__ == "__main__":
    main()
