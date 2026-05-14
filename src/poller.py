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
from providers.base import LEGACY_RULE_FOLDERS, Message, Provider

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
    # when tagging. Set = leaf ids from this mailbox's taxonomy.
    # We also include the legacy v1 folder names (with the -X suffix) so
    # reclassification scrubs those off any message we re-tag.
    rule_categories = [f["id"] or f["name"] for f in list_folders(mb.mailbox)]
    rule_categories.extend(LEGACY_RULE_FOLDERS)

    processed = 0
    latest = watermark
    seen_conversations: set[str] = set()
    for m in msgs:
        if _STOP:
            break
        if m.received_at and (latest is None or m.received_at > latest):
            latest = m.received_at
        # Per-cycle dedup: if the same thread shows up twice in this batch
        # (e.g. several new replies arrived), we only classify once.
        if m.conversation_id and m.conversation_id in seen_conversations:
            continue
        if m.conversation_id:
            seen_conversations.add(m.conversation_id)
        try:
            _classify_thread_and_apply(provider, mb, m, store, llm, rule_categories)
            processed += 1
        except Exception as e:
            log.exception("[%s/%s] process failed: %s", mb.mailbox, m.id[:24], e)

    if latest:
        store.set_watermark(mb.mailbox, latest)
    if processed:
        log.info("[%s] processed %d thread(s), watermark→%s", mb.mailbox, processed, latest)
    return processed


def _classify_thread_and_apply(
    provider: Provider,
    mb: MailboxConfig,
    trigger: Message,
    store: Store,
    llm: LLMConfig,
    rule_categories: list[str],
) -> None:
    """Classify the ENTIRE thread (not just the trigger message) and apply
    the verdict to every message in it. This is v1's behavior, lifted into
    v2. Without this, a thread where a colleague replied 'I'll handle it'
    would still look critical because we'd only see the original message."""

    # 1. Fetch full thread for context. If get_thread fails or returns
    # empty, fall back to the single trigger message.
    thread: list[Message] = []
    if trigger.conversation_id:
        try:
            thread = provider.get_thread(trigger.conversation_id)
        except Exception as e:
            log.warning("[%s/%s] get_thread failed: %s — using trigger alone",
                        mb.mailbox, trigger.id[:24], e)
    if not thread:
        thread = [trigger]

    # Choose the "latest" message as the classifier's anchor. Graph returns
    # the thread sorted oldest-first; we pick the last one. Fall back to the
    # incoming trigger if the thread fetch didn't include it (rare but
    # observed when a message has JUST arrived and the conversationId lookup
    # hasn't propagated yet).
    latest_msg = max(thread, key=lambda x: x.received_at or datetime.min.replace(tzinfo=timezone.utc))
    if trigger.id not in {m.id for m in thread}:
        thread = [*thread, trigger]
        if trigger.received_at and (
            latest_msg.received_at is None or trigger.received_at > latest_msg.received_at
        ):
            latest_msg = trigger

    # 2. Build thread context (older messages first; classifier prompt
    # template treats `thread` as historical context, while `subject`/`body`
    # is the current state).
    thread_ctx = [
        {
            "sender": tm.from_address or tm.from_name or "(unknown)",
            "received": tm.received_at.isoformat() if tm.received_at else "",
            "body": (tm.body_text or "")[:1500],
        }
        for tm in thread
        if tm.id != latest_msg.id
    ]

    # 3. Classify based on the latest message + thread context.
    verdict = classify(
        mailbox=mb.mailbox,
        sender=latest_msg.from_address or latest_msg.from_name,
        subject=latest_msg.subject,
        body=latest_msg.body_text,
        thread=thread_ctx,
        cfg=llm,
    )
    folder_name = verdict.folder

    # 4. Wipe stale decisions for this thread before re-inserting — matches
    # v1's DeleteDecisionsForThread step, so the dashboard never shows two
    # conflicting verdicts for the same conversation.
    if trigger.conversation_id:
        store.delete_decisions_for_thread(mb.mailbox, trigger.conversation_id)

    # 5. Apply the verdict to EVERY message in the thread. Graph mints a new
    # id on move so we track the post-apply id per row.
    moved_count = 0
    tagged_count = 0
    err_count = 0
    for tm in thread:
        src = tm.parent_folder or "INBOX"
        # If we already happen to be in the right place (e.g. v2 classified
        # this earlier), apply_verdict no-ops on the move and is a cheap
        # idempotent tag-set on the categories.
        result = apply_verdict(
            provider,
            message_id=tm.id,
            src_folder=src,
            dest_folder=folder_name,
            category=folder_name,
            apply_mode=mb.apply_mode,
            existing_categories=tm.categories,
            all_rule_categories=rule_categories,
        )
        if result.moved:
            moved_count += 1
        if result.tagged:
            tagged_count += 1
        if result.error:
            err_count += 1

        store.insert_decision(
            mailbox=mb.mailbox,
            provider=mb.provider,
            message_id=result.new_message_id,
            internet_message_id=tm.internet_message_id,
            conversation_id=tm.conversation_id,
            sender=tm.from_address,
            subject=tm.subject,
            body_preview=(tm.body_text or "")[:500],
            src_folder=src,
            verdict_folder=folder_name,
            retrieved=verdict.retrieved,
            llm_raw=(
                verdict.raw if tm.id == latest_msg.id
                else f"thread verdict propagated from {latest_msg.id[:12]}: {verdict.raw[:120]}"
            ),
            apply_mode=result.apply_mode,
            tagged=result.tagged,
            moved=result.moved,
            apply_error=result.error,
        )

    log.info(
        "[%s] thread %s | %s → %s | %d msg(s), tagged=%d moved=%d err=%d",
        mb.mailbox,
        (trigger.conversation_id or "")[:12],
        (latest_msg.subject or "")[:60],
        folder_name,
        len(thread), tagged_count, moved_count, err_count,
    )


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


def reclassify_all(mailbox_email: str, store: Store | None = None, llm: LLMConfig | None = None) -> dict:
    """One-shot reclassification: walk INBOX + every legacy v1 folder,
    classify each thread once (per-conversation dedup), apply verdict to
    every message in the thread. Resets the watermark afterward so the
    normal poller resumes from the latest message.

    Designed to be called from a Flask background thread (see web.py).
    Returns a summary dict for logs / UI feedback.
    """
    store = store or Store()
    llm = llm or LLMConfig.from_env()
    mb = store.get_mailbox(mailbox_email)
    if not mb:
        return {"ok": False, "error": f"unknown mailbox {mailbox_email!r}"}

    provider = make_provider(
        mb.mailbox, mb.provider,
        imap_server=mb.imap_server, imap_port=mb.imap_port,
    )
    rule_categories = [f["id"] or f["name"] for f in list_folders(mb.mailbox)]
    rule_categories.extend(LEGACY_RULE_FOLDERS)

    # Walk INBOX first (the live source), then every legacy folder we know
    # v1 might have stashed mail in. Per-conversation dedup means a thread
    # straddling two folders only gets classified once.
    folders_to_walk = ["INBOX", *LEGACY_RULE_FOLDERS]
    page = 100
    seen: set[str] = set()
    counts = {"folders_walked": 0, "threads_classified": 0, "errors": 0}

    log.info("[reclassify] starting for %s across %d folder(s)", mb.mailbox, len(folders_to_walk))

    for folder in folders_to_walk:
        if _STOP:
            log.info("[reclassify] stop signal — abort mid-folder %s", folder)
            break
        counts["folders_walked"] += 1
        # Paginate by received-time so we can checkpoint progress in logs.
        cursor: datetime | None = None
        while True:
            if _STOP:
                break
            try:
                batch = provider.list_folder(folder, cursor, page)
            except Exception as e:
                log.exception("[reclassify] list %s failed: %s", folder, e)
                counts["errors"] += 1
                break
            if not batch:
                break
            for m in batch:
                if _STOP:
                    break
                if m.conversation_id and m.conversation_id in seen:
                    if m.received_at and (cursor is None or m.received_at > cursor):
                        cursor = m.received_at
                    continue
                if m.conversation_id:
                    seen.add(m.conversation_id)
                try:
                    _classify_thread_and_apply(provider, mb, m, store, llm, rule_categories)
                    counts["threads_classified"] += 1
                except Exception as e:
                    log.exception("[reclassify] %s/%s thread failed: %s",
                                  folder, m.id[:24], e)
                    counts["errors"] += 1
                if m.received_at and (cursor is None or m.received_at > cursor):
                    cursor = m.received_at
            if len(batch) < page:
                break
        log.info("[reclassify] folder %s done (threads=%d errors=%d)",
                 folder, counts["threads_classified"], counts["errors"])

    # Watermark = "we just processed everything"; next poll cycle picks up
    # only genuinely new messages.
    store.set_watermark(mb.mailbox, datetime.now(timezone.utc))

    log.info("[reclassify] %s complete: %s", mb.mailbox, counts)
    counts["ok"] = True
    return counts


def main() -> None:
    store = Store()
    init_from_env(store)
    llm = LLMConfig.from_env()
    run(store, llm)


if __name__ == "__main__":
    main()
