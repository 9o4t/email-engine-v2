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
from lib.storage import MailboxConfig, Store, make_thread_key
from providers import make_provider, sanitize_mailbox
from providers.base import LEGACY_RULE_FOLDERS, Message, Provider

load_dotenv()
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("poller")


_STOP = False

# Mailboxes whose Master Category List has already been synced in this
# process. First poll per mailbox triggers registration (GET existing +
# POST missing); subsequent cycles skip the Graph round-trip. Restart
# the poller to pick up taxonomy edits.
_MASTER_CATS_SYNCED: set[str] = set()


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
    current_categories = [f["id"] or f["name"] for f in list_folders(mb.mailbox)]
    rule_categories = list(current_categories)
    rule_categories.extend(LEGACY_RULE_FOLDERS)

    # First poll per process per mailbox: register the CURRENT taxonomy's
    # leaf names in Outlook's Master Category List so they appear in the
    # categories management UI with the digit-mapped color. Legacy names
    # are intentionally NOT registered — they were retired and the user
    # cleaned them up; we only strip them off messages, never set them.
    if mb.mailbox not in _MASTER_CATS_SYNCED:
        try:
            result = provider.ensure_master_categories(current_categories)
            _MASTER_CATS_SYNCED.add(mb.mailbox)
            if not result.get("skipped"):
                log.info(
                    "[%s] master categories: created=%d existed=%d errors=%d",
                    mb.mailbox, result.get("created", 0),
                    result.get("existed", 0), result.get("errors", 0),
                )
        except Exception as e:
            log.exception("[%s] ensure_master_categories failed: %s", mb.mailbox, e)

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

    # 3a. Capture the PREVIOUS verdict + prior ThreadSummary for this
    # thread BEFORE we touch anything, so:
    #   - the history row records prev → new transitions (/changes view)
    #   - the LLM gets the compact prior summary instead of the full thread
    #     (per-update cost is constant regardless of thread depth — the
    #     cost trick).
    prev_verdict = None
    prior_summary = None
    thread_key = make_thread_key(mb.provider, trigger.conversation_id or "")
    if trigger.conversation_id:
        prev_verdict = store.get_latest_thread_verdict(mb.mailbox, trigger.conversation_id)
    if thread_key:
        ts = store.get_thread_summary(mb.mailbox, thread_key)
        if ts:
            prior_summary = {
                "summary": ts.summary,
                "key_facts": ts.key_facts,
                "timeline": ts.timeline,
                "contacts": ts.contacts,
                "message_count": ts.message_count,
            }

    # 3b. Classify based on the latest message + (prior summary OR thread
    # context — never both). When a prior summary exists it IS the
    # compressed thread context, so we skip the per-message context.
    #
    # Per-mailbox model override: if mb.llm_model is set, use it instead
    # of LLM_MODEL env default. Same provider (base_url + api_key from
    # env), different model — lets you run Haiku on a cost-sensitive
    # mailbox while keeping Opus on your own.
    mailbox_llm = (
        LLMConfig(base_url=llm.base_url, model=mb.llm_model, api_key=llm.api_key)
        if mb.llm_model else llm
    )
    verdict = classify(
        mailbox=mb.mailbox,
        sender=latest_msg.from_address or latest_msg.from_name,
        subject=latest_msg.subject,
        body=latest_msg.body_text,
        thread=thread_ctx if prior_summary is None else None,
        prior_summary=prior_summary,
        message_id=latest_msg.id,
        received_at=latest_msg.received_at.isoformat() if latest_msg.received_at else None,
        cfg=mailbox_llm,
    )
    folder_name = verdict.folder

    # 3c. Append a thread_verdicts row — append-only history, never
    # deleted. This is how the /threads + /changes tabs work.
    # Reason: prefer the parsed summary (now produced by the same LLM
    # call); fall back to the first line of raw output for the legacy
    # plain-id pathway.
    reason_short = (verdict.summary or "").strip()[:240] or None
    if not reason_short and verdict.raw:
        reason_short = verdict.raw.strip().splitlines()[0][:240]
    if trigger.conversation_id:
        try:
            store.record_thread_verdict(
                mailbox=mb.mailbox,
                conversation_id=trigger.conversation_id,
                verdict_folder=folder_name,
                prev_verdict=prev_verdict,
                reason=reason_short,
                model_raw=verdict.raw,
                trigger_message_id=latest_msg.id,
                trigger_subject=latest_msg.subject,
                trigger_sender=latest_msg.from_address or latest_msg.from_name,
                thread_size=len(thread),
            )
        except Exception as e:
            log.exception("[%s] thread_verdicts insert failed: %s", mb.mailbox, e)

    # 3d. Persist the rolling ThreadSummary (synct consumer). This is the
    # row downstream apps query at /api/threads/<threadKey>/summary.
    # `status='errored'` is recorded when the LLM produced invalid JSON
    # so the next-message update has a chance to fix it (and so callers
    # can tell the slice is stale).
    if thread_key:
        # message_count = real thread size from the provider, not a
        # local increment. The poller dedupes per thread per cycle, so a
        # local "++ on every call" undercounts when multiple messages
        # arrive between polls.
        try:
            store.upsert_thread_summary(
                mailbox=mb.mailbox,
                thread_key=thread_key,
                summary=verdict.summary,
                key_facts=verdict.key_facts,
                timeline=verdict.timeline,
                contacts=verdict.contacts,
                last_message_id=latest_msg.id,
                last_message_at=(
                    latest_msg.received_at.isoformat() if latest_msg.received_at else None
                ),
                message_count=len(thread),
                status="errored" if verdict.parse_error else "fresh",
            )
            if verdict.parse_error:
                log.warning(
                    "[%s] thread_summary parse_error for %s: %s",
                    mb.mailbox, thread_key, verdict.parse_error,
                )
        except Exception as e:
            log.exception("[%s] thread_summary upsert failed: %s", mb.mailbox, e)

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
    latest_decision_id: str | None = None
    latest_post_apply_id: str | None = None
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

        did = store.insert_decision(
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
        if tm.id == latest_msg.id:
            latest_decision_id = did
            latest_post_apply_id = result.new_message_id

    # 6. Inject the feedback footer on the latest message of the thread.
    # One footer per (decision_id) — older messages in the thread are
    # already read and modifying them now would be intrusive. Best-effort:
    # any provider/Graph error here is logged + ignored, the classification
    # itself is already persisted.
    if latest_decision_id and latest_post_apply_id:
        _inject_feedback_footer(
            store=store, provider=provider, mailbox=mb.mailbox,
            decision_id=latest_decision_id,
            message_id=latest_post_apply_id,
            verdict_folder=folder_name,
        )

    log.info(
        "[%s] thread %s | %s → %s | %d msg(s), tagged=%d moved=%d err=%d",
        mb.mailbox,
        (trigger.conversation_id or "")[:12],
        (latest_msg.subject or "")[:60],
        folder_name,
        len(thread), tagged_count, moved_count, err_count,
    )


# --- Feedback footer injection ---------------------------------------------

def _inject_feedback_footer(
    *, store: Store, provider: Provider, mailbox: str,
    decision_id: str, message_id: str, verdict_folder: str,
) -> None:
    """Mint a one-shot feedback token and PATCH a discreet footer into
    the message body. Best-effort end-to-end — any failure (no base URL
    configured, Graph PATCH error, etc.) is logged at WARN and ignored.

    The link in the footer is unguessable (sha256-hashed token), single-
    use (consumed on form submit), and 30-day-expiring. Privacy footprint:
    if the user forwards the email, the link goes with it — but the
    token is scoped to this one decision (no broader account access),
    and the landing page never displays anything beyond the subject."""
    base_url = (os.getenv("FEEDBACK_BASE_URL") or "").rstrip("/")
    if not base_url:
        # First time: log once-ish so the operator knows the feature is
        # silently disabled until they set the env var.
        log.warning(
            "FEEDBACK_BASE_URL not set — skipping feedback footer injection "
            "(set it to e.g. https://email.utility.cx to enable)."
        )
        return

    try:
        token = store.mint_feedback_token(decision_id=decision_id, mailbox=mailbox)
    except Exception as e:
        log.warning("[%s] mint feedback token failed: %s", mailbox, e)
        return
    feedback_url = f"{base_url}/f/{token}"

    # Sentinel class `ee2-feedback-footer` is what _append_html_footer
    # checks for de-dup; keep it stable.
    html = (
        '<div class="ee2-feedback-footer" '
        'style="margin-top:24px;padding-top:8px;border-top:1px solid #e0e0e0;'
        'font-family:system-ui,-apple-system,Segoe UI,sans-serif;'
        'font-size:11px;color:#888;line-height:1.4">'
        '<em>email-engine triage:</em> classified as '
        f'<strong>{_html_escape(verdict_folder)}</strong> · '
        f'<a href="{feedback_url}" style="color:#5b6cff;text-decoration:none">'
        'wrong? tell me why ↗</a>'
        '</div>'
    )
    text = (
        f"---\n"
        f"email-engine triage: classified as {verdict_folder} · "
        f"wrong? {feedback_url}"
    )

    try:
        ok = provider.append_to_body(
            message_id, html_snippet=html, text_snippet=text,
        )
        if not ok:
            log.info("[%s] footer injection skipped for %s (provider returned False)",
                     mailbox, message_id[:24])
    except Exception as e:
        log.warning("[%s] footer injection failed for %s: %s",
                    mailbox, message_id[:24], e)


def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#39;"))


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


def reclassify_all(
    mailbox_email: str,
    store: Store | None = None,
    llm: LLMConfig | None = None,
    *,
    days_back: int | None = None,
    progress: dict | None = None,
) -> dict:
    """One-shot reclassification: walk INBOX + every legacy v1 folder,
    classify each thread once (per-conversation dedup), apply verdict to
    every message in the thread.

    `days_back`: limit to threads with received_at within the last N days.
    None = unlimited (walks the entire history). When set, the desc walker
    stops as soon as the page cursor steps before now() - days_back.

    `progress`: optional dict the worker mutates so the web UI can render
    live counts (current_folder, threads_classified, errors, folders_walked,
    folders_total, cursor_received_at). Pass {} to enable live tracking.

    Designed to be called from a Flask background thread (see web.py).
    Returns a summary dict (same shape as the final progress snapshot).
    """
    store = store or Store()
    llm = llm or LLMConfig.from_env()
    mb = store.get_mailbox(mailbox_email)
    if not mb:
        if progress is not None:
            progress["error"] = f"unknown mailbox {mailbox_email!r}"
        return {"ok": False, "error": f"unknown mailbox {mailbox_email!r}"}

    from datetime import timedelta
    stop_at: datetime | None = None
    if days_back and days_back > 0:
        stop_at = datetime.now(timezone.utc) - timedelta(days=days_back)

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
    counts = {
        "folders_walked": 0,
        "folders_total": len(folders_to_walk),
        "threads_classified": 0,
        "errors": 0,
        "current_folder": None,
        "cursor_received_at": None,
    }
    if progress is not None:
        progress.update(counts)

    # Snapshot "now" and advance the watermark up front so the forward
    # poller stops chewing through old INBOX mail behind us. Anything that
    # lands AFTER this moment will be picked up by the next forward poll;
    # reclassify owns everything older.
    started_at = datetime.now(timezone.utc)
    store.set_watermark(mb.mailbox, started_at)

    log.info(
        "[reclassify] starting for %s across %d folder(s) (newest-first, watermark→%s, stop_at=%s)",
        mb.mailbox, len(folders_to_walk), started_at.isoformat(),
        stop_at.isoformat() if stop_at else "none (all history)",
    )

    for folder in folders_to_walk:
        if _STOP:
            log.info("[reclassify] stop signal — abort mid-folder %s", folder)
            break
        counts["folders_walked"] += 1
        counts["current_folder"] = folder
        if progress is not None:
            progress["folders_walked"] = counts["folders_walked"]
            progress["current_folder"] = folder
        # Walk NEWEST → OLDEST so the dashboard fills up with recognizable
        # recent threads first; cursor tracks the OLDEST received_at seen
        # so the next page asks for messages strictly older than that.
        # First page asks for messages received BEFORE `started_at` so any
        # message arriving during reclassify falls to the forward poller.
        cursor: datetime | None = started_at
        while True:
            if _STOP:
                break
            try:
                batch = provider.list_folder(folder, cursor, page, descending=True)
            except Exception as e:
                log.exception("[reclassify] list %s failed: %s", folder, e)
                counts["errors"] += 1
                break
            if not batch:
                break
            hit_stop = False
            for m in batch:
                if _STOP:
                    break
                # Honor days_back: stop once we walk past the cutoff. We
                # still update the cursor so the break propagates cleanly.
                if stop_at and m.received_at and m.received_at < stop_at:
                    log.info("[reclassify] hit stop_at (%s) in %s — stopping folder walk",
                             stop_at.isoformat(), folder)
                    cursor = m.received_at
                    hit_stop = True
                    break
                if m.conversation_id and m.conversation_id in seen:
                    if m.received_at and (cursor is None or m.received_at < cursor):
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
                if m.received_at and (cursor is None or m.received_at < cursor):
                    cursor = m.received_at
                # Mirror live state out to the web UI's progress dict.
                if progress is not None:
                    progress["threads_classified"] = counts["threads_classified"]
                    progress["errors"] = counts["errors"]
                    progress["cursor_received_at"] = cursor.isoformat() if cursor else None
            if hit_stop or len(batch) < page:
                break
        log.info("[reclassify] folder %s done (threads=%d errors=%d)",
                 folder, counts["threads_classified"], counts["errors"])

    # Watermark stays at `started_at` — any message received during the
    # reclassify run is strictly newer than that and gets picked up by the
    # next forward poll cycle, so nothing falls through the crack.

    counts["current_folder"] = None
    if progress is not None:
        progress.update(counts)
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
