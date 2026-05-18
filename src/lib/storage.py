"""
storage.py — SQLite for decisions, feedback, watermarks, mailbox_config.

Tables:
  mailbox_config   — per-mailbox provider (graph|imap) + apply_mode +
                     IMAP server/port + enabled flag. Editable from the UI.
  watermarks       — last-seen receivedDateTime per mailbox so we only
                     classify NEW messages each cycle.
  decisions        — one row per classified email.
  feedback         — one row per feedback button click, keyed to decisions.

The mailbox_config table is the answer to "I want a UI toggle for apply mode."
The UI updates a row here; the poller picks it up next cycle.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


DEFAULT_DB_PATH = Path(os.getenv("FEEDBACK_DB_PATH", "/data/email-engine-v2.db"))


_SCHEMA = """
CREATE TABLE IF NOT EXISTS mailbox_config (
    mailbox        TEXT PRIMARY KEY,
    provider       TEXT NOT NULL,                 -- 'graph' | 'imap'
    apply_mode     TEXT NOT NULL DEFAULT 'tag_and_move',  -- 'tag' | 'move' | 'tag_and_move'
    enabled        INTEGER NOT NULL DEFAULT 1,
    imap_server    TEXT NOT NULL DEFAULT '',
    imap_port      INTEGER NOT NULL DEFAULT 993,
    poll_interval  INTEGER NOT NULL DEFAULT 30,   -- seconds
    notes          TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS watermarks (
    mailbox     TEXT PRIMARY KEY,
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id              TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    mailbox         TEXT NOT NULL,
    provider        TEXT NOT NULL,
    message_id      TEXT,
    internet_message_id TEXT,
    conversation_id TEXT,
    sender          TEXT,
    subject         TEXT,
    body_preview    TEXT,
    src_folder      TEXT,
    verdict_folder  TEXT NOT NULL,
    retrieved       TEXT,
    llm_raw         TEXT,
    apply_mode      TEXT,
    tagged          INTEGER NOT NULL DEFAULT 0,
    moved           INTEGER NOT NULL DEFAULT 0,
    apply_error     TEXT
);
CREATE INDEX IF NOT EXISTS idx_decisions_mailbox_created
    ON decisions(mailbox, created_at DESC);

CREATE TABLE IF NOT EXISTS feedback (
    id           TEXT PRIMARY KEY,
    created_at   TEXT NOT NULL,
    decision_id  TEXT NOT NULL REFERENCES decisions(id),
    correct      INTEGER NOT NULL,    -- 1 right, 0 wrong
    suggested    TEXT,                -- correct folder when wrong
    note         TEXT
);
CREATE INDEX IF NOT EXISTS idx_feedback_decision ON feedback(decision_id);

CREATE TABLE IF NOT EXISTS jobs (
    mailbox     TEXT NOT NULL,
    job_type    TEXT NOT NULL,        -- 'reclassify' | 'sweep'
    state_json  TEXT NOT NULL,        -- serialized state dict the UI renders
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (mailbox, job_type)
);

-- One row per CLASSIFICATION of a thread. Append-only, never deleted.
-- Lets us answer "what was the verdict for this thread at any past
-- moment?" — including capturing the case where a colleague replies and
-- the thread demotes from 1-Critical → 4-Medium, with the timestamp +
-- the LLM's reason for the change.
CREATE TABLE IF NOT EXISTS thread_verdicts (
    id                  TEXT PRIMARY KEY,
    mailbox             TEXT NOT NULL,
    conversation_id     TEXT NOT NULL,
    decided_at          TEXT NOT NULL,
    verdict_folder      TEXT NOT NULL,
    prev_verdict        TEXT,                       -- NULL on first classification
    reason              TEXT,                       -- LLM "reason" field if structured, else first line of raw
    model_raw           TEXT,                       -- full LLM reply for debugging
    trigger_message_id  TEXT,
    trigger_subject     TEXT,
    trigger_sender      TEXT,
    thread_size         INTEGER NOT NULL DEFAULT 0  -- # messages in thread at decision time
);
CREATE INDEX IF NOT EXISTS idx_tv_conv ON thread_verdicts(mailbox, conversation_id, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_tv_decided ON thread_verdicts(mailbox, decided_at DESC);

-- Per-thread persistent summary surfaced to downstream consumers (synct
-- now, portals later). One row per (mailbox, threadKey). Maintained in
-- the same LLM call as the classifier — per-update cost is constant
-- because we feed the LLM the *prior summary* + the new message only,
-- never the full thread.
--
-- threadKey is provider-prefixed:
--    "ms:<conversationId>"  (Microsoft Graph)
--    "gm:<conversationId>"  (Gmail / IMAP — uses X-GM-THRID for Gmail)
-- JSON columns are stored as TEXT (SQLite has no native JSON type;
-- Postgres-compatible — JSONB cast works on migration). Status enum
-- is stored as TEXT for the same reason.
CREATE TABLE IF NOT EXISTS thread_summaries (
    mailbox            TEXT NOT NULL,
    thread_key         TEXT NOT NULL,
    summary            TEXT NOT NULL DEFAULT '',
    key_facts          TEXT NOT NULL DEFAULT '[]',   -- JSON: [{label, value}]
    timeline           TEXT NOT NULL DEFAULT '[]',   -- JSON: [{date, event, messageId}]
    contacts           TEXT NOT NULL DEFAULT '[]',   -- JSON: [{name, email, role, organization, phone}]
    last_message_id    TEXT,
    last_message_at    TEXT,                          -- ISO-8601 UTC
    message_count      INTEGER NOT NULL DEFAULT 0,
    status             TEXT NOT NULL DEFAULT 'fresh', -- 'fresh' | 'stale' | 'errored'
    updated_at         TEXT NOT NULL,
    PRIMARY KEY (mailbox, thread_key)
);
CREATE INDEX IF NOT EXISTS idx_ts_last_message_at ON thread_summaries(last_message_at);

-- One-shot feedback tokens. Minted at injection time and embedded in
-- the footer link of an inbound email. Stored as sha256(token) so a
-- DB leak doesn't expose live tokens. Single-use (consumed on submit)
-- and expires after 30 days. The token IS the auth for /f/<token> —
-- no other credentials are required to view or submit feedback.
CREATE TABLE IF NOT EXISTS feedback_tokens (
    token_hash      TEXT PRIMARY KEY,         -- sha256 hex of the URL token
    decision_id     TEXT NOT NULL,            -- decisions.id this token gives feedback on
    mailbox         TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    used_at         TEXT,                      -- NULL until consumed; non-null = spent
    feedback_id     TEXT                       -- feedback.id created on consumption
);
CREATE INDEX IF NOT EXISTS idx_feedback_tokens_decision ON feedback_tokens(decision_id);

-- LLM-proposed taxonomy edits derived from accumulated feedback.
-- Stored so the user can review the suggestion before applying it
-- (which writes the JSON to /data/hierarchies/<mailbox>.json — the
-- persistent override that takes precedence over the in-repo file).
CREATE TABLE IF NOT EXISTS taxonomy_proposals (
    id              TEXT PRIMARY KEY,
    mailbox         TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    based_on_feedback_count INTEGER NOT NULL,
    current_json    TEXT NOT NULL,           -- snapshot of taxonomy at proposal time
    proposed_json   TEXT NOT NULL,           -- LLM's suggested replacement
    rationale       TEXT,                    -- LLM's per-change reasoning
    llm_raw         TEXT,                    -- full LLM reply for debugging
    applied_at      TEXT,                    -- non-null = user applied it
    discarded_at    TEXT                     -- non-null = user discarded it
);
CREATE INDEX IF NOT EXISTS idx_taxonomy_proposals_mailbox
    ON taxonomy_proposals(mailbox, created_at DESC);
"""


# --- Dataclasses ------------------------------------------------------------

@dataclass
class MailboxConfig:
    mailbox: str
    provider: str
    apply_mode: str
    enabled: bool
    imap_server: str
    imap_port: int
    poll_interval: int
    notes: str


@dataclass
class ThreadSummary:
    mailbox: str
    thread_key: str
    summary: str
    key_facts: list[dict]
    timeline: list[dict]
    contacts: list[dict]
    last_message_id: str | None
    last_message_at: str | None
    message_count: int
    status: str
    updated_at: str


# Provider → threadKey prefix. The contract synct relies on:
#   ms:<conversationId>  (Microsoft Graph)
#   gm:<conversationId>  (Gmail / IMAP — value comes from X-GM-THRID for Gmail
#                         or the IMAP Message-ID for vanilla servers)
THREAD_KEY_PREFIX = {"graph": "ms", "imap": "gm"}


def make_thread_key(provider: str, conversation_id: str) -> str:
    """Compose the provider-prefixed thread key downstream consumers query by.
    Returns '' if conversation_id is empty so callers can short-circuit."""
    if not conversation_id:
        return ""
    return f"{THREAD_KEY_PREFIX.get(provider, provider)}:{conversation_id}"


@dataclass
class Decision:
    id: str
    created_at: str
    mailbox: str
    provider: str
    message_id: str | None
    internet_message_id: str | None
    conversation_id: str | None
    sender: str | None
    subject: str | None
    body_preview: str | None
    src_folder: str | None
    verdict_folder: str
    retrieved: str | None
    llm_raw: str | None
    apply_mode: str | None
    tagged: bool
    moved: bool
    apply_error: str | None


# --- Store ------------------------------------------------------------------

class Store:
    def __init__(self, path: Path | str = DEFAULT_DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self.path, isolation_level=None, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

    # --- mailbox_config -----------------------------------------------------

    def upsert_mailbox(self, mb: MailboxConfig) -> None:
        with self._conn() as c:
            c.execute(
                """INSERT INTO mailbox_config
                   (mailbox, provider, apply_mode, enabled, imap_server, imap_port, poll_interval, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(mailbox) DO UPDATE SET
                     provider=excluded.provider,
                     apply_mode=excluded.apply_mode,
                     enabled=excluded.enabled,
                     imap_server=excluded.imap_server,
                     imap_port=excluded.imap_port,
                     poll_interval=excluded.poll_interval,
                     notes=excluded.notes""",
                (
                    mb.mailbox, mb.provider, mb.apply_mode, 1 if mb.enabled else 0,
                    mb.imap_server, mb.imap_port, mb.poll_interval, mb.notes,
                ),
            )

    def list_mailboxes(self) -> list[MailboxConfig]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM mailbox_config ORDER BY mailbox"
            ).fetchall()
        return [_row_to_mailbox(r) for r in rows]

    def get_mailbox(self, mailbox: str) -> MailboxConfig | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM mailbox_config WHERE mailbox = ?", (mailbox,)
            ).fetchone()
        return _row_to_mailbox(row) if row else None

    def delete_mailbox(self, mailbox: str) -> int:
        with self._conn() as c:
            cur = c.execute("DELETE FROM mailbox_config WHERE mailbox = ?", (mailbox,))
        return cur.rowcount

    # --- watermarks ---------------------------------------------------------

    def get_watermark(self, mailbox: str) -> datetime | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT received_at FROM watermarks WHERE mailbox = ?", (mailbox,)
            ).fetchone()
        if not row:
            return None
        try:
            return datetime.fromisoformat(row["received_at"])
        except ValueError:
            return None

    def set_watermark(self, mailbox: str, ts: datetime) -> None:
        iso = ts.astimezone(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                """INSERT INTO watermarks (mailbox, received_at) VALUES (?, ?)
                   ON CONFLICT(mailbox) DO UPDATE SET received_at=excluded.received_at""",
                (mailbox, iso),
            )

    def reset_watermark(self, mailbox: str) -> None:
        """Drop the watermark so the next poll walks the inbox from the start."""
        with self._conn() as c:
            c.execute("DELETE FROM watermarks WHERE mailbox = ?", (mailbox,))

    def delete_decisions_for_thread(self, mailbox: str, conversation_id: str) -> int:
        """Drop prior decision rows for a thread so a re-classification can
        rewrite them with the new verdict (matches v1's behavior). Without
        this, reclassifying a thread would leave stale rows alongside the
        new ones, and the dashboard would show conflicting answers."""
        if not conversation_id:
            return 0
        with self._conn() as c:
            cur = c.execute(
                "DELETE FROM decisions WHERE mailbox = ? AND conversation_id = ?",
                (mailbox, conversation_id),
            )
        return cur.rowcount

    # --- decisions ----------------------------------------------------------

    def insert_decision(
        self, *,
        mailbox: str,
        provider: str,
        message_id: str | None,
        internet_message_id: str | None,
        conversation_id: str | None,
        sender: str | None,
        subject: str | None,
        body_preview: str | None,
        src_folder: str | None,
        verdict_folder: str,
        retrieved: list[str] | None,
        llm_raw: str | None,
        apply_mode: str | None,
        tagged: bool,
        moved: bool,
        apply_error: str | None,
    ) -> str:
        did = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                """INSERT INTO decisions
                    (id, created_at, mailbox, provider, message_id, internet_message_id,
                     conversation_id, sender, subject, body_preview, src_folder,
                     verdict_folder, retrieved, llm_raw, apply_mode, tagged, moved, apply_error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    did, now, mailbox, provider, message_id, internet_message_id,
                    conversation_id, sender, subject, body_preview, src_folder,
                    verdict_folder,
                    ",".join(retrieved) if retrieved else None,
                    llm_raw, apply_mode,
                    1 if tagged else 0, 1 if moved else 0,
                    apply_error,
                ),
            )
        return did

    def get_decision(self, decision_id: str) -> Decision | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM decisions WHERE id = ?", (decision_id,)).fetchone()
        return _row_to_decision(row) if row else None

    def recent_decisions(self, mailbox: str | None = None, limit: int = 100) -> list[Decision]:
        with self._conn() as c:
            if mailbox:
                rows = c.execute(
                    "SELECT * FROM decisions WHERE mailbox = ? ORDER BY created_at DESC LIMIT ?",
                    (mailbox, limit),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM decisions ORDER BY created_at DESC LIMIT ?", (limit,),
                ).fetchall()
        return [_row_to_decision(r) for r in rows]

    # --- feedback -----------------------------------------------------------

    def record_feedback(self, *, decision_id: str, correct: bool, suggested: str | None, note: str | None) -> str:
        fid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                """INSERT INTO feedback (id, created_at, decision_id, correct, suggested, note)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (fid, now, decision_id, 1 if correct else 0, suggested, note),
            )
        return fid

    # --- jobs (reclassify / sweep state, survives redeploys) ---------------

    def upsert_job(self, mailbox: str, job_type: str, state: dict) -> None:
        """Persist a job's full state dict. Called by the worker at start,
        end, and (optionally) periodically as it progresses. The state
        survives container redeploys so the /mailboxes card always shows
        the last known result, not a blank slate."""
        import json as _json
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                """INSERT INTO jobs (mailbox, job_type, state_json, updated_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(mailbox, job_type) DO UPDATE SET
                     state_json=excluded.state_json,
                     updated_at=excluded.updated_at""",
                (mailbox, job_type, _json.dumps(state), now),
            )

    def get_job(self, mailbox: str, job_type: str) -> dict | None:
        import json as _json
        with self._conn() as c:
            row = c.execute(
                "SELECT state_json FROM jobs WHERE mailbox = ? AND job_type = ?",
                (mailbox, job_type),
            ).fetchone()
        if not row:
            return None
        try:
            return _json.loads(row["state_json"])
        except Exception:
            return None

    # --- thread_verdicts (append-only history) -----------------------------

    def get_latest_thread_verdict(self, mailbox: str, conversation_id: str) -> str | None:
        """Return the most recent verdict_folder this mailbox had for the
        thread, or None if it's never been classified. Used by the poller
        to fill `prev_verdict` on the next thread_verdicts row."""
        if not conversation_id:
            return None
        with self._conn() as c:
            row = c.execute(
                """SELECT verdict_folder FROM thread_verdicts
                   WHERE mailbox = ? AND conversation_id = ?
                   ORDER BY decided_at DESC LIMIT 1""",
                (mailbox, conversation_id),
            ).fetchone()
        return row["verdict_folder"] if row else None

    def record_thread_verdict(
        self, *,
        mailbox: str,
        conversation_id: str,
        verdict_folder: str,
        prev_verdict: str | None,
        reason: str | None,
        model_raw: str | None,
        trigger_message_id: str | None,
        trigger_subject: str | None,
        trigger_sender: str | None,
        thread_size: int,
    ) -> str:
        tvid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                """INSERT INTO thread_verdicts
                   (id, mailbox, conversation_id, decided_at, verdict_folder,
                    prev_verdict, reason, model_raw, trigger_message_id,
                    trigger_subject, trigger_sender, thread_size)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (tvid, mailbox, conversation_id, now, verdict_folder,
                 prev_verdict, reason, model_raw, trigger_message_id,
                 trigger_subject, trigger_sender, thread_size),
            )
        return tvid

    def list_threads(self, mailbox: str | None = None, limit: int = 200) -> list[dict]:
        """One row per conversation_id: latest verdict, subject, sender,
        message count, last activity. Drives the /threads tab."""
        sql = """
            SELECT
              d.conversation_id                                    AS conversation_id,
              d.mailbox                                            AS mailbox,
              MAX(d.created_at)                                    AS last_activity,
              COUNT(*)                                             AS msg_count,
              (SELECT verdict_folder FROM decisions
                 WHERE conversation_id = d.conversation_id AND mailbox = d.mailbox
                 ORDER BY created_at DESC LIMIT 1)                 AS latest_verdict,
              (SELECT subject FROM decisions
                 WHERE conversation_id = d.conversation_id AND mailbox = d.mailbox
                 ORDER BY created_at DESC LIMIT 1)                 AS subject,
              (SELECT sender FROM decisions
                 WHERE conversation_id = d.conversation_id AND mailbox = d.mailbox
                 ORDER BY created_at DESC LIMIT 1)                 AS latest_sender,
              (SELECT body_preview FROM decisions
                 WHERE conversation_id = d.conversation_id AND mailbox = d.mailbox
                 ORDER BY created_at DESC LIMIT 1)                 AS latest_preview,
              (SELECT COUNT(*) FROM thread_verdicts
                 WHERE conversation_id = d.conversation_id AND mailbox = d.mailbox) AS verdict_count
            FROM decisions d
            WHERE d.conversation_id IS NOT NULL AND d.conversation_id != ''
        """
        args: list = []
        if mailbox:
            sql += " AND d.mailbox = ?"
            args.append(mailbox)
        sql += " GROUP BY d.mailbox, d.conversation_id ORDER BY last_activity DESC LIMIT ?"
        args.append(limit)
        with self._conn() as c:
            rows = c.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    def list_thread_changes(
        self, mailbox: str | None = None,
        only_changes: bool = True,
        limit: int = 200,
    ) -> list[dict]:
        """Rows from thread_verdicts. With only_changes=True (default),
        filter to where prev_verdict != verdict_folder (and is non-null) —
        the actual verdict CHANGES. With only_changes=False, every recorded
        classification (useful for full audit)."""
        sql = "SELECT * FROM thread_verdicts WHERE 1=1"
        args: list = []
        if mailbox:
            sql += " AND mailbox = ?"
            args.append(mailbox)
        if only_changes:
            sql += " AND prev_verdict IS NOT NULL AND prev_verdict != verdict_folder"
        sql += " ORDER BY decided_at DESC LIMIT ?"
        args.append(limit)
        with self._conn() as c:
            rows = c.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    def thread_verdict_history(self, mailbox: str, conversation_id: str) -> list[dict]:
        """Full timeline of verdicts for one thread, oldest first.
        Used by the per-thread drill-down."""
        with self._conn() as c:
            rows = c.execute(
                """SELECT * FROM thread_verdicts
                   WHERE mailbox = ? AND conversation_id = ?
                   ORDER BY decided_at ASC""",
                (mailbox, conversation_id),
            ).fetchall()
        return [dict(r) for r in rows]

    # --- feedback_tokens (one-shot URLs injected into email bodies) --------

    def mint_feedback_token(
        self, *, decision_id: str, mailbox: str, ttl_days: int = 30,
    ) -> str:
        """Generate a new opaque token, persist sha256(token), and return
        the RAW token for embedding in the URL. The plaintext token is
        never written to disk — only its hash is stored."""
        import secrets, hashlib
        from datetime import timedelta
        token = secrets.token_urlsafe(24)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(days=ttl_days)).isoformat()
        with self._conn() as c:
            c.execute(
                """INSERT INTO feedback_tokens
                   (token_hash, decision_id, mailbox, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (token_hash, decision_id, mailbox, now.isoformat(), expires),
            )
        return token

    def validate_feedback_token(self, token: str) -> dict | None:
        """Return {decision_id, mailbox, used_at, expires_at} for a token
        that exists, has not expired, and has not been consumed.
        Returns None on any failure mode (caller renders the same
        friendly 'this link is no longer valid' page either way)."""
        if not token:
            return None
        import hashlib
        h = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._conn() as c:
            row = c.execute(
                """SELECT decision_id, mailbox, expires_at, used_at
                   FROM feedback_tokens WHERE token_hash = ?""",
                (h,),
            ).fetchone()
        if not row:
            return None
        if row["used_at"]:
            return None
        try:
            exp = datetime.fromisoformat(row["expires_at"])
            if exp <= datetime.now(timezone.utc):
                return None
        except ValueError:
            return None
        return {
            "decision_id": row["decision_id"],
            "mailbox":     row["mailbox"],
            "expires_at":  row["expires_at"],
        }

    def consume_feedback_token(self, token: str, feedback_id: str) -> bool:
        """Mark the token as used, attaching the feedback row it created.
        Returns False if the token was already consumed in a race with
        another submission (rare — same user double-clicking)."""
        import hashlib
        h = hashlib.sha256(token.encode("ascii")).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            cur = c.execute(
                """UPDATE feedback_tokens
                   SET used_at = ?, feedback_id = ?
                   WHERE token_hash = ? AND used_at IS NULL""",
                (now, feedback_id, h),
            )
        return cur.rowcount > 0

    # --- taxonomy_proposals (LLM-suggested hierarchy edits) ----------------

    def insert_taxonomy_proposal(
        self, *, mailbox: str, based_on_feedback_count: int,
        current_json: str, proposed_json: str,
        rationale: str | None, llm_raw: str | None,
    ) -> str:
        pid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                """INSERT INTO taxonomy_proposals
                   (id, mailbox, created_at, based_on_feedback_count,
                    current_json, proposed_json, rationale, llm_raw)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (pid, mailbox, now, based_on_feedback_count,
                 current_json, proposed_json, rationale, llm_raw),
            )
        return pid

    def get_taxonomy_proposal(self, proposal_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM taxonomy_proposals WHERE id = ?", (proposal_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_taxonomy_proposals(
        self, mailbox: str | None = None, limit: int = 50,
    ) -> list[dict]:
        with self._conn() as c:
            if mailbox:
                rows = c.execute(
                    """SELECT * FROM taxonomy_proposals WHERE mailbox = ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (mailbox, limit),
                ).fetchall()
            else:
                rows = c.execute(
                    """SELECT * FROM taxonomy_proposals
                       ORDER BY created_at DESC LIMIT ?""", (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def mark_taxonomy_proposal(
        self, proposal_id: str, *, applied: bool, discarded: bool,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        col = "applied_at" if applied else "discarded_at" if discarded else None
        if not col:
            return
        with self._conn() as c:
            c.execute(
                f"UPDATE taxonomy_proposals SET {col} = ? WHERE id = ?",
                (now, proposal_id),
            )

    # --- thread_summaries (one row per (mailbox, thread_key)) --------------

    def get_thread_summary(
        self, mailbox: str, thread_key: str,
    ) -> ThreadSummary | None:
        """Return the current summary state for this thread, or None if
        the thread has never been summarized (cold start)."""
        if not thread_key:
            return None
        with self._conn() as c:
            row = c.execute(
                """SELECT * FROM thread_summaries
                   WHERE mailbox = ? AND thread_key = ?""",
                (mailbox, thread_key),
            ).fetchone()
        return _row_to_thread_summary(row) if row else None

    def find_thread_summaries_by_key(self, thread_key: str) -> list[ThreadSummary]:
        """Return every ThreadSummary matching this thread_key across all
        mailboxes. Used by the read endpoint when the caller didn't pin
        a mailbox — usually one row, but a forwarded thread could appear
        in two mailboxes with the same conversation id."""
        if not thread_key:
            return []
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM thread_summaries WHERE thread_key = ?",
                (thread_key,),
            ).fetchall()
        return [_row_to_thread_summary(r) for r in rows]

    def upsert_thread_summary(
        self, *,
        mailbox: str,
        thread_key: str,
        summary: str,
        key_facts: list[dict],
        timeline: list[dict],
        contacts: list[dict],
        last_message_id: str | None,
        last_message_at: str | None,
        message_count: int,
        status: str,
    ) -> None:
        """Write the new ThreadSummary state. Replaces the prior row."""
        import json as _json
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                """INSERT INTO thread_summaries
                     (mailbox, thread_key, summary, key_facts, timeline, contacts,
                      last_message_id, last_message_at, message_count, status, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(mailbox, thread_key) DO UPDATE SET
                     summary=excluded.summary,
                     key_facts=excluded.key_facts,
                     timeline=excluded.timeline,
                     contacts=excluded.contacts,
                     last_message_id=excluded.last_message_id,
                     last_message_at=excluded.last_message_at,
                     message_count=excluded.message_count,
                     status=excluded.status,
                     updated_at=excluded.updated_at""",
                (
                    mailbox, thread_key, summary,
                    _json.dumps(key_facts or []),
                    _json.dumps(timeline or []),
                    _json.dumps(contacts or []),
                    last_message_id, last_message_at,
                    int(message_count), status, now,
                ),
            )

    def feedback_export(self, mailbox: str | None = None) -> list[dict]:
        sql = """
            SELECT d.mailbox, d.provider, d.sender, d.subject, d.body_preview,
                   d.verdict_folder AS model_choice,
                   f.correct, f.suggested, f.note, f.created_at
            FROM feedback f
            JOIN decisions d ON d.id = f.decision_id
        """
        args: tuple = ()
        if mailbox:
            sql += " WHERE d.mailbox = ?"
            args = (mailbox,)
        sql += " ORDER BY f.created_at DESC"
        with self._conn() as c:
            rows = c.execute(sql, args).fetchall()
        return [dict(r) for r in rows]


# --- Row → dataclass --------------------------------------------------------

def _row_to_mailbox(r: sqlite3.Row) -> MailboxConfig:
    return MailboxConfig(
        mailbox=r["mailbox"],
        provider=r["provider"],
        apply_mode=r["apply_mode"],
        enabled=bool(r["enabled"]),
        imap_server=r["imap_server"],
        imap_port=r["imap_port"],
        poll_interval=r["poll_interval"],
        notes=r["notes"],
    )


def _row_to_thread_summary(r: sqlite3.Row) -> ThreadSummary:
    import json as _json
    def _load(s: str | None, default):
        if not s:
            return default
        try:
            return _json.loads(s)
        except Exception:
            return default
    return ThreadSummary(
        mailbox=r["mailbox"],
        thread_key=r["thread_key"],
        summary=r["summary"] or "",
        key_facts=_load(r["key_facts"], []),
        timeline=_load(r["timeline"], []),
        contacts=_load(r["contacts"], []),
        last_message_id=r["last_message_id"],
        last_message_at=r["last_message_at"],
        message_count=r["message_count"] or 0,
        status=r["status"] or "fresh",
        updated_at=r["updated_at"],
    )


def _row_to_decision(r: sqlite3.Row) -> Decision:
    return Decision(
        id=r["id"],
        created_at=r["created_at"],
        mailbox=r["mailbox"],
        provider=r["provider"],
        message_id=r["message_id"],
        internet_message_id=r["internet_message_id"],
        conversation_id=r["conversation_id"],
        sender=r["sender"],
        subject=r["subject"],
        body_preview=r["body_preview"],
        src_folder=r["src_folder"],
        verdict_folder=r["verdict_folder"],
        retrieved=r["retrieved"],
        llm_raw=r["llm_raw"],
        apply_mode=r["apply_mode"],
        tagged=bool(r["tagged"]),
        moved=bool(r["moved"]),
        apply_error=r["apply_error"],
    )
