"""
web.py — Flask dashboard.

Routes:
  GET  /                          decisions list + feedback pills
  GET  /mailboxes                 mailbox config table + apply-mode toggle
  POST /mailboxes/<email>         update one mailbox (apply_mode/enabled/etc.)
  POST /mailboxes                 add a new mailbox
  POST /mailboxes/<email>/delete  remove a mailbox
  GET  /hierarchies/<email>       (read-only) view this mailbox's taxonomy
  POST /feedback                  record a feedback row
  GET  /api/feedback.csv          export joined feedback dataset
  GET  /api/decisions.json        decisions API
  GET  /healthz                   Railway probe

Auth: HTTP basic via WEB_USER + WEB_PASS. Refuses (503) when either is
empty so the dashboard is never exposed without credentials.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import sqlite3
import tempfile
import threading
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import (Flask, Response, abort, after_this_request, jsonify,
                   render_template_string, request, send_file)

from classifier import hierarchy_path_for, invalidate_cache, list_folders
from lib.apply import APPLY_MODES
from lib.storage import MAILBOX_PROFILES, MailboxConfig, Store, ThreadSummary
from poller import reclassify_all


# Name of the cookie we use to remember "who is submitting feedback".
# Self-attested email; cookie is set on every successful submission.
# Honest-but-spoofable — fine for trusted internal users; swap for a
# real auth flow if the user pool ever grows beyond that.
USER_COOKIE = "ee2_user"
USER_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # one year


def _current_user(default: str | None = None) -> str:
    """Return the cookie-remembered user identifier, or the supplied
    default (typically the mailbox address) if no cookie is set."""
    val = (request.cookies.get(USER_COOKIE) or "").strip()
    return val or (default or "")


def _api_key_mask(v: str | None) -> str:
    """Render '(not set)' when null/empty, else '(set: ...XXXX)' showing
    just the last 4 chars. Operators can verify the right key is in
    place without exposing the secret in HTML. The Basic-auth dashboard
    already gates access — last 4 leaks are an acceptable tradeoff for
    'did I paste the wrong key?' confirmability."""
    if not v:
        return "(not set — uses LLM_API_KEY env)"
    s = str(v).strip()
    if len(s) <= 4:
        return "(set: ****)"
    return f"(set: …{s[-4:]})"


log = logging.getLogger(__name__)


# Reclassify status (in-memory; one job at a time per mailbox).
_reclassify_lock = threading.Lock()
_reclassify_state: dict[str, dict] = {}  # mailbox → status dict

# Sweep-to-inbox status (one job at a time per mailbox).
_sweep_lock = threading.Lock()
_sweep_state: dict[str, dict] = {}      # mailbox → status dict


load_dotenv()
app = Flask(__name__)
store = Store()


# Jinja filter: map any verdict folder name to a stable color class.
# Buckets verdicts by their LEADING DIGIT so cross-generation variants
# (1-Critical, 1-CRITICAL-X, _1-CRITICAL-X) all share the same color.
@app.template_filter("verdict_class")
def verdict_class(v: str | None) -> str:
    if not v:
        return "vu"
    for c in v:
        if c.isdigit():
            return f"v{c}"
    return "vu"


@app.template_filter("api_key_mask")
def api_key_mask_filter(v: str | None) -> str:
    return _api_key_mask(v)


# --- Auth -------------------------------------------------------------------

def _require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        user = os.getenv("WEB_USER", "")
        pw = os.getenv("WEB_PASS", "")
        if not user or not pw:
            return Response("Dashboard disabled: set WEB_USER and WEB_PASS.", status=503)
        a_hdr = request.authorization
        if not a_hdr or a_hdr.username != user or a_hdr.password != pw:
            return Response(
                "Auth required.", status=401,
                headers={"WWW-Authenticate": 'Basic realm="email-engine-v2"'},
            )
        return fn(*a, **kw)
    return wrapper


def _require_api_auth(fn):
    """Auth for machine-to-machine API endpoints (synct, portals).
    Accepts:
      - Bearer token matching EMAIL_ENGINE_API_KEY env var (preferred)
      - Basic auth with WEB_USER/WEB_PASS (so manual curls + the
        dashboard's existing creds still work)
    Service is locked down (503) until at least one auth method is
    configured."""
    @wraps(fn)
    def wrapper(*a, **kw):
        api_key = os.getenv("EMAIL_ENGINE_API_KEY", "").strip()
        user = os.getenv("WEB_USER", "").strip()
        pw = os.getenv("WEB_PASS", "").strip()
        if not api_key and not (user and pw):
            return Response(
                "API disabled: set EMAIL_ENGINE_API_KEY (or WEB_USER+WEB_PASS).",
                status=503,
            )
        # Bearer token first (case-insensitive scheme; compare key in
        # constant time to avoid trivial timing-side-channel leaks).
        hdr = request.headers.get("Authorization", "")
        if api_key and hdr.lower().startswith("bearer "):
            import hmac
            token = hdr[7:].strip()
            if hmac.compare_digest(token, api_key):
                return fn(*a, **kw)
        # Basic auth fallback.
        if user and pw:
            a_hdr = request.authorization
            if a_hdr and a_hdr.username == user and a_hdr.password == pw:
                return fn(*a, **kw)
        return Response(
            "Unauthorized.", status=401,
            headers={"WWW-Authenticate": 'Bearer realm="email-engine-v2"'},
        )
    return wrapper


# --- Feedback landing page (no auth — the token IS the auth) ---------------

@app.get("/f/<token>")
def feedback_landing(token: str):
    """Display the feedback form for a footer-link click. Anonymous;
    the unguessable single-use token gates access (it's the equivalent
    of a magic-link). Renders a friendly 'no longer valid' page on
    any failure mode rather than leaking which one (used vs. expired
    vs. never-existed).

    The 'your email' field auto-fills from (in order):
      1. The ee2_user cookie set by your last submission
      2. The mailbox owner address — sensible default on first click
    The user can always override either default before submitting."""
    ctx = store.validate_feedback_token(token)
    if not ctx:
        return render_template_string(_FEEDBACK_DONE_HTML,
                                      title="link expired",
                                      body="This feedback link is no longer valid. It may have been used already, or it may have expired (links last 30 days).")
    d = store.get_decision(ctx["decision_id"])
    if not d:
        return render_template_string(_FEEDBACK_DONE_HTML,
                                      title="decision not found",
                                      body="The classification this link points to is no longer in the database. No further action needed.")
    folders = list_folders(ctx["mailbox"])
    prefilled_user = _current_user(default=ctx["mailbox"])
    return render_template_string(
        _FEEDBACK_FORM_HTML,
        token=token,
        decision=d,
        folders=folders,
        mailbox=ctx["mailbox"],
        prefilled_user=prefilled_user,
    )


@app.post("/f/<token>")
def feedback_landing_post(token: str):
    """Persist the feedback row + consume the token. Shows a thank-you
    page so the user gets visible confirmation in the browser."""
    ctx = store.validate_feedback_token(token)
    if not ctx:
        return render_template_string(_FEEDBACK_DONE_HTML,
                                      title="link expired",
                                      body="This feedback link is no longer valid. If you'd already submitted feedback, that's the most likely reason."), 410
    d = store.get_decision(ctx["decision_id"])
    if not d:
        return render_template_string(_FEEDBACK_DONE_HTML,
                                      title="decision not found",
                                      body="That classification is no longer in the database."), 410

    correct_raw = (request.form.get("correct") or "").strip()
    suggested = (request.form.get("suggested") or "").strip() or None
    note = (request.form.get("note") or "").strip() or None
    user_identifier = (
        (request.form.get("user_identifier") or "").strip()
        or _current_user(default=ctx["mailbox"])
    ) or None
    if correct_raw not in ("1", "0"):
        abort(400, "correct=0|1 required")
    if correct_raw == "0" and not suggested:
        abort(400, "wrong-classification feedback needs a suggested folder")

    fid = store.record_feedback(
        decision_id=ctx["decision_id"],
        correct=correct_raw == "1",
        suggested=suggested,
        note=note,
        user_identifier=user_identifier,
    )
    # consume_feedback_token returns False on race; either way the row
    # was already written so we don't surface the race to the user.
    store.consume_feedback_token(token, fid)
    invalidate_cache()
    resp = Response(render_template_string(
        _FEEDBACK_DONE_HTML,
        title="thank you",
        body=("Got it — recorded. Your reason will feed into the next "
              "taxonomy-improvement proposal on the dashboard."),
    ))
    if user_identifier:
        resp.set_cookie(USER_COOKIE, user_identifier,
                        max_age=USER_COOKIE_MAX_AGE, samesite="Lax")
    return resp


# --- Health -----------------------------------------------------------------

@app.get("/healthz")
def healthz():
    return "ok", 200


# --- Decisions / Feedback ---------------------------------------------------

@app.get("/")
@_require_auth
def index():
    mailbox = request.args.get("mailbox") or None
    limit = int(request.args.get("limit", "100"))
    rows = store.recent_decisions(mailbox=mailbox, limit=limit)
    folders = list_folders(mailbox or "_default")
    return render_template_string(
        _DECISIONS_HTML,
        rows=rows,
        mailboxes=[m.mailbox for m in store.list_mailboxes()],
        current_mailbox=mailbox or "",
        folders=folders,
    )


@app.post("/feedback")
@_require_auth
def feedback():
    decision_id = request.form.get("decision_id", "").strip()
    correct_raw = request.form.get("correct", "").strip()
    suggested = request.form.get("suggested", "").strip() or None
    note = request.form.get("note", "").strip() or None
    # `user_identifier` on dashboard pills: take from form if provided,
    # else fall back to the cookie (set by the most recent submission
    # in this browser). Dashboard pills don't expose the field today,
    # so this almost always comes from the cookie.
    user_identifier = (
        (request.form.get("user_identifier") or "").strip()
        or _current_user()
    ) or None
    if not decision_id or correct_raw not in ("1", "0"):
        abort(400, "decision_id and correct=0|1 required")
    if correct_raw == "0" and not suggested:
        abort(400, "wrong-folder feedback needs a suggested folder")
    if not store.get_decision(decision_id):
        abort(404, "unknown decision_id")
    fid = store.record_feedback(
        decision_id=decision_id,
        correct=correct_raw == "1",
        suggested=suggested,
        note=note,
        user_identifier=user_identifier,
    )
    invalidate_cache()
    if request.headers.get("Accept", "").startswith("application/json"):
        resp = jsonify({"ok": True, "feedback_id": fid})
    else:
        resp = Response(status=303, headers={"Location": request.referrer or "/"})
    if user_identifier:
        resp.set_cookie(USER_COOKIE, user_identifier,
                        max_age=USER_COOKIE_MAX_AGE, samesite="Lax")
    return resp


@app.get("/api/feedback.csv")
@_require_auth
def feedback_csv():
    mailbox = request.args.get("mailbox") or None
    rows = store.feedback_export(mailbox=mailbox)
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="feedback.csv"'})


@app.get("/api/decisions.csv")
@_require_auth
def decisions_csv():
    """Full decisions dump as CSV. Streams from the DB in pages of 1000
    so a million-row table doesn't blow up memory."""
    mailbox = request.args.get("mailbox") or None
    cols = ("id", "created_at", "mailbox", "provider", "message_id",
            "internet_message_id", "conversation_id", "sender", "subject",
            "body_preview", "src_folder", "verdict_folder", "retrieved",
            "llm_raw", "apply_mode", "tagged", "moved", "apply_error")

    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        page = 1000
        offset = 0
        while True:
            sql = "SELECT " + ",".join(cols) + " FROM decisions"
            args: list = []
            if mailbox:
                sql += " WHERE mailbox = ?"
                args.append(mailbox)
            sql += " ORDER BY created_at ASC LIMIT ? OFFSET ?"
            args.extend([page, offset])
            with store._conn() as c:
                rows = c.execute(sql, args).fetchall()
            if not rows:
                break
            for r in rows:
                w.writerow([r[k] for k in cols])
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)
            offset += len(rows)
            if len(rows) < page:
                break
    fname = f"decisions-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.csv"
    return Response(gen(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# --- Threads tab (consolidated by conversation) -----------------------------

@app.get("/threads")
@_require_auth
def threads_view():
    mailbox = request.args.get("mailbox") or None
    limit = int(request.args.get("limit", "200"))
    group_by = request.args.get("group", "date")  # 'date' (default) | 'verdict'
    compact = request.args.get("compact", "0") == "1"

    rows = store.list_threads(mailbox=mailbox, limit=limit)

    # Compact view: collapse rows that share BOTH subject AND sender into
    # a single representative row. Keeps the most-recently-active thread
    # as the visible row (link target) and accumulates a `collapsed_count`
    # of how many same-subject same-sender threads it represents.
    # Templated noise (Teams notifications, marketing blasts, form auto-
    # replies) folds down to one row each.
    raw_count = len(rows)
    if compact:
        # rows are already sorted last_activity DESC by SQL, so the first
        # occurrence of any (subject, sender) is the most recent.
        from collections import OrderedDict
        bucket: OrderedDict = OrderedDict()
        for r in rows:
            key = ((r.get("subject") or "").strip(),
                   (r.get("latest_sender") or "").strip())
            if not key[0] and not key[1]:
                # No identifying info — keep each row separate to avoid
                # collapsing legitimately different anonymous mail.
                bucket[("__solo__", id(r))] = {**r, "collapsed_count": 1}
                continue
            if key in bucket:
                bucket[key]["collapsed_count"] += 1
                bucket[key]["msg_count"] += r.get("msg_count", 0) or 0
            else:
                bucket[key] = {**r, "collapsed_count": 1}
        rows = list(bucket.values())

    # Per-verdict counts AFTER collapse (so headers + chip strip reflect
    # what's actually visible in the table).
    group_counts: dict[str, int] = {}
    for r in rows:
        v = r.get("latest_verdict") or "(unknown)"
        group_counts[v] = group_counts.get(v, 0) + 1

    if group_by == "verdict":
        # Sort: verdict ASC (so 1- before 2- before ...), then most recent
        # activity first within each group.
        def sort_key(r):
            return (
                r.get("latest_verdict") or "zzz",
                -1 * (datetime.fromisoformat(r["last_activity"]).timestamp()
                      if r.get("last_activity") else 0),
            )
        rows.sort(key=sort_key)

    return render_template_string(
        _THREADS_HTML,
        rows=rows,
        mailboxes=[m.mailbox for m in store.list_mailboxes()],
        current_mailbox=mailbox or "",
        limit=limit,
        group_by=group_by,
        group_counts=group_counts,
        compact=compact,
        raw_count=raw_count,
    )


@app.get("/threads/<path:conversation_id>")
@_require_auth
def thread_detail(conversation_id: str):
    """Full timeline for one thread: every verdict row over time."""
    mailbox = request.args.get("mailbox") or None
    # If mailbox isn't supplied, look it up from the most recent decision row.
    if not mailbox:
        rows = store.recent_decisions(limit=1000)
        for d in rows:
            if d.conversation_id == conversation_id:
                mailbox = d.mailbox
                break
    if not mailbox:
        abort(404, "no decision rows found for that conversation_id")
    history = store.thread_verdict_history(mailbox, conversation_id)
    # Also pull the per-message decisions so the user can see WHAT moved.
    with store._conn() as c:
        decisions = [dict(r) for r in c.execute(
            """SELECT created_at, sender, subject, verdict_folder, tagged, moved,
                      apply_error, body_preview
               FROM decisions WHERE mailbox = ? AND conversation_id = ?
               ORDER BY created_at ASC""", (mailbox, conversation_id)).fetchall()]
    return render_template_string(
        _THREAD_DETAIL_HTML,
        mailbox=mailbox,
        conversation_id=conversation_id,
        history=history,
        decisions=decisions,
    )


# --- Changes tab (thread verdict transitions) -------------------------------

@app.get("/changes")
@_require_auth
def changes_view():
    mailbox = request.args.get("mailbox") or None
    only_changes = request.args.get("changes_only", "1") == "1"
    limit = int(request.args.get("limit", "200"))
    rows = store.list_thread_changes(mailbox=mailbox, only_changes=only_changes, limit=limit)
    return render_template_string(
        _CHANGES_HTML,
        rows=rows,
        mailboxes=[m.mailbox for m in store.list_mailboxes()],
        current_mailbox=mailbox or "",
        only_changes=only_changes,
        limit=limit,
    )


# --- DB download (consistent snapshot via sqlite3.backup) -------------------

@app.get("/admin/db.sqlite")
@_require_auth
def download_db():
    """Stream a consistent snapshot of the live SQLite DB.

    Uses sqlite3's online backup API rather than copying the file
    directly — that way the user gets a clean DB even if a write is
    in flight at request time. Snapshot is staged to a temp file and
    cleaned up after the response is sent."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="db-dl-"))
    snap = tmp_dir / "email-engine-v2.db"
    src = sqlite3.connect(str(store.path))
    dst = sqlite3.connect(str(snap))
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()

    @after_this_request
    def _cleanup(response):
        try:
            snap.unlink(missing_ok=True)
            tmp_dir.rmdir()
        except Exception:
            log.exception("temp snapshot cleanup failed")
        return response

    fname = f"email-engine-v2-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.db"
    return send_file(str(snap), as_attachment=True, download_name=fname,
                     mimetype="application/x-sqlite3")


# --- Engine status API (drives the synct "engine" visual) ------------------

# Verdict bucketing: map leading digit → semantic name the synct
# dashboard renders. v1 used `_1-CRITICAL-X` style names; v2 emits the
# short ones (`1-Critical`). Returning BOTH a bucketed totals dict and
# the raw per-verdict counts lets the frontend pick the shape it prefers
# without forcing either side to migrate first.
_VERDICT_BUCKET_BY_DIGIT = {
    "1": "critical",
    "2": "high",
    "3": "personal",
    "4": "medium",
    "5": "low_ignore",
}


def _verdict_bucket(name: str) -> str:
    for ch in (name or ""):
        if ch.isdigit():
            return _VERDICT_BUCKET_BY_DIGIT.get(ch, "other")
    return "other"


def _engine_totals(mailbox: str) -> dict:
    """COUNT decisions by verdict_folder for one mailbox, plus a
    digit-bucketed rollup the frontend can render as Critical/High/etc.
    Single SQL pass — fast even on large decisions tables."""
    with store._conn() as c:
        rows = c.execute(
            """SELECT verdict_folder, COUNT(*) AS n
               FROM decisions WHERE mailbox = ?
               GROUP BY verdict_folder""",
            (mailbox,),
        ).fetchall()
    by_bucket = {k: 0 for k in
                 ("critical", "high", "personal", "medium", "low_ignore", "other")}
    by_verdict: dict[str, int] = {}
    total = 0
    for r in rows:
        v = r["verdict_folder"] or ""
        n = int(r["n"])
        by_verdict[v] = n
        by_bucket[_verdict_bucket(v)] += n
        total += n
    by_bucket["total"] = total
    return {"by_bucket": by_bucket, "by_verdict": by_verdict}


@app.get("/api/engine/mailboxes")
@_require_api_auth
def engine_mailboxes():
    """List configured mailboxes — minimal shape for the synct
    dashboard's mailbox picker. Skips IMAP server/port + notes so the
    payload stays small."""
    return jsonify([
        {
            "mailbox":    m.mailbox,
            "provider":   m.provider,
            "profile":    m.profile,
            "enabled":    m.enabled,
            "apply_mode": m.apply_mode,
        }
        for m in store.list_mailboxes()
    ])


@app.get("/api/engine/status")
@_require_api_auth
def engine_status():
    """Single endpoint that feeds the synct engine visual: countdown
    timer + per-bucket totals + status badge + the most recent N
    decisions for the classify→tag→move animation.

    `last_poll_at` is the LATER of (watermark, most recent decision
    created_at). The watermark advances every poll cycle even when no
    new mail arrived; the decision timestamp moves only when something
    actually got classified. Taking the max gives the most truthful
    "last activity" reading.

    `next_poll_at` is derived (last_poll_at + poll_interval), not a
    real schedule the poller publishes — close enough for a UI
    countdown that rounds to the second.

    `status`: 'disabled' | 'idle' | 'error'. 'error' fires when the
    most recent decision has a non-null apply_error (a tag/move call
    failed on Graph)."""
    mailbox = (request.args.get("mailbox") or "").strip()
    if not mailbox:
        return jsonify({"error": "mailbox query param required"}), 400
    mb = store.get_mailbox(mailbox)
    if not mb:
        return jsonify({"error": "unknown mailbox", "mailbox": mailbox}), 404

    from datetime import datetime as _dt, timedelta, timezone as _tz

    recent_limit = max(1, min(int(request.args.get("recent", "20")), 100))
    recent_rows = store.recent_decisions(mailbox=mailbox, limit=recent_limit)

    last_decision_at: _dt | None = None
    if recent_rows:
        try:
            ts = recent_rows[0].created_at
            if ts.endswith("Z"):
                ts = ts.replace("Z", "+00:00")
            last_decision_at = _dt.fromisoformat(ts)
        except (ValueError, AttributeError):
            last_decision_at = None

    watermark = store.get_watermark(mailbox)
    candidates = [t for t in (watermark, last_decision_at) if t is not None]
    last_poll_at = max(candidates) if candidates else None
    next_poll_at = (
        last_poll_at + timedelta(seconds=mb.poll_interval)
        if last_poll_at else None
    )

    if not mb.enabled:
        status = "disabled"
        last_error = None
    elif recent_rows and recent_rows[0].apply_error:
        status = "error"
        last_error = recent_rows[0].apply_error
    else:
        status = "idle"
        last_error = None

    return jsonify({
        "mailbox":               mailbox,
        "enabled":               mb.enabled,
        "profile":               mb.profile,
        "apply_mode":            mb.apply_mode,
        "status":                status,
        "last_error":            last_error,
        "last_poll_at":          last_poll_at.isoformat() if last_poll_at else None,
        "next_poll_at":          next_poll_at.isoformat() if next_poll_at else None,
        "poll_interval_seconds": mb.poll_interval,
        "server_time":           _dt.now(_tz.utc).isoformat(),
        "totals":                _engine_totals(mailbox),
        "recent": [
            {
                "id":             d.id,
                "created_at":     d.created_at,
                "subject":        d.subject,
                "sender":         d.sender,
                "verdict_folder": d.verdict_folder,
                "verdict_bucket": _verdict_bucket(d.verdict_folder),
                "tagged":         d.tagged,
                "moved":          d.moved,
                "apply_mode":     d.apply_mode,
                "apply_error":    d.apply_error,
            }
            for d in recent_rows
        ],
    })


# --- ThreadSummary read API (synct now, portals later) ---------------------

def _thread_summary_json(ts: ThreadSummary) -> dict:
    """Wire shape downstream consumers (synct, portals) parse. Keep the
    keys camelCase to match the Prisma-style schema synct_utility uses
    on its side; the SQLite columns stay snake_case server-side."""
    return {
        "threadKey":     ts.thread_key,
        "mailbox":       ts.mailbox,
        "summary":       ts.summary,
        "keyFacts":      ts.key_facts,
        "timeline":      ts.timeline,
        "contacts":      ts.contacts,
        "lastMessageId": ts.last_message_id,
        "lastMessageAt": ts.last_message_at,
        "messageCount":  ts.message_count,
        "status":        ts.status,
        "updatedAt":     ts.updated_at,
    }


@app.get("/api/threads/<path:thread_key>/summary")
@_require_api_auth
def thread_summary_get(thread_key: str):
    """Read endpoint for the per-thread ThreadSummary.

    Cold start: 404 if no row exists. The caller (synct_utility) falls
    back to its live LLM summarize the first time it asks; subsequent
    polls hit the cached row here.

    Disambiguation: optional ?mailbox= when the same threadKey was seen
    in multiple connected mailboxes (rare — same conversation forwarded
    between mailboxes). Without it, we 200 the single match, 409 on
    ambiguity, 404 on miss."""
    mailbox = (request.args.get("mailbox") or "").strip()
    if mailbox:
        ts = store.get_thread_summary(mailbox, thread_key)
        if not ts:
            return jsonify({"error": "not_found", "threadKey": thread_key, "mailbox": mailbox}), 404
        return jsonify(_thread_summary_json(ts))
    matches = store.find_thread_summaries_by_key(thread_key)
    if not matches:
        return jsonify({"error": "not_found", "threadKey": thread_key}), 404
    if len(matches) > 1:
        return jsonify({
            "error": "ambiguous_mailbox",
            "threadKey": thread_key,
            "mailboxes": [m.mailbox for m in matches],
            "hint": "pass ?mailbox=<email> to disambiguate",
        }), 409
    return jsonify(_thread_summary_json(matches[0]))


@app.get("/api/decisions.json")
@_require_auth
def decisions_json():
    mailbox = request.args.get("mailbox") or None
    limit = int(request.args.get("limit", "200"))
    rows = store.recent_decisions(mailbox=mailbox, limit=limit)
    return jsonify([{
        "id": d.id, "created_at": d.created_at, "mailbox": d.mailbox,
        "provider": d.provider, "sender": d.sender, "subject": d.subject,
        "verdict_folder": d.verdict_folder, "apply_mode": d.apply_mode,
        "tagged": d.tagged, "moved": d.moved, "apply_error": d.apply_error,
    } for d in rows])


# --- Mailbox config ---------------------------------------------------------

@app.get("/mailboxes")
@_require_auth
def mailboxes_list():
    return render_template_string(
        _MAILBOXES_HTML,
        mailboxes=store.list_mailboxes(),
        apply_modes=APPLY_MODES,
        profiles=MAILBOX_PROFILES,
        env_model=os.getenv("LLM_MODEL", "qwen2.5:7b"),
    )


@app.post("/mailboxes")
@_require_auth
def mailboxes_add():
    profile = request.form.get("profile", "personal").strip().lower()
    if profile not in MAILBOX_PROFILES:
        abort(400, f"profile must be one of {MAILBOX_PROFILES}")
    mb = MailboxConfig(
        mailbox=request.form.get("mailbox", "").strip().lower(),
        provider=request.form.get("provider", "graph"),
        apply_mode=request.form.get("apply_mode", "tag_and_move"),
        enabled=request.form.get("enabled", "1") == "1",
        imap_server=request.form.get("imap_server", "").strip(),
        imap_port=int(request.form.get("imap_port", "993")),
        poll_interval=int(request.form.get("poll_interval", "30")),
        notes=request.form.get("notes", "").strip(),
        profile=profile,
        llm_model=(request.form.get("llm_model", "").strip() or None),
        llm_api_key=(request.form.get("llm_api_key", "").strip() or None),
    )
    if not mb.mailbox:
        abort(400, "mailbox required")
    if mb.provider not in ("graph", "imap"):
        abort(400, "provider must be graph or imap")
    if mb.apply_mode not in APPLY_MODES:
        abort(400, f"apply_mode must be one of {APPLY_MODES}")
    store.upsert_mailbox(mb)
    return Response(status=303, headers={"Location": "/mailboxes"})


@app.post("/mailboxes/<path:email>")
@_require_auth
def mailboxes_update(email: str):
    cur = store.get_mailbox(email)
    if not cur:
        abort(404, "unknown mailbox")
    cur.apply_mode = request.form.get("apply_mode", cur.apply_mode)
    cur.enabled = request.form.get("enabled", "1" if cur.enabled else "0") == "1"
    cur.imap_server = request.form.get("imap_server", cur.imap_server)
    cur.imap_port = int(request.form.get("imap_port", cur.imap_port))
    cur.poll_interval = int(request.form.get("poll_interval", cur.poll_interval))
    cur.notes = request.form.get("notes", cur.notes)
    new_profile = request.form.get("profile", cur.profile).strip().lower()
    if new_profile and new_profile not in MAILBOX_PROFILES:
        abort(400, f"profile must be one of {MAILBOX_PROFILES}")
    cur.profile = new_profile or cur.profile
    # llm_model: empty string → clear back to env default. Distinct from
    # "field missing from form" (which preserves the current value).
    if "llm_model" in request.form:
        cur.llm_model = (request.form.get("llm_model") or "").strip() or None
    # llm_api_key (3-state):
    #   - `clear_api_key=1` checkbox → clear back to env default
    #   - non-empty input value      → set the new key
    #   - empty input + no checkbox  → preserve (lets the user save the
    #     row without re-entering the secret every time, since the input
    #     is always rendered empty for security)
    if request.form.get("clear_api_key") == "1":
        cur.llm_api_key = None
    else:
        new_key = (request.form.get("llm_api_key") or "").strip()
        if new_key:
            cur.llm_api_key = new_key
    if cur.apply_mode not in APPLY_MODES:
        abort(400, f"apply_mode must be one of {APPLY_MODES}")
    store.upsert_mailbox(cur)
    return Response(status=303, headers={"Location": "/mailboxes"})


@app.post("/mailboxes/<path:email>/delete")
@_require_auth
def mailboxes_delete(email: str):
    store.delete_mailbox(email)
    return Response(status=303, headers={"Location": "/mailboxes"})


@app.post("/mailboxes/<path:email>/pause")
@_require_auth
def mailboxes_pause(email: str):
    """One-click pause: flips enabled=0 on this mailbox. Polling stops
    next cycle (≤30s typical). Use to halt LLM cost on a specific
    mailbox without losing its config."""
    if store.set_mailbox_enabled(email, False) == 0:
        abort(404, "unknown mailbox")
    return Response(status=303, headers={"Location": "/mailboxes?msg=paused"})


@app.post("/mailboxes/<path:email>/resume")
@_require_auth
def mailboxes_resume(email: str):
    if store.set_mailbox_enabled(email, True) == 0:
        abort(404, "unknown mailbox")
    return Response(status=303, headers={"Location": "/mailboxes?msg=resumed"})


@app.post("/mailboxes/pause-all")
@_require_auth
def mailboxes_pause_all():
    """Panic button: pauses every mailbox at once. Use when you spot
    runaway cost in your LLM dashboard and want to stop the bleeding
    before debugging which mailbox is responsible."""
    n = store.set_all_mailboxes_enabled(False)
    return Response(status=303, headers={"Location": f"/mailboxes?msg=paused-all&n={n}"})


@app.post("/mailboxes/resume-all")
@_require_auth
def mailboxes_resume_all():
    n = store.set_all_mailboxes_enabled(True)
    return Response(status=303, headers={"Location": f"/mailboxes?msg=resumed-all&n={n}"})


@app.post("/mailboxes/<path:email>/reclassify")
@_require_auth
def mailboxes_reclassify(email: str):
    """Kick off a reclassify-all in a background thread. One job per
    mailbox at a time — second click while running is a no-op.

    Form param `days_back` (int, optional): if set, limit the walk to
    threads received within the last N days. Omit or set to 0 for the
    full inbox history.
    """
    if not store.get_mailbox(email):
        abort(404, "unknown mailbox")

    days_back_raw = (request.form.get("days_back") or "").strip()
    days_back: int | None = None
    if days_back_raw:
        try:
            v = int(days_back_raw)
            if v > 0:
                days_back = v
        except ValueError:
            abort(400, "days_back must be an integer or blank")

    with _reclassify_lock:
        cur = _reclassify_state.get(email)
        if cur and cur.get("running"):
            return Response(status=303, headers={"Location": "/mailboxes?msg=already-running"})
        # `progress` is mutated live by reclassify_all; the /status endpoint
        # reads from the same state dict so the dashboard sees counts
        # increment in real time rather than only at the end.
        state = {
            "running": True,
            "started_at": _now_iso(),
            "finished_at": None,
            "days_back": days_back,
            "progress": {
                "folders_walked": 0,
                "folders_total": 0,
                "threads_classified": 0,
                "errors": 0,
                "current_folder": None,
                "cursor_received_at": None,
            },
            "error": None,
        }
        _reclassify_state[email] = state

    # Persist the initial "started" snapshot so it survives a redeploy
    # even if the worker thread never gets to finish.
    store.upsert_job(email, "reclassify", state)

    def _worker():
        try:
            reclassify_all(email, days_back=days_back, progress=state["progress"])
            with _reclassify_lock:
                state["running"] = False
                state["finished_at"] = _now_iso()
        except Exception as e:
            log.exception("reclassify worker failed: %s", e)
            with _reclassify_lock:
                state["running"] = False
                state["finished_at"] = _now_iso()
                state["error"] = str(e)
        # Always persist final state — success or failure — so the card
        # on /mailboxes survives a redeploy.
        try:
            store.upsert_job(email, "reclassify", state)
        except Exception:
            log.exception("could not persist reclassify state for %s", email)

    threading.Thread(target=_worker, daemon=True, name=f"reclassify-{email}").start()
    return Response(status=303, headers={"Location": "/mailboxes?msg=reclassify-started"})


@app.get("/api/reclassify/<path:email>/status")
@_require_auth
def reclassify_status(email: str):
    # In-memory state is the freshest (mid-run); fall back to the
    # persisted SQLite row from the previous run so the card on
    # /mailboxes is never blank after a redeploy.
    with _reclassify_lock:
        cur = _reclassify_state.get(email)
    if cur:
        return jsonify(cur)
    persisted = store.get_job(email, "reclassify")
    if persisted:
        return jsonify(persisted)
    return jsonify({"running": False, "progress": None})


# --- Sweep folder → Inbox ---------------------------------------------------

@app.post("/mailboxes/<path:email>/sweep-to-inbox")
@_require_auth
def mailboxes_sweep_to_inbox(email: str):
    """Move every message in `from_folder` to the well-known Inbox.

    Form param `from_folder` (required, str): displayName of the source
    folder. Common use case: cleaning up stray folders that v1 (or a
    manual mistake) left behind — e.g. a literal '_inbox' folder created
    by an old quirky classifier."""
    mb = store.get_mailbox(email)
    if not mb:
        abort(404, "unknown mailbox")
    from_folder = (request.form.get("from_folder") or "").strip()
    if not from_folder:
        abort(400, "from_folder is required")
    if from_folder.strip().lower() == "inbox":
        abort(400, "source folder cannot be the inbox itself")

    with _sweep_lock:
        cur = _sweep_state.get(email)
        if cur and cur.get("running"):
            return Response(status=303, headers={"Location": "/mailboxes?msg=sweep-already-running"})
        state = {
            "running": True,
            "from_folder": from_folder,
            "started_at": _now_iso(),
            "finished_at": None,
            "progress": {
                "source_folder": from_folder,
                "moved": 0, "errors": 0, "last_error": None, "done": False,
            },
            "error": None,
        }
        _sweep_state[email] = state

    store.upsert_job(email, "sweep", state)

    def _worker():
        try:
            from providers import make_provider
            provider = make_provider(
                mb.mailbox, mb.provider,
                imap_server=mb.imap_server, imap_port=mb.imap_port,
            )
            provider.sweep_folder_to_inbox(from_folder, progress=state["progress"])
            with _sweep_lock:
                state["running"] = False
                state["finished_at"] = _now_iso()
        except Exception as e:
            log.exception("sweep worker failed: %s", e)
            with _sweep_lock:
                state["running"] = False
                state["finished_at"] = _now_iso()
                state["error"] = str(e)
        try:
            store.upsert_job(email, "sweep", state)
        except Exception:
            log.exception("could not persist sweep state for %s", email)

    threading.Thread(target=_worker, daemon=True, name=f"sweep-{email}").start()
    return Response(status=303, headers={"Location": "/mailboxes?msg=sweep-started"})


@app.get("/api/sweep/<path:email>/status")
@_require_auth
def sweep_status(email: str):
    with _sweep_lock:
        cur = _sweep_state.get(email)
    if cur:
        return jsonify(cur)
    persisted = store.get_job(email, "sweep")
    if persisted:
        return jsonify(persisted)
    return jsonify({"running": False, "progress": None})


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# --- Hierarchy (read-only view; edit JSON files for now) -------------------

@app.get("/hierarchies/<path:email>")
@_require_auth
def hierarchy_view(email: str):
    path = hierarchy_path_for(email)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return Response(f"Cannot read {path}: {e}", status=500)
    return render_template_string(_HIERARCHY_HTML, mailbox=email, path=str(path), data=data)


# --- Templates --------------------------------------------------------------

_NAV = """\
<nav style="margin: 0 0 1rem; font-size: 0.9rem;">
  <a href="/">Decisions</a> ·
  <a href="/threads">Threads</a> ·
  <a href="/changes">Changes</a> ·
  <a href="/feedback-review">Feedback</a> ·
  <a href="/test-classify">Test</a> ·
  <a href="/mailboxes">Mailboxes</a> ·
  <a href="/admin/db.sqlite">Download DB</a> ·
  <a href="/api/feedback.csv">Feedback CSV</a> ·
  <a href="/api/decisions.csv">Decisions CSV</a>
</nav>
"""

_VERDICT_CSS = """\
<style>
  /* Verdict color buckets. Use these by adding the v1/v2/.../vu class
     to a .verdict span. Same color regardless of underscore-prefix or
     -X suffix variants — the verdict_class filter normalizes them. */
  .verdict.v1 { background: #ffe1e1; color: #7a1212; border: 1px solid #d04040; }
  .verdict.v2 { background: #ffe5cf; color: #7a3f00; border: 1px solid #e07a1f; }
  .verdict.v3 { background: #e6dcff; color: #3f1e7a; border: 1px solid #7e57c2; }
  .verdict.v4 { background: #fff3c8; color: #5e4a00; border: 1px solid #d4a82a; }
  .verdict.v5 { background: #d8eede; color: #1e5232; border: 1px solid #5c9b76; }
  .verdict.vu { background: #ececf0; color: #555;    border: 1px solid #b6b6bd; }
  .verdict { font-family: ui-monospace, "Cascadia Mono", Menlo, monospace;
             font-size: 0.78rem; font-weight: 600; padding: 2px 8px;
             border-radius: 999px; letter-spacing: 0.2px; white-space: nowrap; }
  /* Section header rows on grouped tables */
  tr.grouphdr td { background: #f5f5f8; font-weight: 700; padding: 10px 8px;
                   border-top: 2px solid #d6d6dc; border-bottom: 1px solid #d6d6dc; }
  tr.grouphdr .group-count { font-weight: 400; color: #777; margin-left: 8px; font-size: 0.85rem; }
</style>
<style media="(prefers-color-scheme: dark)">
  .verdict.v1 { background: #4a1d1d !important; color: #ffb3b3 !important; border-color: #7a3a3a !important; }
  .verdict.v2 { background: #3a2510 !important; color: #ffc798 !important; border-color: #6a4520 !important; }
  .verdict.v3 { background: #2a1f4a !important; color: #cbb6ff !important; border-color: #5a4a98 !important; }
  .verdict.v4 { background: #3a2f10 !important; color: #ffdc80 !important; border-color: #6a5520 !important; }
  .verdict.v5 { background: #1f3025 !important; color: #b3d8c4 !important; border-color: #3a6045 !important; }
  .verdict.vu { background: #2a2c34 !important; color: #c0c2c8 !important; border-color: #4a4d55 !important; }
  tr.grouphdr td { background: #1c1f26 !important; border-top-color: #2c2f36 !important; border-bottom-color: #2c2f36 !important; color: #d6d8dd !important; }
  tr.grouphdr .group-count { color: #98989f !important; }
</style>
"""


# Single dark-mode override block prepended to every page. Uses
# prefers-color-scheme so it follows your OS setting (no manual toggle —
# add one later if you find yourself flipping between modes a lot).
# Defined via CSS variables so the existing per-template inline styles
# can stay as-is; this block just retints body, tables, inputs, links,
# code, pre, banners, and pills.
_DARK_MODE_CSS = """\
<style>
@media (prefers-color-scheme: dark) {
  body { background: #15171b !important; color: #e6e6e9 !important; }
  .reclass-card { background: #1c1f26 !important; border-color: #2c2f36 !important; }
  .reclass-card table.metrics th { color: #b5b7be !important; }
  .reclass-card table.metrics th,
  .reclass-card table.metrics td { border-bottom-color: #2c2f36 !important; }
  .reclass-card .progbar { background: #2c2f36 !important; }
  a { color: #8eb1ff !important; }
  a:visited { color: #b89aff !important; }
  table th { background: #1f2228 !important; color: #d8d8dc !important; }
  table tr:hover { background: #1c1e23 !important; }
  table td, table th { border-bottom-color: #2c2f36 !important; }
  input[type=text], input[type=number], select, button,
  input[type=submit] {
    background: #1f2228 !important; color: #e6e6e9 !important;
    border: 1px solid #3a3d45 !important; border-radius: 3px;
  }
  input:focus, select:focus { outline: 2px solid #8eb1ff !important; outline-offset: -1px; }
  code { background: #2a2d34 !important; color: #e6e6e9 !important; }
  pre  { background: #11131a !important; color: #d8d8dc !important; }

  .verdict      { background: #233055 !important; color: #cbd6ff !important; }
  .mode         { background: #2a2d34 !important; color: #b0b3bb !important; }
  .err, .moved-no { color: #ff9d9d !important; }
  .help, .when, .sender, .reclass-status, .preview { color: #98989f !important; }
  .conv-tail { color: #6c6c72 !important; }
  .collapsed-chip { background: #1d2a4d !important; color: #cbd6ff !important;
                    border-color: #3a4c80 !important; }
  .pill.right   { background: #1c3a23 !important; color: #88e89c !important; border-color: #2e6a3a !important; }
  .pill.wrong   { background: #4a1f1f !important; color: #ffb0b0 !important; border-color: #7a3a3a !important; }
  .reclass      { background: #1d2a4d !important; color: #cbd6ff !important; border: 1px solid #3a4c80 !important; }
  .add          { background: #1c1f26 !important; border: 1px solid #2c2f36; }
  .banner       { background: #3a2e0e !important; border-left-color: #c08a16 !important; color: #f0e0a6 !important; }
  .banner.ok    { background: #14331e !important; border-left-color: #2e8a48 !important; color: #b6e8c2 !important; }
}
</style>
"""

_DECISIONS_HTML = """\
<!doctype html><title>email-engine-v2 — decisions</title>
<style>
  body { font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 1.5rem; }
  h1 { font-size: 1.2rem; margin: 0 0 1rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
  th { text-align: left; background: #fafafa; }
  /* .verdict styles live in _VERDICT_CSS (colored by leading digit). */
  .mode { font-size: 0.75rem; padding: 1px 5px; border-radius: 3px; background: #f3f3f3; color: #555; margin-left: 4px; }
  .err { color: #b00; font-size: 0.85rem; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; cursor: pointer; margin-right: 4px; }
  .pill.right { background: #d4f8d4; color: #060; border: 1px solid #6c6; }
  .pill.wrong { background: #fde0e0; color: #800; border: 1px solid #c66; }
  select { font-size: 0.85rem; padding: 2px 4px; }
  .subj { font-weight: 600; }
  .sender { color: #555; font-size: 0.85rem; }
  .when { color: #777; font-size: 0.8rem; white-space: nowrap; }
</style>
""" + _DARK_MODE_CSS + _VERDICT_CSS + _NAV + """\
<h1>Recent classifications {% if current_mailbox %}— {{ current_mailbox }}{% endif %}</h1>

<form method="get" style="margin-bottom: 1rem;">
  <label>Mailbox:
    <select name="mailbox" onchange="this.form.submit()">
      <option value="">(all)</option>
      {% for m in mailboxes %}
        <option value="{{ m }}" {% if m == current_mailbox %}selected{% endif %}>{{ m }}</option>
      {% endfor %}
    </select>
  </label>
</form>

<table>
  <thead>
    <tr><th>When</th><th>Mailbox</th><th>Email</th><th>Verdict</th><th>Feedback</th></tr>
  </thead>
  <tbody>
    {% for d in rows %}
    <tr>
      <td class="when">{{ d.created_at[:19].replace('T',' ') }}</td>
      <td>{{ d.mailbox }}<div style="font-size:0.75rem;color:#888">{{ d.provider }}</div></td>
      <td>
        <div class="subj">{{ d.subject or '(no subject)' }}</div>
        <div class="sender">{{ d.sender or '' }}</div>
      </td>
      <td>
        <span class="verdict {{ d.verdict_folder | verdict_class }}">{{ d.verdict_folder }}</span>
        <span class="mode">{{ d.apply_mode or '?' }}</span>
        {% if d.apply_error %}<div class="err">{{ d.apply_error }}</div>{% endif %}
        {% if not d.moved and d.apply_mode and d.apply_mode != 'tag' %}<div style="font-size:0.8rem;color:#a60">not moved</div>{% endif %}
      </td>
      <td>
        <form method="post" action="/feedback" style="display:inline">
          <input type="hidden" name="decision_id" value="{{ d.id }}">
          <input type="hidden" name="correct" value="1">
          <button class="pill right" type="submit">✓ right</button>
        </form>
        <form method="post" action="/feedback" style="display:inline">
          <input type="hidden" name="decision_id" value="{{ d.id }}">
          <input type="hidden" name="correct" value="0">
          <select name="suggested" required>
            <option value="" disabled selected>move to...</option>
            {% for f in folders %}
              <option value="{{ f.id or f.name }}">{{ f.name }}</option>
            {% endfor %}
          </select>
          <button class="pill wrong" type="submit">✗ wrong</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
"""


_MAILBOXES_HTML = """\
<!doctype html><title>email-engine-v2 — mailboxes</title>
<style>
  body { font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 1.5rem; max-width: 1100px; }
  h1, h2 { font-size: 1.1rem; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
  th { text-align: left; background: #fafafa; }
  input[type=text], input[type=number], select { padding: 3px 5px; font-size: 0.9rem; }
  button { padding: 4px 10px; }
  .add { background: #f8f8fc; padding: 12px; border-radius: 6px; }
  code { background: #f0f0f4; padding: 1px 4px; border-radius: 3px; }
  .help { color: #666; font-size: 0.85rem; }
  .banner { background: #fff8e0; border-left: 3px solid #d8a20a; padding: 8px 12px; margin: 0 0 1rem; font-size: 0.9rem; }
  .banner.ok { background: #e8f8ee; border-color: #1a9b4a; }
  .reclass { font-size: 0.8rem; background: #f0f4ff; border: 1px solid #b9c5ec; }
  .reclass-status { font-size: 0.8rem; color: #555; margin-top: 4px; }
  .reclass-card { display: none; margin-top: 8px; padding: 8px 12px; border: 1px solid #d6d6dc;
                  border-radius: 6px; background: #fbfbfd; max-width: 540px; font-size: 0.85rem; }
  .reclass-card.show { display: block; }
  .reclass-card table.metrics { border-collapse: collapse; width: 100%; margin: 6px 0 0; }
  .reclass-card table.metrics th, .reclass-card table.metrics td {
      padding: 3px 8px; border-bottom: 1px solid #ececf0; text-align: left; vertical-align: top;
      font-size: 0.85rem;
  }
  .reclass-card table.metrics th { font-weight: 600; color: #444; width: 40%; background: transparent; }
  .reclass-card .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
                       margin-right: 6px; vertical-align: middle; }
  .reclass-card .dot.running { background: #1aa8ff; animation: pulse 1.1s ease-in-out infinite; }
  .reclass-card .dot.done    { background: #2bb24c; }
  .reclass-card .dot.err     { background: #d84545; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }
  .reclass-card .progbar { height: 4px; background: #ececf0; border-radius: 2px;
                            overflow: hidden; margin-top: 6px; }
  .reclass-card .progbar > span { display: block; height: 100%; background: #1aa8ff;
                                  transition: width 250ms ease; }
  /* Same .preview + .conv-tail rules used on the /threads page; kept here
     so /changes can adopt them later if needed. */
</style>
""" + _DARK_MODE_CSS + _VERDICT_CSS + _NAV + """\
{% if request.args.get('msg') == 'reclassify-started' %}
  <div class="banner ok">Reclassify started — walks INBOX + every legacy <code>…-X</code> folder. Watch <a href="/">decisions</a> or poll <code>/api/reclassify/&lt;email&gt;/status</code>.</div>
{% elif request.args.get('msg') == 'already-running' %}
  <div class="banner">A reclassify is already in flight for that mailbox — second click ignored.</div>
{% elif request.args.get('msg') == 'sweep-started' %}
  <div class="banner ok">Sweep started — moving messages from the requested folder to Inbox in a background thread.</div>
{% elif request.args.get('msg') == 'sweep-already-running' %}
  <div class="banner">A sweep is already in flight for that mailbox — second click ignored.</div>
{% elif request.args.get('msg') == 'paused' %}
  <div class="banner">Mailbox paused. Polling stops on the next cycle (≤30s). Resume any time.</div>
{% elif request.args.get('msg') == 'resumed' %}
  <div class="banner ok">Mailbox resumed. Next poll cycle will pick it back up.</div>
{% elif request.args.get('msg') == 'paused-all' %}
  <div class="banner">Paused {{ request.args.get('n', '?') }} mailbox(es). All polling stops next cycle.</div>
{% elif request.args.get('msg') == 'resumed-all' %}
  <div class="banner ok">Resumed {{ request.args.get('n', '?') }} mailbox(es).</div>
{% endif %}
<h1>Mailboxes</h1>

<div style="margin-bottom: 1rem; display: flex; gap: 8px; align-items: center;">
  <form method="post" action="/mailboxes/pause-all" style="display:inline"
        onsubmit="return confirm('Pause ALL mailboxes? Polling stops on every mailbox next cycle. Use this for runaway LLM cost.')">
    <button type="submit" style="background: #d84545; color: #fff; border: none; padding: 6px 14px; border-radius: 4px; font-weight: 600;">⏸ Pause all</button>
  </form>
  <form method="post" action="/mailboxes/resume-all" style="display:inline"
        onsubmit="return confirm('Resume ALL mailboxes?')">
    <button type="submit" style="background: #2bb24c; color: #fff; border: none; padding: 6px 14px; border-radius: 4px; font-weight: 600;">▶ Resume all</button>
  </form>
  <span class="help" style="margin-left: 8px;">Panic button — pauses every mailbox. Use when LLM cost spikes; each mailbox's config is preserved.</span>
</div>

<table>
  <thead><tr>
    <th>Mailbox</th><th>Provider</th><th>Profile</th><th>Apply mode</th>
    <th>State</th><th>Model</th><th>API key</th>
    <th>IMAP server:port</th><th>Poll interval</th><th>Actions</th>
  </tr></thead>
  <tbody>
  {% for m in mailboxes %}
    <form method="post" action="/mailboxes/{{ m.mailbox }}">
    <tr>
      <td>
        {{ m.mailbox }}
        <div class="help"><a href="/hierarchies/{{ m.mailbox }}">view taxonomy</a></div>
      </td>
      <td>{{ m.provider }}</td>
      <td>
        <select name="profile" title="personal: feedback scoped per user. shared: feedback pooled across everyone.">
          {% for pr in profiles %}
            <option value="{{ pr }}" {% if pr == m.profile %}selected{% endif %}>{{ pr }}</option>
          {% endfor %}
        </select>
      </td>
      <td>
        <select name="apply_mode">
          {% for am in apply_modes %}
            <option value="{{ am }}" {% if am == m.apply_mode %}selected{% endif %}>{{ am }}</option>
          {% endfor %}
        </select>
      </td>
      <td>
        {# Keep enabled in the form so the Save button doesn't accidentally
           re-enable a paused mailbox. The one-click pause/resume buttons
           below are the recommended way to flip state. #}
        <input type="hidden" name="enabled" value="{% if m.enabled %}1{% else %}0{% endif %}">
        {% if m.enabled %}
          <span style="color: #2bb24c; font-weight: 700;" title="polling every cycle">● ACTIVE</span>
        {% else %}
          <span style="color: #d84545; font-weight: 700;" title="poller skips this mailbox">● PAUSED</span>
        {% endif %}
      </td>
      <td>
        <input type="text" name="llm_model" value="{{ m.llm_model or '' }}"
               placeholder="{{ env_model }}" size="22"
               title="Per-mailbox model override. Empty = use LLM_MODEL env default ({{ env_model }}). Set to e.g. 'claude-haiku-4-5' to save cost on a less-critical mailbox.">
      </td>
      <td>
        <div class="help" style="font-family: ui-monospace, monospace; margin-bottom: 4px;">
          {{ m.llm_api_key | api_key_mask }}
        </div>
        <input type="password" name="llm_api_key" value=""
               placeholder="paste new key to replace…" size="20" autocomplete="off"
               title="Per-mailbox API key. Submitting empty preserves the current value (so you don't have to retype on every Save). Paste a new key to replace; tick the clear box below to remove it.">
        <label style="font-size: 0.78rem; color: #666; display: block; margin-top: 2px;">
          <input type="checkbox" name="clear_api_key" value="1"> clear → use env default
        </label>
      </td>
      <td>
        {% if m.provider == 'imap' %}
          <input type="text" name="imap_server" value="{{ m.imap_server }}" size="20">
          :<input type="number" name="imap_port" value="{{ m.imap_port }}" size="5" style="width:60px">
        {% else %}
          <span class="help" title="Only used when provider = imap">n/a — Graph mailbox</span>
          <input type="hidden" name="imap_server" value="{{ m.imap_server }}">
          <input type="hidden" name="imap_port" value="{{ m.imap_port }}">
        {% endif %}
      </td>
      <td><input type="number" name="poll_interval" value="{{ m.poll_interval }}" style="width:60px"> s</td>
      <td>
        <button type="submit">Save</button>
      </td>
    </tr>
    </form>
    <tr>
      <td colspan="10" style="border-bottom: 2px solid #f0f0f0; padding-bottom: 12px;">
        <form method="post" action="/mailboxes/{{ m.mailbox }}/reclassify" style="display:inline-flex; gap:6px; align-items:center; flex-wrap:wrap;"
              id="reclass-form-{{ m.mailbox }}"
              onsubmit="return confirm('Reclassify {{ m.mailbox }}? Scope: ' + (document.getElementById('days-{{ m.mailbox }}').value ? 'last ' + document.getElementById('days-{{ m.mailbox }}').value + ' day(s)' : 'ALL history') + '. Walks INBOX plus every legacy …-X folder, newest first.')">
          <button type="submit" class="reclass">↻ Reclassify</button>
          <span class="help" style="margin-left:4px">last</span>
          <input type="number" min="1" max="3650" name="days_back" placeholder="all"
                 id="days-{{ m.mailbox }}" style="width:72px" title="Blank = walk all history">
          <span class="help">day(s)</span>
          <span class="help" style="margin-left:6px">quick:</span>
          {% for d in [7, 14, 30, 90] %}
            <button type="button" class="reclass" style="font-size:0.72rem;padding:1px 6px"
                    onclick="document.getElementById('days-{{ m.mailbox }}').value = {{ d }}">{{ d }}d</button>
          {% endfor %}
          <button type="button" class="reclass" style="font-size:0.72rem;padding:1px 6px"
                  onclick="document.getElementById('days-{{ m.mailbox }}').value = ''">all</button>
        </form>
        {% if m.enabled %}
          <form method="post" action="/mailboxes/{{ m.mailbox }}/pause" style="display:inline; margin-left: 12px;"
                onsubmit="return confirm('Pause {{ m.mailbox }}? Polling stops on the next cycle. Config is preserved; resume any time.')">
            <button type="submit" class="reclass" style="background: #fde0e0; border-color: #c66; color: #7a1212;">⏸ Pause</button>
          </form>
        {% else %}
          <form method="post" action="/mailboxes/{{ m.mailbox }}/resume" style="display:inline; margin-left: 12px;">
            <button type="submit" class="reclass" style="background: #d4f8d4; border-color: #6c6; color: #060;">▶ Resume</button>
          </form>
        {% endif %}
        <form method="post" action="/mailboxes/{{ m.mailbox }}/delete" style="display:inline; margin-left: 12px;"
              onsubmit="return confirm('Remove this mailbox? Decisions stay, polling stops.')">
          <button type="submit" style="font-size:0.75rem;color:#a00">delete</button>
        </form>
        <span class="help">{{ m.notes }}</span>
        <div style="margin-top: 8px;">
          <form method="post" action="/mailboxes/{{ m.mailbox }}/sweep-to-inbox" style="display:inline-flex; gap:6px; align-items:center; flex-wrap:wrap;"
                onsubmit="return confirm('Move every message in folder \\'' + this.from_folder.value + '\\' to ' + (this.from_folder.value.toLowerCase() === 'inbox' ? 'ERROR' : 'Inbox') + '? Per-message MOVE — runs in the background. Use for cleaning stray folders only.')">
            <span class="help">Sweep folder → Inbox:</span>
            <input type="text" name="from_folder" placeholder="e.g. _inbox" style="width:180px" required>
            <button type="submit" class="reclass" style="font-size:0.75rem;padding:2px 8px">Move all to Inbox</button>
          </form>
          <div class="reclass-status" id="sweep-status-{{ m.mailbox }}"></div>
        </div>
        <div class="reclass-card" id="card-{{ m.mailbox }}">
          <div><span class="dot" id="dot-{{ m.mailbox }}"></span><strong id="state-{{ m.mailbox }}">—</strong>
               <span class="help" style="margin-left:8px" id="scope-{{ m.mailbox }}"></span></div>
          <div class="progbar" id="progwrap-{{ m.mailbox }}" style="display:none"><span id="prog-{{ m.mailbox }}"></span></div>
          <table class="metrics">
            <tr><th>Started</th>          <td id="m-started-{{ m.mailbox }}">—</td></tr>
            <tr><th>Finished / elapsed</th><td id="m-finished-{{ m.mailbox }}">—</td></tr>
            <tr><th>Threads classified</th><td id="m-threads-{{ m.mailbox }}">0</td></tr>
            <tr><th>Errors</th>            <td id="m-errors-{{ m.mailbox }}">0</td></tr>
            <tr><th>Folders walked</th>    <td id="m-folders-{{ m.mailbox }}">0 / 0</td></tr>
            <tr><th>Current folder</th>    <td id="m-cur-{{ m.mailbox }}">—</td></tr>
            <tr><th>Walk cursor</th>       <td id="m-cursor-{{ m.mailbox }}">—</td></tr>
          </table>
        </div>
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table>

<div class="add">
<h2>Add a mailbox</h2>
<form method="post" action="/mailboxes">
  <label>Email <input type="text" name="mailbox" required size="30" placeholder="dave@9o4t.com"></label>
  <label>Provider
    <select name="provider">
      <option value="graph">graph (Microsoft 365 via token broker)</option>
      <option value="imap">imap (Gmail / Workspace)</option>
    </select>
  </label>
  <label>Apply mode
    <select name="apply_mode">
      {% for am in apply_modes %}<option value="{{ am }}">{{ am }}</option>{% endfor %}
    </select>
  </label>
  <label>Profile
    <select name="profile" title="personal: feedback scoped per user (your taxonomy reflects YOUR preferences). shared: feedback pooled (workflow mailboxes like quotes@/orders@/helpdesk@).">
      {% for pr in profiles %}<option value="{{ pr }}">{{ pr }}</option>{% endfor %}
    </select>
  </label>
  <label>Model <input type="text" name="llm_model" placeholder="{{ env_model }}" size="22"
                     title="Optional per-mailbox model override. Blank = use LLM_MODEL env default ({{ env_model }})."></label>
  <label>API key <input type="password" name="llm_api_key" placeholder="(blank = LLM_API_KEY env)" size="22" autocomplete="off"
                       title="Optional per-mailbox API key. Useful for cost attribution per inbox in the provider dashboard."></label>
  <br><br>
  <label>IMAP server <input type="text" name="imap_server" size="20" value="imap.gmail.com"></label>
  <label>Port <input type="number" name="imap_port" value="993" style="width:60px"></label>
  <label>Poll interval <input type="number" name="poll_interval" value="30" style="width:60px"> s</label>
  <br><br>
  <label>Notes <input type="text" name="notes" size="40" placeholder="optional"></label>
  <br><br>
  <button type="submit">Add mailbox</button>
</form>

<p class="help">For <strong>graph</strong>: token broker must be configured (<code>CALENDAR_URL</code> + <code>B2B_TOKEN</code> env vars); IMAP fields ignored.<br>
For <strong>imap</strong>: set <code>IMAP_&lt;SANITIZED_EMAIL&gt;_PASSWORD</code> in Railway secrets (e.g. <code>IMAP_DAVE_GMAIL_COM_PASSWORD</code>).</p>
</div>

<script>
// Live reclassify metrics table. Polls every 2s while a job runs,
// every 8s otherwise.
(function () {
  const mailboxes = {{ mailboxes | map(attribute='mailbox') | list | tojson }};

  function fmtDuration(ms) {
    if (ms < 1000) return `${ms} ms`;
    const s = Math.floor(ms / 1000);
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60), rs = s % 60;
    return `${m}m ${rs}s`;
  }
  function fmtUtc(iso) {
    if (!iso) return '—';
    return iso.slice(0, 19).replace('T', ' ') + ' UTC';
  }
  function set(id, txt) { const el = document.getElementById(id); if (el) el.textContent = txt; }

  function render(mb, s) {
    const card = document.getElementById(`card-${mb}`);
    if (!s || (!s.running && !s.progress && !s.error)) {
      if (card) card.classList.remove('show');
      return;
    }
    if (card) card.classList.add('show');

    const dot = document.getElementById(`dot-${mb}`);
    const state = document.getElementById(`state-${mb}`);
    if (s.running) {
      dot.className = 'dot running';
      state.textContent = 'Running…';
    } else if (s.error) {
      dot.className = 'dot err';
      state.textContent = 'Error';
    } else {
      dot.className = 'dot done';
      state.textContent = 'Complete';
    }

    const scope = s.days_back ? `scope: last ${s.days_back} day(s)` : 'scope: all history';
    set(`scope-${mb}`, scope);
    set(`m-started-${mb}`, fmtUtc(s.started_at));

    // Finished / elapsed cell shows finish time when done, live duration when running.
    if (s.running && s.started_at) {
      const dur = Date.now() - Date.parse(s.started_at);
      set(`m-finished-${mb}`, `running — ${fmtDuration(dur)}`);
    } else if (s.finished_at && s.started_at) {
      const dur = Date.parse(s.finished_at) - Date.parse(s.started_at);
      set(`m-finished-${mb}`, `${fmtUtc(s.finished_at)} (${fmtDuration(dur)})`);
    } else {
      set(`m-finished-${mb}`, '—');
    }

    const p = s.progress || {};
    set(`m-threads-${mb}`, String(p.threads_classified ?? 0));
    set(`m-errors-${mb}`,  String(p.errors ?? 0));
    set(`m-folders-${mb}`, `${p.folders_walked ?? 0} / ${p.folders_total ?? 0}`);
    set(`m-cur-${mb}`,     p.current_folder || (s.running ? 'starting…' : '—'));
    set(`m-cursor-${mb}`,  p.cursor_received_at ? fmtUtc(p.cursor_received_at) : '—');

    if (s.error) {
      set(`m-cur-${mb}`, s.error);
    }

    const progwrap = document.getElementById(`progwrap-${mb}`);
    const prog = document.getElementById(`prog-${mb}`);
    if (p.folders_total && p.folders_total > 0 && s.running) {
      progwrap.style.display = 'block';
      prog.style.width = `${Math.min(100, (p.folders_walked / p.folders_total) * 100).toFixed(1)}%`;
    } else {
      progwrap.style.display = 'none';
    }
  }

  function fmtSweep(s) {
    if (!s) return '';
    const src = s.from_folder ? `"${s.from_folder}" → Inbox` : '';
    const p = s.progress || {};
    if (s.running) return `… sweeping ${src}: moved ${p.moved || 0}, errors ${p.errors || 0}${p.last_error ? ' — ' + p.last_error : ''}`;
    if (s.error)   return `✗ sweep ${src} error: ${s.error}`;
    if (p.done)    return `✓ sweep ${src} done: moved ${p.moved || 0}, errors ${p.errors || 0}`;
    return '';
  }

  let pollMs = 8000;
  async function tick() {
    let anyRunning = false;
    for (const mb of mailboxes) {
      try {
        const r = await fetch(`/api/reclassify/${encodeURIComponent(mb)}/status`);
        if (r.ok) {
          const j = await r.json();
          render(mb, j);
          if (j && j.running) anyRunning = true;
        }
      } catch (_) {}
      try {
        const r2 = await fetch(`/api/sweep/${encodeURIComponent(mb)}/status`);
        if (r2.ok) {
          const j2 = await r2.json();
          const el = document.getElementById(`sweep-status-${mb}`);
          if (el) el.textContent = fmtSweep(j2);
          if (j2 && j2.running) anyRunning = true;
        }
      } catch (_) {}
    }
    pollMs = anyRunning ? 2000 : 8000;
    setTimeout(tick, pollMs);
  }
  tick();
})();
</script>
"""


_HIERARCHY_HTML = """\
<!doctype html><title>{{ mailbox }} — taxonomy</title>
<style>
  body { font: 14px/1.45 -apple-system, system-ui, sans-serif; margin: 1.5rem; max-width: 900px; }
  pre {
    background: #f8f8f8; padding: 12px; border-radius: 6px;
    white-space: pre-wrap; word-break: break-word; overflow-wrap: anywhere;
  }
  .path { color: #666; font-size: 0.85rem; }
</style>
""" + _DARK_MODE_CSS + _VERDICT_CSS + _NAV + """\
<h2>{{ mailbox }} — taxonomy</h2>
<p class="path">Source: <code>{{ path }}</code></p>
<p>Edit this file in your fork's <code>src/data/hierarchies/</code> and push to update. Cache invalidates on every feedback submission, so no restart needed once the file lands in the container.</p>
<pre>{{ data | tojson(indent=2) }}</pre>
"""


_THREADS_HTML = """\
<!doctype html><title>email-engine-v2 — threads</title>
<style>
  body { font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 1.5rem; }
  h1 { font-size: 1.2rem; margin: 0 0 1rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
  th { text-align: left; background: #fafafa; }
  /* .verdict styles live in _VERDICT_CSS (colored by leading digit). */
  .when { color: #777; font-size: 0.8rem; white-space: nowrap; }
  .subj { font-weight: 600; }
  .sender, .help { color: #555; font-size: 0.85rem; }
  .chip { display: inline-block; font-size: 0.7rem; padding: 1px 5px;
          border-radius: 8px; background: #fff3d4; color: #6b4d00; margin-left: 4px; }
  a.tlink { color: inherit; text-decoration: none; }
  a.tlink:hover { text-decoration: underline; }
  .preview { color: #666; font-size: 0.8rem; margin-top: 3px;
             max-width: 700px; line-height: 1.35;
             display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;
             overflow: hidden; }
  .conv-tail { color: #999; font-family: ui-monospace, monospace; font-size: 0.7rem; }
  .collapsed-chip { display: inline-block; margin-left: 8px;
                    font-size: 0.7rem; font-weight: 700; padding: 1px 7px;
                    border-radius: 999px; background: #ecf3ff; color: #2545a6;
                    border: 1px solid #b4c7f1; vertical-align: middle; cursor: help; }
</style>
""" + _DARK_MODE_CSS + _VERDICT_CSS + _NAV + """\
<h1>Threads {% if current_mailbox %}— {{ current_mailbox }}{% endif %}</h1>

<form method="get" style="margin-bottom: 1rem;">
  <label>Mailbox:
    <select name="mailbox" onchange="this.form.submit()">
      <option value="">(all)</option>
      {% for m in mailboxes %}<option value="{{ m }}" {% if m == current_mailbox %}selected{% endif %}>{{ m }}</option>{% endfor %}
    </select>
  </label>
  <label>Group by:
    <select name="group" onchange="this.form.submit()">
      <option value="date"    {% if group_by == 'date' %}selected{% endif %}>most-recent activity</option>
      <option value="verdict" {% if group_by == 'verdict' %}selected{% endif %}>current verdict</option>
    </select>
  </label>
  <label>View:
    <select name="compact" onchange="this.form.submit()">
      <option value="0" {% if not compact %}selected{% endif %}>all threads</option>
      <option value="1" {% if compact %}selected{% endif %}>compact (collapse same subject + sender)</option>
    </select>
  </label>
  <label>Show:
    <select name="limit" onchange="this.form.submit()">
      {% for n in [100, 200, 500, 1000] %}<option value="{{ n }}" {% if n == limit %}selected{% endif %}>{{ n }}</option>{% endfor %}
    </select>
  </label>
  <span class="help">
    {% if compact %}{{ rows|length }} row(s) (collapsed from {{ raw_count }} thread(s)){% else %}{{ rows|length }} thread(s) shown{% endif %}
  </span>
</form>

{% if group_counts %}
<div style="margin: 0 0 1rem; font-size: 0.85rem;">
  <span class="help">verdict mix:</span>
  {% for v, n in group_counts.items() | sort %}
    <span class="verdict {{ v | verdict_class }}" style="margin-right: 4px;">{{ v }} · {{ n }}</span>
  {% endfor %}
</div>
{% endif %}

<table>
  <thead><tr>
    <th>Last activity</th><th>Mailbox</th><th>Thread (latest)</th>
    <th>Current verdict</th><th># msgs</th><th>Verdict history</th>
  </tr></thead>
  <tbody>
    {% set ns = namespace(prev_v=None) %}
    {% for r in rows %}
      {% if group_by == 'verdict' and r.latest_verdict != ns.prev_v %}
        {% set ns.prev_v = r.latest_verdict %}
        <tr class="grouphdr">
          <td colspan="6">
            <span class="verdict {{ r.latest_verdict | verdict_class }}">{{ r.latest_verdict or '(unknown)' }}</span>
            <span class="group-count">{{ group_counts.get(r.latest_verdict or '(unknown)', 0) }} thread(s)</span>
          </td>
        </tr>
      {% endif %}
    <tr>
      <td class="when">{{ r.last_activity[:19].replace('T',' ') if r.last_activity else '' }}</td>
      <td>{{ r.mailbox }}</td>
      <td>
        <div class="subj">
          <a class="tlink" href="/threads/{{ r.conversation_id }}?mailbox={{ r.mailbox }}">{{ r.subject or '(no subject)' }}</a>
          {% if r.collapsed_count and r.collapsed_count > 1 %}
            <span class="collapsed-chip" title="Collapsed {{ r.collapsed_count }} threads with this exact subject + sender. Link opens the most recent.">× {{ r.collapsed_count }}</span>
          {% endif %}
        </div>
        <div class="sender">{{ r.latest_sender or '' }} <span class="conv-tail">· {{ r.conversation_id[-8:] }}</span></div>
        {% if r.latest_preview %}
          <div class="preview">{{ r.latest_preview[:140] }}{% if r.latest_preview|length > 140 %}…{% endif %}</div>
        {% endif %}
      </td>
      <td><span class="verdict {{ r.latest_verdict | verdict_class }}">{{ r.latest_verdict }}</span></td>
      <td>{{ r.msg_count }}</td>
      <td>
        {{ r.verdict_count or 0 }} verdict(s)
        {% if r.verdict_count and r.verdict_count > 1 %}<span class="chip">changed</span>{% endif %}
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
"""


_THREAD_DETAIL_HTML = """\
<!doctype html><title>thread {{ conversation_id[:12] }} — email-engine-v2</title>
<style>
  body { font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 1.5rem; max-width: 1100px; }
  h1, h2 { font-size: 1.1rem; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
  th { text-align: left; background: #fafafa; }
  /* .verdict styles live in _VERDICT_CSS (colored by leading digit). */
  .arrow { color: #888; }
  .when { color: #777; font-size: 0.8rem; white-space: nowrap; }
  .reason { color: #555; font-style: italic; font-size: 0.85rem;
            white-space: pre-wrap; word-break: break-word; }
  .err { color: #b00; font-size: 0.85rem; }
  code { background: #f0f0f4; padding: 1px 4px; border-radius: 3px; font-size: 0.8rem; }
  .changed { background: #fff8db; }
</style>
""" + _DARK_MODE_CSS + _VERDICT_CSS + _NAV + """\
<h2>Thread <code>{{ conversation_id[:24] }}…</code></h2>
<p class="help" style="color: #666; font-size: 0.85rem; margin-top: -8px;">Mailbox: {{ mailbox }}</p>

<h2>Verdict timeline ({{ history|length }} classification(s))</h2>
<table>
  <thead><tr><th>When (UTC)</th><th>Verdict</th><th>Trigger subject</th><th>Trigger sender</th><th>Thread size</th><th>Reason</th></tr></thead>
  <tbody>
    {% for h in history %}
    <tr {% if h.prev_verdict and h.prev_verdict != h.verdict_folder %}class="changed"{% endif %}>
      <td class="when">{{ h.decided_at[:19].replace('T',' ') }}</td>
      <td>
        {% if h.prev_verdict and h.prev_verdict != h.verdict_folder %}
          <span class="verdict {{ h.prev_verdict | verdict_class }}">{{ h.prev_verdict }}</span> <span class="arrow">→</span>
        {% endif %}
        <span class="verdict {{ h.verdict_folder | verdict_class }}">{{ h.verdict_folder }}</span>
      </td>
      <td>{{ (h.trigger_subject or '')[:80] }}</td>
      <td>{{ h.trigger_sender or '' }}</td>
      <td>{{ h.thread_size }}</td>
      <td class="reason">{{ (h.reason or h.model_raw or '')[:300] }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>

<h2>Messages in this thread ({{ decisions|length }})</h2>
<table>
  <thead><tr><th>When (UTC)</th><th>Sender</th><th>Subject</th><th>Verdict folder</th><th>Tag</th><th>Move</th><th>Apply error</th></tr></thead>
  <tbody>
    {% for d in decisions %}
    <tr>
      <td class="when">{{ d.created_at[:19].replace('T',' ') }}</td>
      <td>{{ d.sender }}</td>
      <td>{{ (d.subject or '(no subject)')[:80] }}</td>
      <td><span class="verdict {{ d.verdict_folder | verdict_class }}">{{ d.verdict_folder }}</span></td>
      <td>{% if d.tagged %}✓{% else %}—{% endif %}</td>
      <td>{% if d.moved %}✓{% else %}—{% endif %}</td>
      <td class="err">{{ d.apply_error or '' }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
"""


_CHANGES_HTML = """\
<!doctype html><title>email-engine-v2 — verdict changes</title>
<style>
  body { font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 1.5rem; }
  h1 { font-size: 1.2rem; margin: 0 0 1rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
  th { text-align: left; background: #fafafa; }
  /* .verdict styles live in _VERDICT_CSS (colored by leading digit). */
  .arrow { color: #888; font-weight: 700; }
  .when { color: #777; font-size: 0.8rem; white-space: nowrap; }
  .subj { font-weight: 600; }
  .sender, .help { color: #555; font-size: 0.85rem; }
  .reason { color: #555; font-style: italic; font-size: 0.85rem;
            max-width: 420px; white-space: pre-wrap; word-break: break-word; }
  a.tlink { color: inherit; text-decoration: none; }
  a.tlink:hover { text-decoration: underline; }
</style>
""" + _DARK_MODE_CSS + _VERDICT_CSS + _NAV + """\
<h1>Verdict changes {% if current_mailbox %}— {{ current_mailbox }}{% endif %}</h1>

<form method="get" style="margin-bottom: 1rem;">
  <label>Mailbox:
    <select name="mailbox" onchange="this.form.submit()">
      <option value="">(all)</option>
      {% for m in mailboxes %}<option value="{{ m }}" {% if m == current_mailbox %}selected{% endif %}>{{ m }}</option>{% endfor %}
    </select>
  </label>
  <label>Filter:
    <select name="changes_only" onchange="this.form.submit()">
      <option value="1" {% if only_changes %}selected{% endif %}>only verdict changes</option>
      <option value="0" {% if not only_changes %}selected{% endif %}>every classification (full audit)</option>
    </select>
  </label>
  <label>Show:
    <select name="limit" onchange="this.form.submit()">
      {% for n in [100, 200, 500, 1000] %}<option value="{{ n }}" {% if n == limit %}selected{% endif %}>{{ n }}</option>{% endfor %}
    </select>
  </label>
  <span class="help">{{ rows|length }} row(s)</span>
</form>

<table>
  <thead><tr>
    <th>When (UTC)</th><th>Mailbox</th><th>Thread (trigger)</th>
    <th>Verdict</th><th>Reason</th>
  </tr></thead>
  <tbody>
    {% for r in rows %}
    <tr>
      <td class="when">{{ r.decided_at[:19].replace('T',' ') }}</td>
      <td>{{ r.mailbox }}</td>
      <td>
        <div class="subj">
          <a class="tlink" href="/threads/{{ r.conversation_id }}?mailbox={{ r.mailbox }}">{{ (r.trigger_subject or '(no subject)')[:80] }}</a>
        </div>
        <div class="sender">{{ r.trigger_sender or '' }} · thread size: {{ r.thread_size }}</div>
      </td>
      <td>
        {% if r.prev_verdict %}
          <span class="verdict {{ r.prev_verdict | verdict_class }}">{{ r.prev_verdict }}</span>
          <span class="arrow">→</span>
        {% endif %}
        <span class="verdict {{ r.verdict_folder | verdict_class }}">{{ r.verdict_folder }}</span>
      </td>
      <td class="reason">{{ r.reason or r.model_raw or '' }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
"""


# --- Test classify (replay a real thread through the classifier) ----------

@app.get("/test-classify")
@_require_auth
def test_classify_view():
    """List multi-message threads the operator can replay through the
    classifier. Used to verify behavior (especially: 'is the JSON
    response actually coming back?') without waiting for new mail or
    burning a 7-day reclassify."""
    min_msgs = int(request.args.get("min", "10"))
    rows = store.list_long_threads(min_messages=min_msgs, limit=100)
    return render_template_string(
        _TEST_CLASSIFY_HTML,
        rows=rows,
        min_msgs=min_msgs,
    )


@app.post("/test-classify/run")
@_require_auth
def test_classify_run():
    """Dry-run classify a single existing thread end-to-end:
      1. Fetch the thread from the provider
      2. Look up any prior ThreadSummary
      3. Call classify() with the same prompt path the poller uses
      4. Show the RAW LLM output + parsed Verdict on the result page

    No DB writes (no decision row, no thread_verdict, no summary
    upsert) — pure observation. If 'persist' checkbox is set, the
    thread_summary IS written so you can confirm the write path works
    end-to-end."""
    from datetime import datetime as _dt, timezone as _tz
    from classifier import LLMConfig, classify
    from lib.storage import make_thread_key
    from providers import make_provider

    mailbox = (request.form.get("mailbox") or "").strip()
    conv_id = (request.form.get("conversation_id") or "").strip()
    persist = request.form.get("persist") == "1"
    if not mailbox or not conv_id:
        abort(400, "mailbox + conversation_id required")
    mb = store.get_mailbox(mailbox)
    if not mb:
        abort(404, "unknown mailbox")

    provider = make_provider(
        mb.mailbox, mb.provider,
        imap_server=mb.imap_server, imap_port=mb.imap_port,
    )

    try:
        thread = provider.get_thread(conv_id)
    except Exception as e:
        return Response(f"provider.get_thread failed: {e}",
                        status=502, mimetype="text/plain")
    if not thread:
        abort(404, "thread not found in provider (it may have been deleted or moved)")

    latest_msg = max(
        thread,
        key=lambda x: x.received_at or _dt.min.replace(tzinfo=_tz.utc),
    )
    thread_ctx = [
        {
            "sender": tm.from_address or tm.from_name or "(unknown)",
            "received": tm.received_at.isoformat() if tm.received_at else "",
            "body": (tm.body_text or "")[:1500],
        }
        for tm in thread
        if tm.id != latest_msg.id
    ]

    thread_key = make_thread_key(mb.provider, conv_id)
    prior_summary_dict = None
    prior_ts_row = store.get_thread_summary(mb.mailbox, thread_key) if thread_key else None
    if prior_ts_row:
        prior_summary_dict = {
            "summary":       prior_ts_row.summary,
            "key_facts":     prior_ts_row.key_facts,
            "timeline":      prior_ts_row.timeline,
            "contacts":      prior_ts_row.contacts,
            "message_count": prior_ts_row.message_count,
        }

    # Per-mailbox LLM override (matches what the poller does live).
    llm = LLMConfig.from_env()
    if mb.llm_model or mb.llm_api_key:
        llm = LLMConfig(
            base_url=llm.base_url,
            model=mb.llm_model or llm.model,
            api_key=mb.llm_api_key or llm.api_key,
        )

    started_at = _dt.now(_tz.utc)
    try:
        verdict = classify(
            mailbox=mb.mailbox,
            sender=latest_msg.from_address or latest_msg.from_name,
            subject=latest_msg.subject,
            body=latest_msg.body_text,
            thread=thread_ctx if prior_summary_dict is None else None,
            prior_summary=prior_summary_dict,
            message_id=latest_msg.id,
            received_at=latest_msg.received_at.isoformat() if latest_msg.received_at else None,
            cfg=llm,
        )
    except Exception as e:
        return Response(f"classify() raised: {e}\n\nFull traceback in poller logs.",
                        status=502, mimetype="text/plain")
    elapsed = (_dt.now(_tz.utc) - started_at).total_seconds()

    persisted = False
    if persist and thread_key:
        try:
            store.upsert_thread_summary(
                mailbox=mb.mailbox,
                thread_key=thread_key,
                summary=verdict.summary,
                key_facts=verdict.key_facts,
                timeline=verdict.timeline,
                contacts=verdict.contacts,
                last_message_id=latest_msg.id,
                last_message_at=(latest_msg.received_at.isoformat()
                                 if latest_msg.received_at else None),
                message_count=len(thread),
                status="errored" if verdict.parse_error else "fresh",
            )
            persisted = True
        except Exception as e:
            log.exception("test-classify persist failed: %s", e)

    return render_template_string(
        _TEST_RESULT_HTML,
        mailbox=mb.mailbox,
        thread_key=thread_key,
        conv_id=conv_id,
        thread_size=len(thread),
        latest_msg=latest_msg,
        used_prior_summary=prior_summary_dict is not None,
        prior_summary=prior_summary_dict,
        verdict=verdict,
        model_used=llm.model,
        elapsed_seconds=elapsed,
        persist=persist,
        persisted=persisted,
    )


# --- Feedback review + LLM taxonomy proposals -------------------------------

@app.get("/feedback-review")
@_require_auth
def feedback_review():
    """List feedback rows + any pending taxonomy proposals per mailbox.

    Per-user scoping: the page picks a "current user" from the
    ?user=... query param (overrides), the ee2_user cookie (default),
    or empty (= 'all users' pool). Feedback rows + proposal generation
    are filtered to that scope.

    The 'Generate proposal from MY feedback' button uses the current
    user; the 'Generate from ALL users' button is always available too
    so cross-pollination is one click away."""
    mailbox = request.args.get("mailbox") or None
    mb_obj = store.get_mailbox(mailbox) if mailbox else None
    mb_profile = mb_obj.profile if mb_obj else None
    # Default scope: cookie when present; shared mailboxes default
    # to pooled regardless (no per-user split makes sense for a
    # workflow mailbox where everyone triages collectively).
    requested_user = (request.args.get("user") or "").strip()
    if requested_user == "__all__":
        current_user = ""  # explicit "all users" view
    elif requested_user:
        current_user = requested_user
    elif mb_profile == "shared":
        current_user = ""
    else:
        current_user = _current_user()
    feedback = store.feedback_export(
        mailbox=mailbox,
        user_identifier=current_user or None,
    )
    feedback_users = store.list_feedback_users(mailbox=mailbox)
    proposals = store.list_taxonomy_proposals(mailbox=mailbox, limit=20)
    return render_template_string(
        _FEEDBACK_REVIEW_HTML,
        feedback=feedback,
        feedback_users=feedback_users,
        proposals=proposals,
        mailboxes=[m.mailbox for m in store.list_mailboxes()],
        current_mailbox=mailbox or "",
        current_user=current_user,
        mb_profile=mb_profile or "",
    )


@app.post("/feedback-review/<path:email>/propose")
@_require_auth
def feedback_propose(email: str):
    """Synchronous LLM call to generate a taxonomy proposal for one
    mailbox. Synchronous because proposals are infrequent (the user
    clicks once after accumulating feedback); a background job + status
    poller is overkill here. ~30s response time is fine for a button
    the user explicitly clicked.

    Form param `user_identifier`:
      - non-empty value → scope proposal to that user's feedback
      - empty / missing → pool all users' feedback
    The dashboard provides two buttons that POST the right value."""
    if not store.get_mailbox(email):
        abort(404, "unknown mailbox")
    from classifier import LLMConfig
    from taxonomy_review import generate_proposal
    user_id = (request.form.get("user_identifier") or "").strip() or None
    result = generate_proposal(email, store, LLMConfig.from_env(),
                               user_identifier=user_id)
    if not result.get("ok"):
        return Response(f"Proposal failed: {result.get('error')}",
                        status=400, mimetype="text/plain")
    return Response(status=303, headers={
        "Location": f"/feedback-review/proposal/{result['proposal_id']}",
    })


@app.get("/feedback-review/proposal/<proposal_id>")
@_require_auth
def feedback_proposal_view(proposal_id: str):
    p = store.get_taxonomy_proposal(proposal_id)
    if not p:
        abort(404, "proposal not found")
    return render_template_string(_PROPOSAL_DIFF_HTML, p=p)


@app.post("/feedback-review/proposal/<proposal_id>/apply")
@_require_auth
def feedback_proposal_apply(proposal_id: str):
    from taxonomy_review import apply_proposal
    result = apply_proposal(proposal_id, store)
    if not result.get("ok"):
        return Response(f"Apply failed: {result.get('error')}",
                        status=400, mimetype="text/plain")
    # Bust hierarchy + pipeline caches so the next classification picks
    # up the new taxonomy without a poller restart.
    invalidate_cache()
    return Response(status=303, headers={
        "Location": f"/feedback-review/proposal/{proposal_id}",
    })


@app.post("/feedback-review/proposal/<proposal_id>/discard")
@_require_auth
def feedback_proposal_discard(proposal_id: str):
    from taxonomy_review import discard_proposal
    discard_proposal(proposal_id, store)
    return Response(status=303, headers={"Location": "/feedback-review"})


_FEEDBACK_REVIEW_HTML = """\
<!doctype html><title>email-engine-v2 — feedback review</title>
<style>
  body { font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 1.5rem; max-width: 1100px; }
  h1, h2 { font-size: 1.15rem; margin: 0 0 12px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; font-size: 0.88rem; }
  th { text-align: left; background: #fafafa; }
  .when { color: #777; font-size: 0.78rem; white-space: nowrap; }
  .arrow { color: #888; }
  .right { color: #196b3a; font-weight: 600; }
  .wrong { color: #b32626; font-weight: 600; }
  .note  { color: #444; font-style: italic; max-width: 480px;
           white-space: pre-wrap; word-break: break-word; }
  .actions { background: #f0f4ff; border: 1px solid #b9c5ec; padding: 12px;
             border-radius: 6px; margin-bottom: 1.5rem; }
  .actions button { padding: 6px 14px; font-size: 0.9rem; }
  .help { color: #666; font-size: 0.85rem; }
  .prop-card { border: 1px solid #d6d6dc; border-radius: 6px;
               padding: 10px 14px; margin: 6px 0; font-size: 0.88rem; }
  .prop-card.applied   { background: #ecf8ef; border-color: #6dc488; }
  .prop-card.discarded { background: #fbeaea; border-color: #d68b8b; opacity: 0.7; }
  a { color: #4a5dd0; }
</style>
""" + _DARK_MODE_CSS + _VERDICT_CSS + _NAV + """\
<h1>Feedback review</h1>

<form method="get" style="margin-bottom: 1rem;">
  <label>Mailbox:
    <select name="mailbox" onchange="this.form.submit()">
      <option value="">(all)</option>
      {% for m in mailboxes %}<option value="{{ m }}" {% if m == current_mailbox %}selected{% endif %}>{{ m }}</option>{% endfor %}
    </select>
  </label>
  <label>Scope:
    <select name="user" onchange="this.form.submit()">
      <option value="__all__" {% if not current_user %}selected{% endif %}>all users (pooled)</option>
      {% for u in feedback_users %}
        <option value="{{ u.user_identifier }}" {% if u.user_identifier == current_user %}selected{% endif %}>{{ u.user_identifier }} · {{ u.n }} row(s)</option>
      {% endfor %}
    </select>
  </label>
  <span class="help">
    {% if mb_profile == 'shared' %}shared inbox → defaults to pooled
    {% elif mb_profile == 'personal' %}personal inbox → defaults to your cookie ({{ current_user or '(not set)' }})
    {% endif %}
  </span>
</form>

{% if current_mailbox %}
<div class="actions">
  <form method="post" action="/feedback-review/{{ current_mailbox }}/propose"
        onsubmit="this.querySelector('button').disabled = true; this.querySelector('button').textContent='Thinking… (~30s)'; return true;"
        style="display: inline">
    {% if current_user %}
      <input type="hidden" name="user_identifier" value="{{ current_user }}">
      <button type="submit">↻ Generate proposal from <strong>{{ current_user }}</strong>'s {{ feedback|length }} row(s)</button>
    {% else %}
      <button type="submit">↻ Generate proposal from ALL users' {{ feedback|length }} row(s) (pooled)</button>
    {% endif %}
  </form>
  {% if current_user %}
  <form method="post" action="/feedback-review/{{ current_mailbox }}/propose"
        onsubmit="this.querySelector('button').disabled = true; this.querySelector('button').textContent='Thinking… (~30s)'; return true;"
        style="display: inline; margin-left: 8px">
    <button type="submit" style="background: #eee">↻ Also generate pooled (cross-pollination)</button>
  </form>
  {% endif %}
  <div class="help" style="margin-top: 6px">
    LLM reads the current taxonomy + the feedback rows above and proposes a JSON revision. You review the diff before anything is applied.
  </div>
</div>
{% else %}
<div class="help" style="margin-bottom: 1rem;">Pick a mailbox above to enable the "generate proposal" action.</div>
{% endif %}

<h2>Recent taxonomy proposals ({{ proposals|length }})</h2>
{% if not proposals %}
<p class="help">No proposals yet.</p>
{% endif %}
{% for p in proposals %}
<div class="prop-card{% if p.applied_at %} applied{% elif p.discarded_at %} discarded{% endif %}">
  <div>
    <a href="/feedback-review/proposal/{{ p.id }}"><strong>{{ p.mailbox }}</strong> · proposal {{ p.id[:8] }}</a>
    <span class="when">{{ p.created_at[:19].replace('T',' ') }} UTC · based on {{ p.based_on_feedback_count }} feedback row(s)</span>
  </div>
  <div class="help">
    {% if p.applied_at %}✓ applied {{ p.applied_at[:19].replace('T',' ') }} UTC
    {% elif p.discarded_at %}✗ discarded {{ p.discarded_at[:19].replace('T',' ') }} UTC
    {% else %}pending review{% endif %}
  </div>
</div>
{% endfor %}

<h2>Feedback rows ({{ feedback|length }})</h2>
<table>
  <thead><tr>
    <th>When</th><th>Mailbox</th><th>User</th><th>Verdict</th><th>Subject</th>
    <th>Right/Wrong</th><th>Note</th>
  </tr></thead>
  <tbody>
  {% for f in feedback %}
    <tr>
      <td class="when">{{ f.created_at[:19].replace('T',' ') }}</td>
      <td>{{ f.mailbox }}</td>
      <td>{{ f.user_identifier or '(anonymous)' }}</td>
      <td>
        <span class="verdict {{ f.model_choice | verdict_class }}">{{ f.model_choice }}</span>
        {% if f.suggested and f.suggested != f.model_choice %}
          <span class="arrow">→</span>
          <span class="verdict {{ f.suggested | verdict_class }}">{{ f.suggested }}</span>
        {% endif %}
      </td>
      <td>{{ (f.subject or '(no subject)')[:60] }}</td>
      <td>{% if f.correct %}<span class="right">✓ correct</span>{% else %}<span class="wrong">✗ wrong</span>{% endif %}</td>
      <td class="note">{{ f.note or '' }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
"""


_PROPOSAL_DIFF_HTML = """\
<!doctype html><title>proposal {{ p.id[:8] }} — email-engine-v2</title>
<style>
  body { font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 1.5rem; max-width: 1100px; }
  h1, h2 { font-size: 1.1rem; }
  pre { background: #f5f5f8; padding: 10px 12px; border-radius: 6px;
        white-space: pre-wrap; word-break: break-word; font-size: 0.82rem;
        line-height: 1.4; max-height: 420px; overflow: auto; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .rationale { background: #fffaf0; border-left: 3px solid #d4a82a;
               padding: 10px 14px; margin: 12px 0;
               white-space: pre-wrap; word-break: break-word; }
  .actions { margin: 12px 0 24px; }
  .actions form { display: inline-block; margin-right: 8px; }
  .actions button { padding: 7px 18px; font-size: 0.92rem; }
  .actions button.apply   { background: #2bb24c; color: #fff; border: none; border-radius: 4px; }
  .actions button.discard { background: #d84545; color: #fff; border: none; border-radius: 4px; }
  .help { color: #666; font-size: 0.85rem; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
           font-size: 0.78rem; margin-left: 4px; }
  .badge.applied   { background: #d8f0de; color: #196b3a; }
  .badge.discarded { background: #fbe2e2; color: #b32626; }
</style>
""" + _DARK_MODE_CSS + _VERDICT_CSS + _NAV + """\
<h1>
  Taxonomy proposal — {{ p.mailbox }}
  {% if p.applied_at %}<span class="badge applied">applied {{ p.applied_at[:19] }} UTC</span>{% endif %}
  {% if p.discarded_at %}<span class="badge discarded">discarded {{ p.discarded_at[:19] }} UTC</span>{% endif %}
</h1>
<p class="help">Based on {{ p.based_on_feedback_count }} feedback row(s). Created {{ p.created_at[:19] }} UTC.</p>

{% if p.rationale %}
<h2>Rationale</h2>
<div class="rationale">{{ p.rationale }}</div>
{% endif %}

{% if not p.applied_at and not p.discarded_at %}
<div class="actions">
  <form method="post" action="/feedback-review/proposal/{{ p.id }}/apply"
        onsubmit="return confirm('Write this taxonomy to the persistent override path? The next classification cycle picks it up immediately.')">
    <button type="submit" class="apply">✓ Apply proposal</button>
  </form>
  <form method="post" action="/feedback-review/proposal/{{ p.id }}/discard">
    <button type="submit" class="discard">✗ Discard</button>
  </form>
  <span class="help">Apply writes to <code>/data/hierarchies/&lt;mailbox&gt;.json</code> (persistent volume).</span>
</div>
{% endif %}

<h2>Diff</h2>
<div class="cols">
  <div>
    <h3 style="font-size: 0.95rem;">Current</h3>
    <pre>{{ p.current_json }}</pre>
  </div>
  <div>
    <h3 style="font-size: 0.95rem;">Proposed</h3>
    <pre>{{ p.proposed_json }}</pre>
  </div>
</div>
"""


_TEST_CLASSIFY_HTML = """\
<!doctype html><title>test classify — email-engine-v2</title>
<style>
  body { font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 1.5rem; max-width: 1100px; }
  h1 { font-size: 1.2rem; margin: 0 0 1rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; font-size: 0.88rem; }
  th { text-align: left; background: #fafafa; }
  .help { color: #666; font-size: 0.85rem; }
  .when { color: #777; font-size: 0.8rem; white-space: nowrap; }
  .subj { font-weight: 600; }
  button { padding: 4px 10px; font-size: 0.85rem; cursor: pointer; }
  .test-btn { background: #5b6cff; color: #fff; border: none; border-radius: 3px; }
  .conv-tail { color: #999; font-family: ui-monospace, monospace; font-size: 0.75rem; }
  .preview-form { margin-top: 0; padding: 8px 12px; background: #fffaf0;
                  border-left: 3px solid #d4a82a; border-radius: 3px;
                  font-size: 0.9rem; margin-bottom: 1rem; }
  .preview-form label { margin-right: 12px; }
</style>
""" + _DARK_MODE_CSS + _VERDICT_CSS + _NAV + """\
<h1>Test classify</h1>
<p class="help">Pick a real thread from your connected mailbox history and replay it through the classifier <em>right now</em> — no waiting for new mail, no full reclassify. Pure observation by default (no DB writes); tick "write summary" to also land a real thread_summaries row.</p>

<form method="get" class="preview-form">
  <label>Minimum messages in thread:
    <input type="number" name="min" value="{{ min_msgs }}" min="2" max="500" style="width: 70px"
           onchange="this.form.submit()">
  </label>
  <span class="help">{{ rows|length }} thread(s) shown</span>
</form>

<table>
  <thead><tr>
    <th>Mailbox</th><th>Subject</th><th># msgs</th><th>Last activity</th><th></th>
  </tr></thead>
  <tbody>
  {% for r in rows %}
    <tr>
      <td>{{ r.mailbox }}</td>
      <td>
        <div class="subj">{{ (r.subject or '(no subject)')[:90] }}</div>
        <div class="conv-tail">{{ r.conversation_id[-12:] }}</div>
      </td>
      <td>{{ r.msg_count }}</td>
      <td class="when">{{ r.last_activity[:19].replace('T',' ') if r.last_activity else '' }}</td>
      <td>
        <form method="post" action="/test-classify/run" style="display:inline-flex; gap: 6px; align-items: center;">
          <input type="hidden" name="mailbox" value="{{ r.mailbox }}">
          <input type="hidden" name="conversation_id" value="{{ r.conversation_id }}">
          <label class="help" style="display:inline-flex; gap: 4px; align-items: center;">
            <input type="checkbox" name="persist" value="1"> write summary
          </label>
          <button type="submit" class="test-btn">↻ Test classify</button>
        </form>
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table>
"""


_TEST_RESULT_HTML = """\
<!doctype html><title>test result — email-engine-v2</title>
<style>
  body { font: 14px/1.45 -apple-system, system-ui, sans-serif; margin: 1.5rem; max-width: 1100px; }
  h1, h2 { font-size: 1.1rem; }
  pre { background: #f5f5f8; padding: 10px 12px; border-radius: 6px;
        white-space: pre-wrap; word-break: break-word; font-size: 0.85rem;
        line-height: 1.4; max-height: 480px; overflow: auto; }
  .meta { background: #f3f4f8; padding: 10px 14px; border-radius: 6px;
          margin-bottom: 18px; font-size: 0.9rem; }
  .meta dt { font-weight: 600; margin-top: 4px; }
  .meta dd { margin: 0 0 4px 0; color: #444; }
  .ok   { color: #196b3a; font-weight: 600; }
  .fail { color: #b32626; font-weight: 600; }
  .help { color: #666; font-size: 0.85rem; }
  table.kv { border-collapse: collapse; width: 100%; margin: 8px 0; }
  table.kv th, table.kv td { padding: 5px 8px; border-bottom: 1px solid #eee;
                              vertical-align: top; font-size: 0.85rem; text-align: left; }
  table.kv th { background: #fafafa; font-weight: 600; }
  .banner { padding: 10px 14px; border-radius: 6px; margin-bottom: 16px; font-weight: 600; }
  .banner.ok   { background: #e8f8ee; color: #196b3a; border-left: 4px solid #2bb24c; }
  .banner.fail { background: #fde0e0; color: #b32626; border-left: 4px solid #d84545; }
</style>
""" + _DARK_MODE_CSS + _VERDICT_CSS + _NAV + """\
<h1>Test classify result</h1>

{% if verdict.parse_error %}
<div class="banner fail">
  ✗ LLM did not return JSON. parse_error: <code>{{ verdict.parse_error }}</code><br>
  <span class="help" style="font-weight: 400;">→ The response_format=json_object fix is either not deployed yet, or the backend ignored it. Check raw output below.</span>
</div>
{% elif verdict.summary %}
<div class="banner ok">
  ✓ LLM returned valid JSON with a summary ({{ verdict.summary|length }} chars).
  This is the cost-saving strategy working as designed.
</div>
{% else %}
<div class="banner fail">
  ⚠ LLM returned JSON but the summary field was empty. Folder verdict still works; cost-saving doesn't kick in.
</div>
{% endif %}

<div class="meta">
  <dl>
    <dt>Mailbox</dt>           <dd>{{ mailbox }}</dd>
    <dt>Thread key</dt>        <dd><code>{{ thread_key }}</code></dd>
    <dt>Conversation id</dt>   <dd><code>{{ conv_id }}</code></dd>
    <dt>Thread size</dt>       <dd>{{ thread_size }} message(s) fetched from provider</dd>
    <dt>Latest message</dt>    <dd>{{ latest_msg.subject or '(no subject)' }} — from {{ latest_msg.from_address or latest_msg.from_name }}</dd>
    <dt>Prior summary used?</dt><dd>{% if used_prior_summary %}<span class="ok">YES</span> — cost-saving path active (full thread NOT re-sent){% else %}<span class="fail">NO</span> — first classification of this thread, full thread context sent{% endif %}</dd>
    <dt>Model</dt>             <dd><code>{{ model_used }}</code></dd>
    <dt>Elapsed</dt>           <dd>{{ '%.2f'|format(elapsed_seconds) }}s</dd>
    {% if persist %}
      <dt>Persisted to thread_summaries?</dt>
      <dd>{% if persisted %}<span class="ok">YES</span> — summary row written{% else %}<span class="fail">NO</span> — write failed (see logs){% endif %}</dd>
    {% else %}
      <dt>Persisted?</dt><dd>No — dry-run mode (no DB writes)</dd>
    {% endif %}
  </dl>
</div>

<h2>Parsed verdict</h2>
<table class="kv">
  <tr><th>folder</th><td><span class="verdict {{ verdict.folder | verdict_class }}">{{ verdict.folder }}</span></td></tr>
  <tr><th>summary</th><td>{{ verdict.summary or '(empty)' }}</td></tr>
  <tr><th>keyFacts ({{ verdict.key_facts|length }})</th><td>
    {% if verdict.key_facts %}
      <ul style="margin:0; padding-left: 18px;">
      {% for kf in verdict.key_facts %}
        <li><strong>{{ kf.label }}:</strong> {{ kf.value }}</li>
      {% endfor %}
      </ul>
    {% else %}<span class="help">(empty)</span>{% endif %}
  </td></tr>
  <tr><th>timeline ({{ verdict.timeline|length }})</th><td>
    {% if verdict.timeline %}
      <ul style="margin:0; padding-left: 18px;">
      {% for ev in verdict.timeline %}
        <li><code>{{ ev.date }}</code> — {{ ev.event }}</li>
      {% endfor %}
      </ul>
    {% else %}<span class="help">(empty)</span>{% endif %}
  </td></tr>
  <tr><th>contacts ({{ verdict.contacts|length }})</th><td>
    {% if verdict.contacts %}
      <ul style="margin:0; padding-left: 18px;">
      {% for c in verdict.contacts %}
        <li><strong>{{ c.name or '(unknown)' }}</strong>
          {% if c.email %}&lt;{{ c.email }}&gt;{% endif %}
          {% if c.role %} · {{ c.role }}{% endif %}
          {% if c.organization %} · {{ c.organization }}{% endif %}</li>
      {% endfor %}
      </ul>
    {% else %}<span class="help">(empty)</span>{% endif %}
  </td></tr>
</table>

<h2>Raw LLM output</h2>
<p class="help">Should start with <code>{</code> if the JSON-output fix is working. Plain folder names like <code>4-Medium</code> mean the LLM still isn't producing JSON.</p>
<pre>{{ verdict.raw }}</pre>

{% if prior_summary %}
<h2>Prior summary (what we fed the LLM)</h2>
<pre>{{ prior_summary | tojson(indent=2) }}</pre>
{% endif %}

<p><a href="/test-classify">← back to thread list</a></p>
"""


_FEEDBACK_FORM_HTML = """\
<!doctype html><meta charset="utf-8"><title>feedback — email-engine</title>
<style>
  body { font: 15px/1.5 -apple-system, system-ui, Segoe UI, sans-serif;
         margin: 0; padding: 0; background: #f6f7fb; color: #222; }
  .card { max-width: 580px; margin: 4rem auto; background: #fff;
          border-radius: 12px; padding: 28px 32px;
          box-shadow: 0 1px 3px rgba(0,0,0,.04), 0 8px 24px rgba(0,0,0,.06); }
  h1 { font-size: 1.15rem; margin: 0 0 18px; color: #333; }
  .meta { background: #f3f4f8; border-radius: 8px; padding: 10px 14px;
          margin-bottom: 20px; font-size: 0.9rem; color: #555; }
  .meta strong { color: #222; }
  label { display: block; margin: 14px 0 4px; font-weight: 600; color: #444;
          font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.4px; }
  select, textarea, input[type=text] {
    width: 100%; padding: 8px 10px; font-size: 0.95rem;
    border: 1px solid #d4d5dc; border-radius: 6px; box-sizing: border-box;
    font-family: inherit;
  }
  textarea { min-height: 110px; resize: vertical; }
  .row { display: flex; gap: 10px; align-items: center; margin: 8px 0; }
  .row label.inline { margin: 0; font-weight: 500; text-transform: none;
                      letter-spacing: 0; font-size: 0.95rem; color: #333;
                      display: inline-flex; align-items: center; gap: 8px; }
  button { margin-top: 18px; padding: 10px 22px; background: #5b6cff;
           color: #fff; border: none; border-radius: 6px;
           font-size: 0.95rem; font-weight: 600; cursor: pointer; }
  button:hover { background: #4456e8; }
  .help { color: #777; font-size: 0.82rem; margin-top: 4px; }
</style>
<body>
<div class="card">
  <h1>Was this classification wrong?</h1>
  <div class="meta">
    <div><strong>Subject:</strong> {{ decision.subject or '(no subject)' }}</div>
    <div><strong>From:</strong> {{ decision.sender or '(unknown)' }}</div>
    <div><strong>Classified as:</strong> {{ decision.verdict_folder }}</div>
  </div>
  <form method="post">
    <div class="row">
      <label class="inline"><input type="radio" name="correct" value="1" required> ✓ actually correct</label>
      <label class="inline"><input type="radio" name="correct" value="0" checked> ✗ wrong</label>
    </div>

    <label>What should it have been?</label>
    <select name="suggested">
      <option value="">(leave blank if it was correct)</option>
      {% for f in folders %}
        <option value="{{ f.id or f.name }}" {% if (f.id or f.name) == decision.verdict_folder %}disabled{% endif %}>{{ f.name }}</option>
      {% endfor %}
    </select>
    <div class="help">Required if you picked ✗ wrong.</div>

    <label>Why? (your reasoning helps the next taxonomy update)</label>
    <textarea name="note" placeholder="e.g. 'sender is internal; thread is about a renewal contract; should always be high-priority not medium'"></textarea>

    <label>Your email <span class="help" style="text-transform: none; letter-spacing: 0; font-weight: 400">(so your taxonomy reflects YOUR preferences)</span></label>
    <input type="text" name="user_identifier" value="{{ prefilled_user }}"
           placeholder="you@example.com">

    <button type="submit">Submit feedback</button>
  </form>
</div>
</body>
"""

_FEEDBACK_DONE_HTML = """\
<!doctype html><meta charset="utf-8"><title>{{ title }} — email-engine</title>
<style>
  body { font: 15px/1.5 -apple-system, system-ui, Segoe UI, sans-serif;
         margin: 0; padding: 0; background: #f6f7fb; color: #222; }
  .card { max-width: 480px; margin: 6rem auto; background: #fff;
          border-radius: 12px; padding: 28px 32px;
          box-shadow: 0 1px 3px rgba(0,0,0,.04), 0 8px 24px rgba(0,0,0,.06); }
  h1 { font-size: 1.1rem; margin: 0 0 12px; color: #333; }
  p  { color: #555; margin: 0; }
</style>
<body><div class="card"><h1>{{ title }}</h1><p>{{ body }}</p></div></body>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
