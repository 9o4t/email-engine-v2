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

def _sidebar_data(current_mailbox: str = "") -> dict:
    """Compute the sidebar payload (mailbox list + per-hour counts +
    pending-proposal count) every page needs. Single SQL pass per
    counter so /overview still renders in ~10ms on a multi-million-row
    decisions table."""
    mailboxes = store.list_mailboxes()
    counts: dict[str, int] = {}
    pending = 0
    try:
        with store._conn() as c:
            for r in c.execute(
                """SELECT mailbox, COUNT(*) AS n FROM decisions
                   WHERE created_at >= datetime('now', '-1 hours')
                   GROUP BY mailbox""").fetchall():
                counts[r["mailbox"]] = int(r["n"])
            pending = int(c.execute(
                """SELECT COUNT(*) AS n FROM taxonomy_proposals
                   WHERE applied_at IS NULL AND discarded_at IS NULL"""
            ).fetchone()["n"])
    except sqlite3.Error:
        pass
    total_hr = sum(counts.values())
    return {
        "mailboxes": mailboxes,
        "counts": counts,
        "total_hr": total_hr,
        "current": current_mailbox or "",
        "pending_proposals": pending,
    }


def _overview_data(mailbox: str | None = None) -> dict:
    """Aggregate the overview screen's stat cards, 24h sparkline, verdict
    mix, and recent decisions in a single helper. Per-hour bucketing
    uses SQLite's strftime so a 24h window is one query."""
    from datetime import datetime as _dt, timezone as _tz, timedelta
    now = _dt.now(_tz.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    mb_clause = ""
    args: list = []
    if mailbox:
        mb_clause = " AND mailbox = ?"
        args.append(mailbox)

    with store._conn() as c:
        # Classified today + yesterday (for delta)
        classified_today = int(c.execute(
            f"SELECT COUNT(*) AS n FROM decisions WHERE created_at >= ?{mb_clause}",
            (today_start.isoformat(), *args),
        ).fetchone()["n"])
        y_start = (today_start - timedelta(days=1)).isoformat()
        y_end = today_start.isoformat()
        classified_y = int(c.execute(
            f"SELECT COUNT(*) AS n FROM decisions WHERE created_at >= ? AND created_at < ?{mb_clause}",
            (y_start, y_end, *args),
        ).fetchone()["n"])

        # Apply errors in last 24h
        apply_errors = int(c.execute(
            f"""SELECT COUNT(*) AS n FROM decisions
                WHERE apply_error IS NOT NULL AND apply_error != ''
                  AND created_at >= datetime('now', '-24 hours'){mb_clause}""",
            tuple(args),
        ).fetchone()["n"])

        # Avg latency (seconds) over last 24h
        latency_row = c.execute(
            f"""SELECT AVG((julianday(created_at) - julianday(retrieved)) * 86400.0) AS s
                FROM decisions
                WHERE retrieved IS NOT NULL
                  AND created_at >= datetime('now', '-24 hours'){mb_clause}""",
            tuple(args),
        ).fetchone()
        avg_latency = float(latency_row["s"]) if latency_row and latency_row["s"] is not None else None

        # Per-hour 24h activity + verdict counts
        rows_24h = c.execute(
            f"""SELECT created_at, verdict_folder FROM decisions
                WHERE created_at >= datetime('now', '-24 hours'){mb_clause}""",
            tuple(args),
        ).fetchall()

    buckets = [0] * 24
    verdict_counts: dict[str, int] = {"1": 0, "2": 0, "3": 0, "4": 0, "5": 0}
    for r in rows_24h:
        try:
            ts = r["created_at"]
            if ts.endswith("Z"):
                ts = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            hours_ago = int((now - dt).total_seconds() // 3600)
            if 0 <= hours_ago < 24:
                buckets[23 - hours_ago] += 1
        except (ValueError, AttributeError):
            pass
        v = (r["verdict_folder"] or "")
        for ch in v:
            if ch.isdigit():
                if ch in verdict_counts:
                    verdict_counts[ch] += 1
                break

    # Mailbox active/total
    all_mb = store.list_mailboxes()
    active_n = sum(1 for m in all_mb if m.enabled)
    total_n = len(all_mb)

    # Delta vs. yesterday-by-this-time. Use full-day yesterday as baseline
    # to avoid noisy comparisons against very-early-morning windows.
    if classified_y > 0:
        delta_pct = ((classified_today - classified_y) / classified_y) * 100
    else:
        delta_pct = None

    recent = store.recent_decisions(mailbox=mailbox, limit=6)

    return {
        "classified_today": classified_today,
        "delta_pct": delta_pct,
        "apply_errors": apply_errors,
        "avg_latency": avg_latency,
        "active_n": active_n,
        "total_n": total_n,
        "paused_n": total_n - active_n,
        "activity_24h": buckets,
        "activity_24h_max": max(buckets) if buckets and max(buckets) > 0 else 1,
        "verdict_counts": verdict_counts,
        "verdict_total": sum(verdict_counts.values()),
        "recent": recent,
    }


def _dashboard_render(body_template: str, *, active_tab: str,
                      page_title: str = "email-engine v2",
                      current_mailbox: str = "",
                      **ctx) -> str:
    """Compose the shared sidebar shell + a per-page body template, then
    render. Every authenticated dashboard page goes through this; the
    public feedback landing pages render their own standalone HTML."""
    tpl = _SHELL_HEAD + body_template + _SHELL_FOOT
    return render_template_string(
        tpl,
        active_tab=active_tab,
        page_title=page_title,
        sidebar=_sidebar_data(current_mailbox),
        **ctx,
    )


@app.get("/")
@_require_auth
def index():
    """Overview screen — stat cards, 24h sparkline, verdict mix, and the
    six most-recent classifications. The decisions list moved to
    /decisions when this became the landing page."""
    mailbox = request.args.get("mailbox") or None
    data = _overview_data(mailbox)
    return _dashboard_render(
        _OVERVIEW_HTML,
        active_tab="overview",
        page_title="Overview",
        current_mailbox=mailbox or "",
        data=data,
        mailbox=mailbox or "",
    )


@app.get("/decisions")
@_require_auth
def decisions_view():
    """Full decisions list. This is what `/` used to render before the
    overview screen took the landing spot."""
    mailbox = request.args.get("mailbox") or None
    limit = int(request.args.get("limit", "100"))
    rows = store.recent_decisions(mailbox=mailbox, limit=limit)
    folders = list_folders(mailbox or "_default")
    return _dashboard_render(
        _DECISIONS_HTML,
        active_tab="decisions",
        page_title="Decisions",
        current_mailbox=mailbox or "",
        rows=rows,
        folders=folders,
        limit=limit,
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

    return _dashboard_render(
        _THREADS_HTML,
        active_tab="threads",
        page_title="Threads",
        current_mailbox=mailbox or "",
        rows=rows,
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
    return _dashboard_render(
        _THREAD_DETAIL_HTML,
        active_tab="threads",
        page_title="Thread",
        current_mailbox=mailbox,
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
    return _dashboard_render(
        _CHANGES_HTML,
        active_tab="changes",
        page_title="Changes",
        current_mailbox=mailbox or "",
        rows=rows,
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
    return _dashboard_render(
        _MAILBOXES_HTML,
        active_tab="mailboxes",
        page_title="Mailboxes",
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


# --- Sync Outlook Master Category List --------------------------------------

# In-memory cache of the most recent sync result per mailbox so the
# /mailboxes page can show "last sync: created 5, errors 0" inline.
_master_cats_last_sync: dict[str, dict] = {}


@app.post("/mailboxes/<path:email>/sync-categories")
@_require_auth
def mailboxes_sync_categories(email: str):
    """One-click force-sync of Outlook's Master Category List for one
    mailbox. Runs synchronously, captures created/existed/errors counts
    + actual error messages so a Graph permission failure is visible in
    the UI banner (instead of dying silently in poller logs the way the
    on-poll auto-sync does).

    Common failure mode this surfaces: Graph app permission is
    `Mail.ReadWrite` only — that's enough for set_categories on
    messages, but the master list itself requires
    `MailboxSettings.ReadWrite`. The 403 from masterCategories shows up
    in the result banner with the exact remediation."""
    from providers import make_provider
    from classifier import list_folders

    mb = store.get_mailbox(email)
    if not mb:
        abort(404, "unknown mailbox")
    if mb.provider != "graph":
        return Response(status=303, headers={
            "Location": "/mailboxes?msg=sync-categories-noop",
        })

    try:
        provider = make_provider(
            mb.mailbox, mb.provider,
            imap_server=mb.imap_server, imap_port=mb.imap_port,
        )
    except Exception as e:
        _master_cats_last_sync[email] = {
            "ok": False, "ran_at": _now_iso(),
            "created": 0, "existed": 0, "errors": 1,
            "error_messages": [f"provider construction failed: {e}"],
            "existing_names": [], "registered_names": [],
        }
        return Response(status=303, headers={
            "Location": "/mailboxes?msg=sync-categories-failed",
        })

    current_categories = [f["id"] or f["name"] for f in list_folders(mb.mailbox)]

    # Force re-sync: clear the per-process "already synced" cache so the
    # on-poll auto-sync also retries on its next cycle (in case the
    # operator just updated Graph app permissions in Azure).
    try:
        from poller import _MASTER_CATS_SYNCED
        _MASTER_CATS_SYNCED.discard(email)
    except Exception:
        pass

    result = provider.ensure_master_categories(current_categories)
    result["ran_at"] = _now_iso()
    result["ok"] = result.get("errors", 0) == 0
    _master_cats_last_sync[email] = result
    return Response(status=303, headers={
        "Location": "/mailboxes?msg=sync-categories-done",
    })


@app.get("/api/mailboxes/<path:email>/sync-categories/last")
@_require_auth
def mailboxes_sync_categories_last(email: str):
    """JSON read of the most recent sync result. 404 if no sync has
    been attempted in this process. Used by the per-card status JS."""
    r = _master_cats_last_sync.get(email)
    if not r:
        return jsonify({"error": "never_run", "mailbox": email}), 404
    return jsonify({"mailbox": email, **r})


# In-memory cache for the most recent search-folder sync per mailbox.
_search_folders_last_sync: dict[str, dict] = {}


@app.post("/mailboxes/<path:email>/sync-search-folders")
@_require_auth
def mailboxes_sync_search_folders(email: str):
    """Create Outlook search folders (one per verdict tag) for one
    mailbox. The search folders auto-list messages by category — much
    cleaner UX than relying on the master category list:
      - they appear in Outlook's folder tree directly
      - users click them like real folders
      - they auto-update as the engine tags new mail
      - no Master Category List dependency for filtering

    Runs synchronously, returns counts + error messages in the same
    shape as sync-categories so the UI plumbing matches."""
    from providers import make_provider
    from classifier import list_folders

    mb = store.get_mailbox(email)
    if not mb:
        abort(404, "unknown mailbox")
    if mb.provider != "graph":
        return Response(status=303, headers={
            "Location": "/mailboxes?msg=sync-search-folders-noop",
        })

    try:
        provider = make_provider(
            mb.mailbox, mb.provider,
            imap_server=mb.imap_server, imap_port=mb.imap_port,
        )
    except Exception as e:
        _search_folders_last_sync[email] = {
            "ok": False, "ran_at": _now_iso(),
            "created": 0, "existed": 0, "errors": 1,
            "error_messages": [f"provider construction failed: {e}"],
            "existing_names": [], "created_names": [],
        }
        return Response(status=303, headers={
            "Location": "/mailboxes?msg=sync-search-folders-failed",
        })

    current_categories = [f["id"] or f["name"] for f in list_folders(mb.mailbox)]
    result = provider.ensure_search_folders(current_categories)
    result["ran_at"] = _now_iso()
    result["ok"] = result.get("errors", 0) == 0
    _search_folders_last_sync[email] = result
    return Response(status=303, headers={
        "Location": "/mailboxes?msg=sync-search-folders-done",
    })


@app.get("/api/mailboxes/<path:email>/sync-search-folders/last")
@_require_auth
def mailboxes_sync_search_folders_last(email: str):
    """JSON read of the most recent search-folder sync. 404 if never
    run in this process. Used by the per-card status line JS."""
    r = _search_folders_last_sync.get(email)
    if not r:
        return jsonify({"error": "never_run", "mailbox": email}), 404
    return jsonify({"mailbox": email, **r})


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
    return _dashboard_render(
        _HIERARCHY_HTML,
        active_tab="mailboxes",
        page_title="Taxonomy",
        current_mailbox=email,
        mailbox=email,
        path=str(path),
        data=data,
    )


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
    return _dashboard_render(
        _TEST_CLASSIFY_HTML,
        active_tab="test",
        page_title="Test classify",
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

    return _dashboard_render(
        _TEST_RESULT_HTML,
        active_tab="test",
        page_title="Test result",
        current_mailbox=mb.mailbox,
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
    return _dashboard_render(
        _FEEDBACK_REVIEW_HTML,
        active_tab="feedback",
        page_title="Feedback",
        current_mailbox=mailbox or "",
        feedback=feedback,
        feedback_users=feedback_users,
        proposals=proposals,
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
    return _dashboard_render(_PROPOSAL_DIFF_HTML, active_tab="feedback", page_title="Proposal", current_mailbox=p.mailbox, p=p)


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



# --- Templates --------------------------------------------------------------
#
# All authenticated dashboard pages share a sidebar + main shell composed at
# render-time by `_dashboard_render()`. Each *_HTML below is the *body* that
# slots into <main class="main"> — no <html>, <head>, or <body> tags. The
# public feedback-landing pages (`_FEEDBACK_FORM_HTML`, `_FEEDBACK_DONE_HTML`)
# are standalone — they don't share the dashboard chrome.

# Design tokens from the cloud handoff (canopy-cool palette). Cool indigo
# dark theme; single 3px radius; single typeface (Outfit).
_TOKENS_CSS = """
:root {
  --bg:      oklch(0.155 0.014 265);
  --bg2:     oklch(0.190 0.014 265);
  --surf:    oklch(0.225 0.014 265);
  --surf2:   oklch(0.265 0.014 265);
  --bd:      oklch(0.310 0.014 265);
  --bd2:     oklch(0.380 0.014 265);
  --t1:      oklch(0.965 0.005 265);
  --t2:      oklch(0.780 0.012 265);
  --t3:      oklch(0.580 0.014 265);
  --ac:      oklch(0.72 0.17 268);
  --acFg:    oklch(0.16 0.02 265);
  --acSoft:  oklch(0.30 0.08 268);
  --ok:      oklch(0.78 0.13 152);
  --warn:    oklch(0.80 0.13 78);
  --err:     oklch(0.74 0.18 24);
  --v1-bg: oklch(0.55 0.21 25);    --v1-fg: oklch(0.98 0.005 25);
  --v2-bg: oklch(0.68 0.18 52);    --v2-fg: oklch(0.18 0.05 50);
  --v3-bg: oklch(0.52 0.18 292);   --v3-fg: oklch(0.98 0.005 290);
  --v4-bg: oklch(0.82 0.16 92);    --v4-fg: oklch(0.22 0.05 90);
  --v5-bg: oklch(0.62 0.14 152);   --v5-fg: oklch(0.16 0.04 160);
  --font-ui: "Outfit", system-ui, sans-serif;
  --r: 3px;
}
"""

_BASE_CSS = """
*, *::before, *::after { box-sizing: border-box; }
html, body { margin: 0; padding: 0; height: 100%; background: var(--bg); color: var(--t1);
             font-family: var(--font-ui); font-size: 13.5px; line-height: 1.5;
             letter-spacing: -0.005em; -webkit-font-smoothing: antialiased; }
a { color: var(--ac); text-decoration: none; }
a:hover { text-decoration: underline; }
::selection { background: oklch(0.4 0.15 268 / 0.4); }

.app { display: flex; height: 100vh; }

/* Sidebar */
.sidebar { width: 240px; background: var(--bg); border-right: 1px solid var(--bd);
           padding: 18px 14px; overflow: auto; flex-shrink: 0;
           display: flex; flex-direction: column; gap: 18px; }
.sidebar .brand { display: flex; align-items: center; gap: 10px; padding: 0 6px;
                  font-size: 15px; font-weight: 600; letter-spacing: -0.02em;
                  color: var(--t1); text-decoration: none; }
.sidebar .brand:hover { text-decoration: none; }
.sidebar .brand .logo { width: 28px; height: 28px; border-radius: 3px;
                        background: linear-gradient(135deg, oklch(0.78 0.16 268), oklch(0.62 0.18 250));
                        display: grid; place-items: center; color: oklch(0.98 0.005 265);
                        font-weight: 700; font-size: 14px;
                        box-shadow: 0 2px 8px oklch(0.6 0.17 268 / 0.35); }
.sidebar .brand-name { display: inline-flex; align-items: baseline; gap: 4px; }
.sidebar .brand-v { color: var(--t3); font-weight: 400; font-size: 12px; }

.sidebar .nav { display: flex; flex-direction: column; gap: 1px; }
.sidebar .nav-item { display: flex; align-items: center; gap: 10px; padding: 7px 10px;
                     border-radius: 3px; cursor: pointer; color: var(--t2);
                     font-size: 13.5px; text-decoration: none; }
.sidebar .nav-item:hover { background: var(--surf); color: var(--t1); text-decoration: none; }
.sidebar .nav-item.on { background: var(--surf); color: var(--t1); font-weight: 500; }
.sidebar .nav-item .ic { width: 16px; height: 16px; flex-shrink: 0; opacity: 0.7; }
.sidebar .nav-item.on .ic { opacity: 1; color: var(--ac); }
.sidebar .nav-item .count { margin-left: auto; font-size: 11px; color: var(--t3);
                            font-variant-numeric: tabular-nums; }
.sidebar .nav-item.on .count { color: var(--t2); }
.sidebar .nav-item .pill-count { margin-left: auto; background: var(--acSoft); color: var(--ac);
                                  padding: 1px 7px; border-radius: 3px; font-size: 10px;
                                  font-weight: 600; font-variant-numeric: tabular-nums; }

.sidebar .sec h6 { font-size: 11px; color: var(--t3); margin: 0 8px 6px;
                   text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; }
.sidebar .mb { display: flex; align-items: center; gap: 8px; padding: 6px 10px;
               border-radius: 3px; cursor: pointer; color: var(--t2); font-size: 12.5px;
               text-decoration: none; }
.sidebar .mb:hover { background: var(--surf); color: var(--t1); text-decoration: none; }
.sidebar .mb.on { background: var(--acSoft); color: var(--t1); }
.sidebar .mb.off { opacity: 0.55; }
.sidebar .mb .stat { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.sidebar .mb .stat.on { background: var(--ok); box-shadow: 0 0 0 2px oklch(0.78 0.12 152 / 0.15); }
.sidebar .mb .stat.off { background: var(--t3); }
.sidebar .mb .mb-email { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sidebar .mb .count { margin-left: auto; font-size: 11px; color: var(--t3);
                      font-variant-numeric: tabular-nums; }

.sidebar .sec-utility { display: flex; flex-direction: column; gap: 1px; }
.sidebar .util-link { display: block; padding: 5px 10px; border-radius: 3px;
                      font-size: 12px; color: var(--t3); text-decoration: none; }
.sidebar .util-link:hover { background: var(--surf); color: var(--t1); text-decoration: none; }

.sidebar .footer-side { margin-top: auto; padding: 10px 6px; color: var(--t3); font-size: 11px;
                        border-top: 1px solid var(--bd); }

/* Main */
.main { flex: 1; overflow: auto; min-width: 0; padding: 24px 32px 40px; background: var(--bg); }

/* Page header */
.ph { display: flex; align-items: baseline; gap: 14px; margin-bottom: 22px; flex-wrap: wrap; }
.ph h1 { font-size: 22px; font-weight: 600; letter-spacing: -0.025em; margin: 0; }
.ph .sub { color: var(--t3); font-size: 13px; }
.ph .actions { margin-left: auto; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.pill-live { display: inline-flex; align-items: center; gap: 7px; padding: 4px 10px;
             border-radius: 3px; background: oklch(0.25 0.05 152); color: var(--ok); font-size: 11.5px; }
.pill-live .pulse { width: 6px; height: 6px; border-radius: 50%; background: var(--ok);
                    animation: c-pulse 1.7s ease-in-out infinite; }
@keyframes c-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }

/* Buttons */
.btn { background: var(--bg2); border: 1px solid var(--bd); color: var(--t1);
       padding: 6px 12px; border-radius: 3px; font-size: 12.5px;
       font-family: inherit; cursor: pointer; display: inline-flex; align-items: center; gap: 6px;
       text-decoration: none; }
.btn:hover { background: var(--surf); border-color: var(--bd2); text-decoration: none; }
.btn.pri { background: var(--ac); color: var(--acFg); border-color: var(--ac); font-weight: 600; }
.btn.pri:hover { background: oklch(0.78 0.17 268); }
.btn.danger { background: oklch(0.3 0.13 22); color: oklch(0.92 0.08 22);
              border-color: oklch(0.4 0.14 22); }
.btn.danger:hover { background: oklch(0.35 0.14 22); }
.btn.sm { padding: 4px 9px; font-size: 11.5px; border-radius: 3px; }
.btn.ghost { background: transparent; }
.btn.err-color { color: var(--err); }
button.btn { font-family: inherit; }

/* Inputs */
input[type=text], input[type=number], input[type=password], select, textarea {
  background: var(--bg2); border: 1px solid var(--bd); color: var(--t1);
  padding: 6px 10px; border-radius: 3px; font-size: 12.5px; font-family: inherit;
}
input:focus, select:focus, textarea:focus { outline: none; border-color: var(--ac);
                                            box-shadow: 0 0 0 3px oklch(0.72 0.17 268 / 0.18); }

/* Verdict pill */
.vp { display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px;
      border-radius: 3px; font-size: 11.5px; font-weight: 600;
      line-height: 1.3; letter-spacing: 0.005em; font-family: inherit;
      white-space: nowrap; }
.vp.v1 { background: var(--v1-bg); color: var(--v1-fg); }
.vp.v2 { background: var(--v2-bg); color: var(--v2-fg); }
.vp.v3 { background: var(--v3-bg); color: var(--v3-fg); }
.vp.v4 { background: var(--v4-bg); color: var(--v4-fg); }
.vp.v5 { background: var(--v5-bg); color: var(--v5-fg); }
.vp.vu { background: var(--surf2); color: var(--t2); }

/* Stat cards */
.grid4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 18px; }
.card { background: var(--bg2); border: 1px solid var(--bd); border-radius: 3px;
        padding: 16px 18px; }
.card h6 { font-size: 12px; color: var(--t3); margin: 0 0 10px; font-weight: 500; }
.card .big { font-size: 28px; font-weight: 600; letter-spacing: -0.028em;
             font-variant-numeric: tabular-nums; }
.card .big .suffix { font-size: 14px; color: var(--t3); margin-left: 4px; font-weight: 500; }
.card .big.err { color: var(--err); }
.card .delta { font-size: 12px; color: var(--t3); margin-top: 6px;
               display: inline-flex; align-items: center; gap: 4px; }
.card .delta.up { color: var(--ok); }
.card .delta.down { color: var(--err); }
.card.big-card { padding: 20px 22px; }

/* Sparkline */
.spark { display: flex; align-items: flex-end; gap: 3px; height: 60px; }
.spark span { flex: 1; background: linear-gradient(to top, var(--ac), oklch(0.72 0.17 268 / 0.3));
              border-radius: 3px 3px 0 0; min-height: 2px; }
.spark-labels { display: flex; justify-content: space-between; color: var(--t3);
                font-size: 11px; margin-top: 8px; }

/* Verdict mix */
.vmix { display: flex; height: 14px; border-radius: 3px; overflow: hidden;
        margin: 10px 0 12px; background: var(--surf); }
.vmix span { display: block; }
.vmix-legend { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; }
.vmix-legend > div { display: flex; flex-direction: column; gap: 2px; }
.vmix-legend .top { display: flex; align-items: center; gap: 6px; color: var(--t2); font-size: 12px; }
.vmix-legend .num { font-size: 18px; font-weight: 600; letter-spacing: -0.02em;
                    font-variant-numeric: tabular-nums; }
.swatch { width: 9px; height: 9px; border-radius: 3px; }

/* Section label */
.section-label { color: var(--t3); font-size: 11.5px; text-transform: uppercase;
                 letter-spacing: 0.06em; margin: 0 0 12px; font-weight: 600;
                 display: flex; align-items: center; gap: 10px; }
.section-label::after { content: ""; flex: 1; height: 1px; background: var(--bd); }

/* Tables */
table { width: 100%; border-collapse: collapse; }
thead th { text-align: left; font-weight: 500; color: var(--t3); font-size: 11.5px;
           padding: 10px 14px; border-bottom: 1px solid var(--bd);
           background: oklch(0.21 0.014 265);
           text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; }
tbody td { padding: 13px 14px; border-bottom: 1px solid var(--bd); vertical-align: top; }
tbody tr { transition: background 100ms; }
tbody tr:hover td { background: oklch(0.205 0.014 265); }
tbody tr:last-child td { border-bottom: none; }
.when { color: var(--t3); font-size: 12px; white-space: nowrap; font-variant-numeric: tabular-nums; }
.subj { font-weight: 500; color: var(--t1); font-size: 13.5px; }
.from { color: var(--t3); font-size: 12px; margin-top: 2px; font-variant-numeric: tabular-nums; }
.err-line { color: var(--err); font-size: 12px; margin-top: 5px; }
.applybadge { display: inline-block; padding: 2px 8px; border-radius: 3px;
              background: var(--surf); color: var(--t2); font-size: 11px; }
.table-wrap { background: var(--bg2); border: 1px solid var(--bd); border-radius: 3px;
              overflow: hidden; }

/* Feedback pills */
.pill-right { background: oklch(0.3 0.1 152); color: oklch(0.88 0.13 152);
              border: 1px solid oklch(0.42 0.11 152); padding: 4px 10px;
              border-radius: 3px; font-size: 11.5px; cursor: pointer;
              font-family: inherit; }
.pill-wrong { background: oklch(0.30 0.13 22); color: oklch(0.88 0.13 22);
              border: 1px solid oklch(0.42 0.13 22); padding: 4px 10px;
              border-radius: 3px; font-size: 11.5px; cursor: pointer;
              font-family: inherit; }
.pill-row { display: flex; gap: 4px; flex-wrap: wrap; }

/* Mailbox cards */
.mb-grid { display: grid; grid-template-columns: 1fr; gap: 14px; }
.mbcard { background: var(--bg2); border: 1px solid var(--bd); border-radius: 3px;
          padding: 0; overflow: hidden; transition: border-color 100ms; }
.mbcard:hover { border-color: var(--bd2); }
.mbcard.disabled { opacity: 0.75; }
.mbcard .mhead { display: flex; align-items: center; gap: 12px; padding: 16px 20px;
                 border-bottom: 1px solid var(--bd); flex-wrap: wrap; }
.mbcard .avatar { width: 32px; height: 32px; border-radius: 3px;
                  display: grid; place-items: center; color: oklch(0.98 0.005 265);
                  font-weight: 600; font-size: 14px;
                  background: linear-gradient(135deg, oklch(0.72 0.17 268), oklch(0.55 0.17 250));
                  flex-shrink: 0; }
.mbcard.disabled .avatar { background: oklch(0.3 0.01 265); color: var(--t3); }
.mbcard .mhead .meta { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.mbcard .mhead .email { font-size: 14.5px; font-weight: 500; letter-spacing: -0.01em; }
.mbcard .mhead .sub { color: var(--t3); font-size: 12px; }
.mbcard .mhead .badges { display: inline-flex; gap: 6px; flex-wrap: wrap; margin-left: 4px; }
.mbcard .badge { font-size: 11px; padding: 2px 8px; border-radius: 3px;
                 background: var(--surf); color: var(--t2); }
.mbcard .badge.on { background: oklch(0.28 0.07 152); color: var(--ok); }
.mbcard .badge.off { background: oklch(0.3 0.05 22); color: oklch(0.85 0.1 22); }
.mbcard .mhead .actions { margin-left: auto; display: flex; gap: 6px; align-items: center; }

.mbcard .body-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0;
                     border-bottom: 1px solid var(--bd); }
.mbcard .field { padding: 12px 20px; border-right: 1px solid var(--bd);
                 border-bottom: 1px solid var(--bd); }
.mbcard .field:nth-child(even) { border-right: none; }
.mbcard .field:nth-last-child(-n+2) { border-bottom: none; }
.mbcard .field .k { color: var(--t3); font-size: 11.5px; margin-bottom: 4px;
                    text-transform: uppercase; letter-spacing: 0.05em; }
.mbcard .field .v { color: var(--t1); font-size: 13px; display: flex; align-items: center;
                    gap: 8px; flex-wrap: wrap; min-height: 22px;
                    font-variant-numeric: tabular-nums; }
.mbcard .field .v .muted { color: var(--t3); }
.mbcard .field details summary { cursor: pointer; list-style: none; }
.mbcard .field details summary::-webkit-details-marker { display: none; }
.mbcard .field details[open] summary { margin-bottom: 6px; }

/* Segmented control */
.seg { display: inline-flex; background: var(--bg); border: 1px solid var(--bd);
       border-radius: 3px; padding: 2px; gap: 0; }
.seg button { background: transparent; border: none; color: var(--t2);
              padding: 4px 12px; border-radius: 3px; font-size: 11.5px;
              cursor: pointer; font-family: inherit; }
.seg button:hover { color: var(--t1); }
.seg button.on { background: var(--ac); color: var(--acFg); font-weight: 600; }
.seg form { display: inline; }

/* Toolbar row on mailbox cards */
.toolbar-row { display: flex; gap: 8px; padding: 14px 20px; flex-wrap: wrap;
               background: oklch(0.18 0.014 265); align-items: center; }
.toolbar-row form { display: inline-flex; gap: 6px; align-items: center; }
.toolbar-row .spacer { flex: 1; }
.toolbar-row details summary { cursor: pointer; list-style: none; }
.toolbar-row details summary::-webkit-details-marker { display: none; }
.toolbar-row details[open] { width: 100%; }
.toolbar-row details[open] .details-body { margin-top: 10px; padding: 10px 12px;
  background: var(--bg2); border: 1px solid var(--bd); border-radius: 3px;
  display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }

/* Reclassify live card */
.reclass { padding: 14px 20px; background: oklch(0.22 0.08 268);
           border-top: 1px solid oklch(0.34 0.10 268); display: none; }
.reclass.show { display: block; }
.reclass .top { display: flex; align-items: center; gap: 10px; }
.reclass .top .lbl { font-weight: 600; color: var(--ac); font-size: 12.5px; }
.reclass .top .pct { margin-left: auto; font-variant-numeric: tabular-nums;
                     font-size: 12px; color: var(--t1); font-weight: 600; }
.reclass .bar { height: 5px; background: oklch(0.2 0.05 268); border-radius: 3px;
                margin: 10px 0; overflow: hidden; }
.reclass .bar span { display: block; height: 100%; background: var(--ac);
                     border-radius: 3px; transition: width 600ms ease; width: 0; }
.reclass .meta { display: flex; gap: 18px; font-size: 12px; color: var(--t2); flex-wrap: wrap; }
.reclass .meta b { color: var(--t1); font-weight: 500; }
.reclass.err { background: oklch(0.22 0.08 22); border-top-color: oklch(0.34 0.10 22); }
.reclass.err .top .lbl { color: var(--err); }
.reclass.done .top .lbl { color: var(--ok); }

/* Sweep status line */
.sweep-status { padding: 10px 20px; font-size: 12px; color: var(--t2);
                background: oklch(0.18 0.014 265); border-top: 1px solid var(--bd);
                display: none; }
.sweep-status.show { display: block; }

/* Feedback split */
.feed-split { display: grid; grid-template-columns: 1.3fr 1fr; gap: 16px; }
.proposal { background: var(--bg2); border: 1px solid var(--bd); border-radius: 3px;
            padding: 16px 18px; margin-bottom: 12px; }
.proposal.pending { border-left: 3px solid var(--ac);
                    background: linear-gradient(to right, oklch(0.22 0.06 268), var(--bg2) 35%); }
.proposal.applied { border-left: 3px solid var(--ok); }
.proposal.discarded { opacity: 0.6; }
.proposal h5 { font-size: 13.5px; font-weight: 600; margin: 0; color: var(--t1); }
.proposal .meta { color: var(--t3); font-size: 12px; margin-top: 4px; }
.proposal .rat { color: var(--t2); font-size: 13px; margin: 10px 0; line-height: 1.6; }
.proposal .pa { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }

/* Misc utilities */
.banner { padding: 10px 14px; border-radius: 3px; font-size: 13px;
          margin-bottom: 16px; border: 1px solid var(--bd); background: var(--bg2); }
.banner.ok { background: oklch(0.25 0.05 152); border-color: oklch(0.35 0.08 152);
             color: var(--ok); }
.banner.err { background: oklch(0.25 0.07 22); border-color: oklch(0.35 0.1 22);
              color: var(--err); }
.banner.info { background: oklch(0.22 0.06 268); border-color: oklch(0.32 0.08 268);
               color: var(--t1); }
code, .mono { font-family: var(--font-ui); font-variant-numeric: tabular-nums; }
code { background: var(--surf); padding: 1px 5px; border-radius: 3px; font-size: 12px; }
pre { background: var(--bg); border: 1px solid var(--bd); padding: 12px 14px;
      border-radius: 3px; overflow: auto; font-size: 12px; line-height: 1.5;
      font-family: var(--font-ui); white-space: pre-wrap; word-break: break-word; }
.help { color: var(--t3); font-size: 12px; }
.note-block { color: var(--t2); font-size: 12.5px; font-style: italic; margin-top: 6px;
              padding-left: 10px; border-left: 2px solid var(--bd2); }
.arrow { color: var(--t3); }
.changed-row td { background: oklch(0.22 0.06 268 / 0.4); }
hr.divider { border: none; border-top: 1px solid var(--bd); margin: 24px 0; }

/* Inline form rows */
.row-inline { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.row-inline label { color: var(--t3); font-size: 12px; }

/* Add mailbox panel */
.add-panel { background: var(--bg2); border: 1px solid var(--bd); border-radius: 3px;
             padding: 18px 22px; margin-top: 24px; }
.add-panel h3 { margin: 0 0 14px; font-size: 15px; font-weight: 600; letter-spacing: -0.01em; }
.add-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 12px 16px; margin-bottom: 14px; }
.add-grid .add-field label { display: block; color: var(--t3); font-size: 11.5px;
                              text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; }
.add-grid .add-field input, .add-grid .add-field select { width: 100%; }

/* k-v metadata block (test-classify result, etc.) */
table.kv th { background: oklch(0.21 0.014 265); color: var(--t3);
              font-weight: 500; text-align: left; width: 180px; padding: 10px 14px;
              text-transform: uppercase; font-size: 11.5px; letter-spacing: 0.05em; }
table.kv td { padding: 10px 14px; border-bottom: 1px solid var(--bd); }

/* Banner severity for test classify */
.banner-big { padding: 14px 18px; font-size: 14px; }

/* Decisions filter row */
.filter-input { width: 240px; }
"""


# Composed inline-style block injected into every page's <head>. (kept as
# one string so the `<style>...</style>` tags only appear once.)
_INLINE_STYLE = "<style>\n" + _TOKENS_CSS + "\n" + _BASE_CSS + "\n</style>"


_SHELL_HEAD = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ page_title }} · email-engine v2</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
""" + _INLINE_STYLE + """
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <a class="brand" href="/">
      <span class="logo">E</span>
      <span class="brand-name">email-engine<span class="brand-v">v2</span></span>
    </a>
    <nav class="nav">
      <a class="nav-item {% if active_tab=='overview' %}on{% endif %}" href="/">
        <svg class="ic" viewBox="0 0 20 20" fill="currentColor"><path d="M3 13h2v-3H3v3zm4 0h2V7H7v6zm4 0h2v-9h-2v9zm4 0h2v-5h-2v5z"/></svg>
        <span>Overview</span>
      </a>
      <a class="nav-item {% if active_tab=='decisions' %}on{% endif %}" href="/decisions">
        <svg class="ic" viewBox="0 0 20 20" fill="currentColor"><path d="M3 5h14v2H3V5zm0 4h14v2H3V9zm0 4h10v2H3v-2z"/></svg>
        <span>Decisions</span>
      </a>
      <a class="nav-item {% if active_tab=='mailboxes' %}on{% endif %}" href="/mailboxes">
        <svg class="ic" viewBox="0 0 20 20" fill="currentColor"><path d="M3 5h14v10H3V5zm1 1v8h12V6H4zm6 1l5 4h-10l5-4z"/></svg>
        <span>Mailboxes</span>
        <span class="count">{{ sidebar.mailboxes|length }}</span>
      </a>
      <a class="nav-item {% if active_tab=='feedback' %}on{% endif %}" href="/feedback-review">
        <svg class="ic" viewBox="0 0 20 20" fill="currentColor"><path d="M4 4h12v9H7l-3 3V4zm2 2v6.2l1.4-1.2H14V6H6z"/></svg>
        <span>Feedback</span>
        {% if sidebar.pending_proposals %}<span class="pill-count">{{ sidebar.pending_proposals }}</span>{% endif %}
      </a>
      <a class="nav-item {% if active_tab=='threads' %}on{% endif %}" href="/threads">
        <svg class="ic" viewBox="0 0 20 20" fill="currentColor"><path d="M3 4h14v3H3V4zm0 5h14v3H3V9zm0 5h10v3H3v-3z"/></svg>
        <span>Threads</span>
      </a>
      <a class="nav-item {% if active_tab=='changes' %}on{% endif %}" href="/changes">
        <svg class="ic" viewBox="0 0 20 20" fill="currentColor"><path d="M5 3l4 4H6v8H4V7H1l4-4zm10 14l-4-4h3V5h2v8h3l-4 4z"/></svg>
        <span>Changes</span>
      </a>
      <a class="nav-item {% if active_tab=='test' %}on{% endif %}" href="/test-classify">
        <svg class="ic" viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a3 3 0 013 3v4a3 3 0 11-6 0V5a3 3 0 013-3zm-6 13a6 6 0 1112 0v3H4v-3z"/></svg>
        <span>Test classify</span>
      </a>
    </nav>
    <div class="sec">
      <h6>Mailboxes</h6>
      <div class="nav">
        <a class="mb {% if not sidebar.current %}on{% endif %}" href="/?mailbox=">
          <span class="stat on"></span>
          <span class="mb-email">all mailboxes</span>
          <span class="count">{{ sidebar.total_hr }}/h</span>
        </a>
        {% for m in sidebar.mailboxes %}
        <a class="mb {% if sidebar.current == m.mailbox %}on{% endif %}{% if not m.enabled %} off{% endif %}"
           href="/?mailbox={{ m.mailbox }}">
          <span class="stat {% if m.enabled %}on{% else %}off{% endif %}"></span>
          <span class="mb-email">{{ m.mailbox }}</span>
          {% if m.enabled %}<span class="count">{{ sidebar.counts.get(m.mailbox, 0) }}/h</span>{% endif %}
        </a>
        {% endfor %}
      </div>
    </div>
    <div class="sec sec-utility">
      <h6>Tools</h6>
      <a class="util-link" href="/admin/db.sqlite">Download DB</a>
      <a class="util-link" href="/api/feedback.csv">Feedback CSV</a>
      <a class="util-link" href="/api/decisions.csv">Decisions CSV</a>
    </div>
    <div class="footer-side">email-engine v2 · dark by default</div>
  </aside>
  <main class="main">
"""

_SHELL_FOOT = """\
  </main>
</div>
</body>
</html>
"""


# --- Overview screen --------------------------------------------------------

_OVERVIEW_HTML = """\
<div class="ph">
  <h1>Overview</h1>
  <span class="sub">{{ mailbox or 'all mailboxes' }} · last 24h</span>
  <div class="actions">
    <span class="pill-live"><span class="pulse"></span>polling live</span>
    <a class="btn" href="/api/decisions.csv{% if mailbox %}?mailbox={{ mailbox }}{% endif %}">Export</a>
  </div>
</div>

<div class="grid4">
  <div class="card">
    <h6>Classified today</h6>
    <div class="big">{{ data.classified_today }}</div>
    {% if data.delta_pct is not none %}
      <div class="delta {% if data.delta_pct >= 0 %}up{% else %}down{% endif %}">
        {% if data.delta_pct >= 0 %}↑{% else %}↓{% endif %} {{ '%.0f'|format(data.delta_pct|abs) }}% vs. yesterday
      </div>
    {% else %}
      <div class="delta">no baseline yet</div>
    {% endif %}
  </div>
  <div class="card">
    <h6>Avg latency</h6>
    <div class="big">
      {% if data.avg_latency is not none %}{{ '%.1f'|format(data.avg_latency) }}<span class="suffix">s</span>{% else %}—{% endif %}
    </div>
    <div class="delta">poll → applied</div>
  </div>
  <div class="card">
    <h6>Apply errors</h6>
    <div class="big {% if data.apply_errors %}err{% endif %}">{{ data.apply_errors }}</div>
    <div class="delta {% if data.apply_errors %}down{% endif %}">last 24h</div>
  </div>
  <div class="card">
    <h6>Active mailboxes</h6>
    <div class="big">{{ data.active_n }}<span class="suffix">/ {{ data.total_n }}</span></div>
    <div class="delta">{% if data.paused_n %}{{ data.paused_n }} paused{% else %}all active{% endif %}</div>
  </div>
</div>

<div style="display:grid; grid-template-columns: 1.3fr 1fr; gap: 14px; margin-bottom: 18px;">
  <div class="card big-card">
    <h6>Activity · last 24h</h6>
    <div class="spark">
      {% for v in data.activity_24h %}
        <span style="height: {{ ((v / data.activity_24h_max) * 100)|round(0) }}%"></span>
      {% endfor %}
    </div>
    <div class="spark-labels"><span>24h ago</span><span>12h</span><span>now</span></div>
  </div>

  <div class="card big-card">
    <h6>Verdict mix · last 24h</h6>
    <div class="vmix">
      {% set total = data.verdict_total if data.verdict_total > 0 else 1 %}
      {% for digit, label, color in [('1','P1','var(--v1-bg)'), ('2','P2','var(--v2-bg)'), ('3','P3','var(--v3-bg)'), ('4','P4','var(--v4-bg)'), ('5','P5','var(--v5-bg)')] %}
        {% set n = data.verdict_counts.get(digit, 0) %}
        {% if n > 0 %}<span style="width: {{ (n / total * 100) }}%; background: {{ color }};"></span>{% endif %}
      {% endfor %}
    </div>
    <div class="vmix-legend">
      {% for digit, label, color in [('1','P1','var(--v1-bg)'), ('2','P2','var(--v2-bg)'), ('3','P3','var(--v3-bg)'), ('4','P4','var(--v4-bg)'), ('5','P5','var(--v5-bg)')] %}
        <div>
          <div class="top"><span class="swatch" style="background: {{ color }}"></span>{{ label }}</div>
          <div class="num">{{ data.verdict_counts.get(digit, 0) }}</div>
        </div>
      {% endfor %}
    </div>
  </div>
</div>

<div class="section-label">Recent decisions</div>
<div class="table-wrap">
  <table>
    <tbody>
      {% for d in data.recent %}
      <tr>
        <td class="when" style="width: 90px">{{ d.created_at[11:19] }}</td>
        <td>
          <div class="subj">{{ (d.subject or '(no subject)')[:80] }}</div>
          <div class="from">{{ d.sender or '' }} · {{ d.mailbox }}</div>
        </td>
        <td style="width: 160px; text-align: right">
          <span class="vp {{ d.verdict_folder | verdict_class }}">{{ d.verdict_folder }}</span>
        </td>
      </tr>
      {% else %}
      <tr><td style="text-align: center; padding: 32px; color: var(--t3);">No classifications yet.</td></tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<div style="margin-top: 14px;">
  <a class="btn" href="/decisions{% if mailbox %}?mailbox={{ mailbox }}{% endif %}">View all decisions →</a>
</div>
"""


# --- Decisions screen -------------------------------------------------------

_DECISIONS_HTML = """\
<div class="ph">
  <h1>Decisions</h1>
  <span class="sub">{{ rows|length }} most recent{% if current_mailbox %} · {{ current_mailbox }}{% endif %}</span>
  <div class="actions">
    <form method="get" style="display:inline-flex; gap: 8px; align-items: center;">
      <input type="text" name="q" placeholder="Filter…" class="filter-input"
             oninput="filterRows(this.value)">
      <select name="mailbox" onchange="this.form.submit()">
        <option value="">All mailboxes</option>
        {% for m in sidebar.mailboxes %}
          <option value="{{ m.mailbox }}" {% if m.mailbox == current_mailbox %}selected{% endif %}>{{ m.mailbox }}</option>
        {% endfor %}
      </select>
    </form>
    <a class="btn" href="/api/decisions.csv{% if current_mailbox %}?mailbox={{ current_mailbox }}{% endif %}">Export</a>
  </div>
</div>

<div class="table-wrap">
  <table id="decisions-table">
    <thead>
      <tr>
        <th style="width: 90px">When</th>
        <th>Email</th>
        <th style="width: 160px">Verdict</th>
        <th style="width: 140px">Apply</th>
        <th style="width: 280px">Feedback</th>
      </tr>
    </thead>
    <tbody>
      {% for d in rows %}
      <tr data-search="{{ ((d.subject or '') ~ ' ' ~ (d.sender or '') ~ ' ' ~ d.mailbox ~ ' ' ~ (d.verdict_folder or ''))|lower }}">
        <td class="when">{{ d.created_at[:19].replace('T',' ') }}</td>
        <td>
          <div class="subj">{{ d.subject or '(no subject)' }}</div>
          <div class="from">{{ d.sender or '' }} · {{ d.mailbox }}</div>
          {% if d.apply_error %}<div class="err-line">↻ {{ d.apply_error[:120] }}</div>{% endif %}
        </td>
        <td><span class="vp {{ d.verdict_folder | verdict_class }}">{{ d.verdict_folder }}</span></td>
        <td>
          <span class="applybadge">{{ d.apply_mode or '?' }}</span>
          <div class="from" style="margin-top: 4px;">
            {% if d.tagged %}✓ tagged{% endif %}{% if d.tagged and d.moved %} · {% endif %}{% if d.moved %}✓ moved{% endif %}
            {% if not d.tagged and not d.moved %}—{% endif %}
          </div>
        </td>
        <td>
          <div class="pill-row">
            <form method="post" action="/feedback" style="display: inline">
              <input type="hidden" name="decision_id" value="{{ d.id }}">
              <input type="hidden" name="correct" value="1">
              <button class="pill-right" type="submit">✓ right</button>
            </form>
            <form method="post" action="/feedback" style="display: inline-flex; gap: 4px; align-items: center;">
              <input type="hidden" name="decision_id" value="{{ d.id }}">
              <input type="hidden" name="correct" value="0">
              <select name="suggested" required style="font-size: 11.5px; padding: 3px 6px;">
                <option value="" disabled selected>move to…</option>
                {% for f in folders %}
                  <option value="{{ f.id or f.name }}">{{ f.name }}</option>
                {% endfor %}
              </select>
              <button class="pill-wrong" type="submit">✗ wrong</button>
            </form>
          </div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<script>
function filterRows(q) {
  q = (q || '').toLowerCase().trim();
  var rows = document.querySelectorAll('#decisions-table tbody tr');
  rows.forEach(function(r){
    var s = r.getAttribute('data-search') || '';
    r.style.display = (!q || s.indexOf(q) !== -1) ? '' : 'none';
  });
}
</script>
"""


# --- Mailboxes screen -------------------------------------------------------

_MAILBOXES_HTML = """\
<div class="ph">
  <h1>Mailboxes</h1>
  {% set active_n = mailboxes|selectattr('enabled')|list|length %}
  {% set paused_n = mailboxes|rejectattr('enabled')|list|length %}
  <span class="sub">{{ active_n }} active · {{ paused_n }} paused</span>
  <div class="actions">
    <form method="post" action="/mailboxes/pause-all" style="display:inline"
          onsubmit="return confirm('Pause ALL mailboxes? Polling stops everywhere next cycle. Use for runaway LLM cost.')">
      <button type="submit" class="btn danger" title="Panic button">⏸ Pause all</button>
    </form>
    <form method="post" action="/mailboxes/resume-all" style="display:inline"
          onsubmit="return confirm('Resume ALL mailboxes?')">
      <button type="submit" class="btn">▶ Resume all</button>
    </form>
    <a class="btn pri" href="#add-mailbox">+ Add mailbox</a>
  </div>
</div>

{% if request.args.get('msg') == 'reclassify-started' %}
  <div class="banner ok">Reclassify started — walks INBOX plus every legacy …-X folder. Watch the live card below or the <a href="/decisions">decisions</a> list.</div>
{% elif request.args.get('msg') == 'already-running' %}
  <div class="banner">A reclassify is already in flight for that mailbox — second click ignored.</div>
{% elif request.args.get('msg') == 'sweep-started' %}
  <div class="banner ok">Sweep started — moving messages to Inbox in a background thread.</div>
{% elif request.args.get('msg') == 'sweep-already-running' %}
  <div class="banner">A sweep is already in flight — second click ignored.</div>
{% elif request.args.get('msg') == 'paused' %}
  <div class="banner">Mailbox paused. Polling stops on the next cycle (≤30s).</div>
{% elif request.args.get('msg') == 'resumed' %}
  <div class="banner ok">Mailbox resumed.</div>
{% elif request.args.get('msg') == 'paused-all' %}
  <div class="banner">Paused {{ request.args.get('n', '?') }} mailbox(es). All polling stops next cycle.</div>
{% elif request.args.get('msg') == 'resumed-all' %}
  <div class="banner ok">Resumed {{ request.args.get('n', '?') }} mailbox(es).</div>
{% elif request.args.get('msg') == 'sync-categories-done' %}
  <div class="banner ok">Category sync attempted. See per-mailbox status below for created / existed / errors counts.</div>
{% elif request.args.get('msg') == 'sync-categories-failed' %}
  <div class="banner">Category sync failed before it could call Graph. See per-mailbox status below.</div>
{% elif request.args.get('msg') == 'sync-categories-noop' %}
  <div class="banner">Sync skipped — only Graph (Microsoft 365) mailboxes have a Master Category List.</div>
{% elif request.args.get('msg') == 'sync-search-folders-done' %}
  <div class="banner ok">Search folders attempted. See per-mailbox status below — once successful, refresh Outlook and look under "Search Folders" in the folder tree.</div>
{% elif request.args.get('msg') == 'sync-search-folders-failed' %}
  <div class="banner">Search folder creation failed before it could call Graph. See per-mailbox status below.</div>
{% elif request.args.get('msg') == 'sync-search-folders-noop' %}
  <div class="banner">Sync skipped — search folders only apply to Graph (Microsoft 365) mailboxes.</div>
{% endif %}

{% set active_mbs = mailboxes|selectattr('enabled')|list %}
{% set paused_mbs = mailboxes|rejectattr('enabled')|list %}

{% macro mbcard(m) %}
  <div class="mbcard {% if not m.enabled %}disabled{% endif %}" id="mb-{{ m.mailbox }}">
    <div class="mhead">
      <div class="avatar">{{ m.mailbox[0]|upper }}</div>
      <div class="meta">
        <span class="email">{{ m.mailbox }}</span>
        <div class="sub">
          {% if m.notes %}{{ m.notes }}
          {% elif m.provider == 'graph' %}Microsoft Graph mailbox
          {% else %}IMAP mailbox{% endif %}
        </div>
      </div>
      <div class="badges">
        <span class="badge">{{ m.provider }}</span>
        <span class="badge">{{ m.profile }}</span>
        <span class="badge {% if m.enabled %}on{% else %}off{% endif %}">● {% if m.enabled %}active{% else %}paused{% endif %}</span>
      </div>
      <div class="actions">
        {% if m.enabled %}
        <form method="post" action="/mailboxes/{{ m.mailbox }}/pause" style="display:inline"
              onsubmit="return confirm('Pause {{ m.mailbox }}? Polling stops next cycle; config preserved.')">
          <button type="submit" class="btn sm">⏸ Pause</button>
        </form>
        {% else %}
        <form method="post" action="/mailboxes/{{ m.mailbox }}/resume" style="display:inline">
          <button type="submit" class="btn sm pri">▶ Resume</button>
        </form>
        {% endif %}
        <a class="btn sm ghost" href="/hierarchies/{{ m.mailbox }}" title="View taxonomy">⋯</a>
      </div>
    </div>

    <div class="body-grid">
      <div class="field">
        <div class="k">Apply mode</div>
        <div class="v">
          <form method="post" action="/mailboxes/{{ m.mailbox }}" class="seg">
            <button name="apply_mode" value="tag" class="{% if m.apply_mode=='tag' %}on{% endif %}">tag</button>
            <button name="apply_mode" value="move" class="{% if m.apply_mode=='move' %}on{% endif %}">move</button>
            <button name="apply_mode" value="tag_and_move" class="{% if m.apply_mode=='tag_and_move' %}on{% endif %}">both</button>
          </form>
        </div>
      </div>
      <div class="field">
        <div class="k">Profile</div>
        <div class="v">
          <form method="post" action="/mailboxes/{{ m.mailbox }}" class="seg">
            <button name="profile" value="personal" class="{% if m.profile=='personal' %}on{% endif %}">personal</button>
            <button name="profile" value="shared" class="{% if m.profile=='shared' %}on{% endif %}">shared</button>
          </form>
        </div>
      </div>
      <div class="field">
        <div class="k">Model</div>
        <div class="v">
          <details>
            <summary>
              {% if m.llm_model %}{{ m.llm_model }}{% else %}<span class="muted">env default ({{ env_model }})</span>{% endif %}
              <span style="margin-left: 8px; color: var(--t3); font-size: 11.5px;">edit ▸</span>
            </summary>
            <form method="post" action="/mailboxes/{{ m.mailbox }}" style="display:flex; gap: 6px; margin-top: 6px;">
              <input type="text" name="llm_model" value="{{ m.llm_model or '' }}" placeholder="{{ env_model }}" style="flex:1; min-width: 0;">
              <button type="submit" class="btn sm pri">Save</button>
            </form>
          </details>
        </div>
      </div>
      <div class="field">
        <div class="k">API key</div>
        <div class="v">
          <details>
            <summary>
              {% if m.llm_api_key %}<span style="color: var(--ok)">● set</span>
              <span class="muted">{{ m.llm_api_key | api_key_mask }}</span>
              {% else %}<span class="muted">uses env $LLM_API_KEY</span>{% endif %}
              <span style="margin-left: 8px; color: var(--t3); font-size: 11.5px;">replace ▸</span>
            </summary>
            <form method="post" action="/mailboxes/{{ m.mailbox }}" style="display:flex; flex-direction: column; gap: 6px; margin-top: 6px;">
              <input type="password" name="llm_api_key" placeholder="paste new key…" autocomplete="off">
              <label class="help" style="display:inline-flex; gap: 4px; align-items: center; font-size: 11.5px;">
                <input type="checkbox" name="clear_api_key" value="1"> clear → use env default
              </label>
              <button type="submit" class="btn sm pri" style="align-self: flex-start;">Save</button>
            </form>
          </details>
        </div>
      </div>
      {% if m.provider == 'imap' %}
      <div class="field">
        <div class="k">IMAP server</div>
        <div class="v">{{ m.imap_server }}:{{ m.imap_port }}</div>
      </div>
      {% else %}
      <div class="field">
        <div class="k">Connection</div>
        <div class="v"><span class="muted">Token broker (n8n) → Graph v1.0</span></div>
      </div>
      {% endif %}
      <div class="field">
        <div class="k">Poll interval</div>
        <div class="v">
          <details>
            <summary>{{ m.poll_interval }}s <span style="margin-left: 8px; color: var(--t3); font-size: 11.5px;">edit ▸</span></summary>
            <form method="post" action="/mailboxes/{{ m.mailbox }}" style="display:flex; gap: 6px; margin-top: 6px;">
              <input type="number" name="poll_interval" value="{{ m.poll_interval }}" min="5" max="3600" style="width: 100px;">
              <button type="submit" class="btn sm pri">Save</button>
            </form>
          </details>
        </div>
      </div>
    </div>

    <div class="toolbar-row">
      <details>
        {# `class="btn sm"` is applied to <summary> directly. Nesting a
           <button> inside <summary> is invalid HTML — Chromium-based
           browsers (Edge, recent Chrome) capture the click on the inner
           button and the details element never toggles, hiding the day-
           range picker entirely. The CSS above already strips the
           default disclosure marker so styling the summary as a button
           is the canonical fix. Same pattern applied to "Sweep" below. #}
        <summary class="btn sm">↻ Reclassify…</summary>
        <div class="details-body">
          <form method="post" action="/mailboxes/{{ m.mailbox }}/reclassify"
                onsubmit="return confirm('Reclassify {{ m.mailbox }}? ' + (this.days_back.value ? 'Last ' + this.days_back.value + ' day(s)' : 'ALL history') + '.')">
            <span class="help">last</span>
            <input type="number" name="days_back" min="1" max="3650" placeholder="all" style="width: 80px;">
            <span class="help">day(s)</span>
            {% for d in [7, 14, 30, 90] %}
              <button type="button" class="btn sm" onclick="this.form.days_back.value={{ d }}">{{ d }}d</button>
            {% endfor %}
            <button type="button" class="btn sm" onclick="this.form.days_back.value=''">all</button>
            <button type="submit" class="btn sm pri">↻ Go</button>
          </form>
        </div>
      </details>
      <a class="btn sm" href="/hierarchies/{{ m.mailbox }}">View taxonomy</a>
      {% if m.provider == 'graph' %}
      <form method="post" action="/mailboxes/{{ m.mailbox }}/sync-search-folders" style="display:inline">
        <button type="submit" class="btn sm"
                title="Create one Outlook search folder per verdict tag (1-Critical … 5-Low-Ignore). Each folder auto-lists messages tagged with that category — appears in Outlook's folder tree, no Master Category List dependency. Idempotent.">
          ⊞ Create search folders
        </button>
      </form>
      <form method="post" action="/mailboxes/{{ m.mailbox }}/sync-categories" style="display:inline">
        <button type="submit" class="btn sm"
                title="Register the verdict tags in Outlook's Master Category List with colors. Optional polish — gives the category pills colors in the message list. Search folders are the main filtering affordance.">
          ⊕ Sync categories
        </button>
      </form>
      {% endif %}
      <details>
        <summary class="btn sm">Sweep folder → Inbox</summary>
        <div class="details-body">
          <form method="post" action="/mailboxes/{{ m.mailbox }}/sweep-to-inbox"
                onsubmit="return confirm('Move every message in &quot;' + this.from_folder.value + '&quot; to Inbox?')">
            <span class="help">from</span>
            <input type="text" name="from_folder" placeholder="e.g. _inbox" required style="width: 200px;">
            <button type="submit" class="btn sm pri">Sweep</button>
          </form>
        </div>
      </details>
      <a class="btn sm" href="/decisions?mailbox={{ m.mailbox }}">Recent decisions</a>
      <div class="spacer"></div>
      <form method="post" action="/mailboxes/{{ m.mailbox }}/delete" style="display:inline"
            onsubmit="return confirm('Remove this mailbox? Decisions stay, polling stops.')">
        <button type="submit" class="btn sm ghost err-color">Remove mailbox</button>
      </form>
    </div>

    <div class="sweep-status" id="sweep-status-{{ m.mailbox }}"></div>
    <div class="sweep-status" id="sync-folders-status-{{ m.mailbox }}" style="margin-top: 4px;"></div>
    <div class="sweep-status" id="sync-cats-status-{{ m.mailbox }}" style="margin-top: 4px;"></div>

    <div class="reclass" id="reclass-{{ m.mailbox }}">
      <div class="top">
        <span class="lbl" id="reclass-lbl-{{ m.mailbox }}">↻ Reclassifying…</span>
        <span class="pct" id="reclass-pct-{{ m.mailbox }}">0%</span>
      </div>
      <div class="bar"><span id="reclass-bar-{{ m.mailbox }}"></span></div>
      <div class="meta">
        <span><b id="reclass-threads-{{ m.mailbox }}">0</b> threads classified</span>
        <span>folder <b id="reclass-folders-{{ m.mailbox }}">0/0</b></span>
        <span id="reclass-curfolder-{{ m.mailbox }}">starting…</span>
      </div>
      <div class="meta" id="reclass-diag-{{ m.mailbox }}" style="opacity: 0.8;">
        <span><b id="reclass-walked-{{ m.mailbox }}">0</b> walked</span>
        <span><b id="reclass-skipold-{{ m.mailbox }}">0</b> skipped (older than window)</span>
        <span><b id="reclass-skipdedup-{{ m.mailbox }}">0</b> skipped (dedup)</span>
        <span><b id="reclass-errors-{{ m.mailbox }}">0</b> errors</span>
        <span>oldest seen: <b id="reclass-oldest-{{ m.mailbox }}">—</b></span>
      </div>
      <div class="meta" id="reclass-hint-{{ m.mailbox }}" style="display:none; color: var(--warn, #d4a154); font-size: 11.5px;"></div>
    </div>
  </div>
{% endmacro %}

{% if active_mbs %}
<div class="section-label">Active</div>
<div class="mb-grid">
  {% for m in active_mbs %}{{ mbcard(m) }}{% endfor %}
</div>
{% endif %}

{% if paused_mbs %}
<div class="section-label" style="margin-top: 28px;">Paused</div>
<div class="mb-grid">
  {% for m in paused_mbs %}{{ mbcard(m) }}{% endfor %}
</div>
{% endif %}

<div class="add-panel" id="add-mailbox">
  <h3>Add a mailbox</h3>
  <form method="post" action="/mailboxes">
    <div class="add-grid">
      <div class="add-field"><label>Email</label><input type="text" name="mailbox" required placeholder="dave@9o4t.com"></div>
      <div class="add-field"><label>Provider</label>
        <select name="provider">
          <option value="graph">graph (Microsoft 365)</option>
          <option value="imap">imap (Gmail / Workspace)</option>
        </select>
      </div>
      <div class="add-field"><label>Apply mode</label>
        <select name="apply_mode">
          {% for am in apply_modes %}<option value="{{ am }}">{{ am }}</option>{% endfor %}
        </select>
      </div>
      <div class="add-field"><label>Profile</label>
        <select name="profile">
          {% for pr in profiles %}<option value="{{ pr }}">{{ pr }}</option>{% endfor %}
        </select>
      </div>
      <div class="add-field"><label>Model (optional)</label>
        <input type="text" name="llm_model" placeholder="{{ env_model }}"></div>
      <div class="add-field"><label>API key (optional)</label>
        <input type="password" name="llm_api_key" placeholder="(blank = env default)" autocomplete="off"></div>
      <div class="add-field"><label>IMAP server</label>
        <input type="text" name="imap_server" value="imap.gmail.com"></div>
      <div class="add-field"><label>IMAP port</label>
        <input type="number" name="imap_port" value="993"></div>
      <div class="add-field"><label>Poll interval (s)</label>
        <input type="number" name="poll_interval" value="30"></div>
      <div class="add-field" style="grid-column: span 2;"><label>Notes</label>
        <input type="text" name="notes" placeholder="optional"></div>
    </div>
    <button type="submit" class="btn pri">Add mailbox</button>
    <span class="help" style="margin-left: 12px;">
      For graph: token broker required (CALENDAR_URL + B2B_TOKEN env). For imap: set IMAP_&lt;SANITIZED&gt;_PASSWORD secret.
    </span>
  </form>
</div>

<script>
(function () {
  var mailboxes = {{ mailboxes | map(attribute='mailbox') | list | tojson }};

  function set(id, txt) { var el = document.getElementById(id); if (el) el.textContent = txt; }

  function renderReclass(mb, s) {
    var card = document.getElementById('reclass-' + mb);
    if (!card) return;
    if (!s || (!s.running && !s.progress && !s.error && !s.finished_at)) {
      card.classList.remove('show', 'err', 'done');
      return;
    }
    card.classList.add('show');
    card.classList.remove('err', 'done');
    var lbl = document.getElementById('reclass-lbl-' + mb);
    var p = s.progress || {};
    var pct = (p.folders_total && p.folders_total > 0)
              ? Math.min(100, (p.folders_walked / p.folders_total) * 100) : 0;
    if (s.running) {
      lbl.textContent = '↻ Reclassifying' + (s.days_back ? ' — last ' + s.days_back + ' days' : ' — all history');
    } else if (s.error) {
      card.classList.add('err');
      lbl.textContent = '✗ Reclassify failed: ' + (s.error || '').slice(0, 80);
    } else {
      card.classList.add('done');
      lbl.textContent = '✓ Reclassify complete';
      pct = 100;
    }
    set('reclass-pct-' + mb, Math.round(pct) + '%');
    // Diagnostics — surface what the walker actually saw so a "0 threads
    // classified" result is no longer a black box. The hint banner below
    // tells the user *why* it was 0 (cutoff vs errors vs empty folders).
    set('reclass-walked-' + mb,    String(p.messages_walked        || 0));
    set('reclass-skipold-' + mb,   String(p.messages_skipped_old   || 0));
    set('reclass-skipdedup-' + mb, String(p.messages_skipped_dedup || 0));
    set('reclass-errors-' + mb,    String(p.errors                 || 0));
    set('reclass-oldest-' + mb,    p.cursor_received_at ? p.cursor_received_at.slice(0, 19).replace('T', ' ') + 'Z' : '—');
    var hint = document.getElementById('reclass-hint-' + mb);
    if (hint && !s.running) {
      var msg = '';
      if ((p.errors || 0) > 0 && (p.threads_classified || 0) === 0) {
        msg = 'Every folder errored before any classification ran — check Railway logs for [reclassify] exceptions.';
      } else if ((p.threads_classified || 0) === 0 && (p.messages_walked || 0) === 0) {
        msg = 'No messages walked. INBOX + legacy folders are empty (or none exist on this mailbox).';
      } else if ((p.threads_classified || 0) === 0
                 && (p.messages_skipped_old || 0) > 0
                 && s.days_back) {
        msg = 'Every message inspected was older than the ' + s.days_back + '-day window — try a wider range (or "all") if you want to reprocess older mail.';
      } else if ((p.threads_classified || 0) === 0 && (p.messages_skipped_dedup || 0) > 0) {
        msg = 'Every conversation was already covered by another folder — nothing new to classify.';
      }
      if (msg) { hint.textContent = msg; hint.style.display = ''; }
      else     { hint.textContent = ''; hint.style.display = 'none'; }
    }
    var bar = document.getElementById('reclass-bar-' + mb);
    if (bar) bar.style.width = pct + '%';
    set('reclass-threads-' + mb, String(p.threads_classified || 0));
    set('reclass-folders-' + mb, (p.folders_walked || 0) + '/' + (p.folders_total || 0));
    set('reclass-curfolder-' + mb, p.current_folder || (s.running ? 'starting…' : ''));
  }

  function fmtSweep(s) {
    if (!s) return '';
    var src = s.from_folder ? '"' + s.from_folder + '" → Inbox' : '';
    var p = s.progress || {};
    if (s.running) return '… sweeping ' + src + ': moved ' + (p.moved || 0) + ', errors ' + (p.errors || 0);
    if (s.error)   return '✗ sweep ' + src + ' error: ' + s.error;
    if (p.done)    return '✓ sweep ' + src + ' done: moved ' + (p.moved || 0) + ', errors ' + (p.errors || 0);
    return '';
  }

  function renderSweep(mb, s) {
    var el = document.getElementById('sweep-status-' + mb);
    if (!el) return;
    var txt = fmtSweep(s);
    if (txt) { el.textContent = txt; el.classList.add('show'); }
    else     { el.textContent = ''; el.classList.remove('show'); }
  }

  function fmtSyncCats(s) {
    if (!s || s.error === 'never_run') return '';
    var when = s.ran_at ? s.ran_at.slice(11, 19) : '';
    var existing = (s.existing_names && s.existing_names.length)
      ? ' · ' + s.existing_names.length + ' pre-existing in Outlook'
      : '';
    if (s.errors && s.errors > 0) {
      var errs = (s.error_messages || []).join(' · ');
      return '✗ category sync (' + when + ') errors=' + s.errors + ' — ' + errs;
    }
    var regs = (s.registered_names || []);
    var regsStr = regs.length ? ' (new: ' + regs.join(', ') + ')' : '';
    return '✓ category sync (' + when + '): created=' + (s.created||0) + ', existed=' + (s.existed||0) + regsStr + existing;
  }

  function renderSyncCats(mb, s) {
    var el = document.getElementById('sync-cats-status-' + mb);
    if (!el) return;
    var txt = fmtSyncCats(s);
    if (txt) {
      el.textContent = txt;
      el.style.color = (s && s.errors > 0) ? '#b32626' : '#196b3a';
      el.classList.add('show');
    } else {
      el.textContent = '';
      el.classList.remove('show');
    }
  }

  function fmtSyncFolders(s) {
    if (!s || s.error === 'never_run') return '';
    var when = s.ran_at ? s.ran_at.slice(11, 19) : '';
    var existing = (s.existing_names && s.existing_names.length)
      ? ' · ' + s.existing_names.length + ' pre-existing search folders'
      : '';
    if (s.errors && s.errors > 0) {
      var errs = (s.error_messages || []).join(' · ');
      return '✗ search folders (' + when + ') errors=' + s.errors + ' — ' + errs;
    }
    var crts = (s.created_names || []);
    var ups  = (s.updated_names || []);
    var crtsStr = crts.length ? ' (new: ' + crts.join(', ') + ')' : '';
    var upsStr  = ups.length  ? ' (patched: ' + ups.join(', ')  + ')' : '';
    return '✓ search folders (' + when + '): created=' + (s.created||0) +
           ', updated=' + (s.updated||0) + ', existed=' + (s.existed||0) +
           crtsStr + upsStr + existing;
  }

  function renderSyncFolders(mb, s) {
    var el = document.getElementById('sync-folders-status-' + mb);
    if (!el) return;
    var txt = fmtSyncFolders(s);
    if (txt) {
      el.textContent = txt;
      el.style.color = (s && s.errors > 0) ? '#b32626' : '#196b3a';
      el.classList.add('show');
    } else {
      el.textContent = '';
      el.classList.remove('show');
    }
  }

  var pollMs = 8000;
  function tick() {
    var anyRunning = false;
    var pending = mailboxes.length * 4;
    if (!pending) { setTimeout(tick, pollMs); return; }
    mailboxes.forEach(function(mb) {
      fetch('/api/reclassify/' + encodeURIComponent(mb) + '/status')
        .then(function(r){ return r.ok ? r.json() : null; })
        .then(function(j){ renderReclass(mb, j); if (j && j.running) anyRunning = true; })
        .catch(function(){})
        .finally(function(){ if (--pending === 0) { pollMs = anyRunning ? 2000 : 8000; setTimeout(tick, pollMs); } });
      fetch('/api/sweep/' + encodeURIComponent(mb) + '/status')
        .then(function(r){ return r.ok ? r.json() : null; })
        .then(function(j){ renderSweep(mb, j); if (j && j.running) anyRunning = true; })
        .catch(function(){})
        .finally(function(){ if (--pending === 0) { pollMs = anyRunning ? 2000 : 8000; setTimeout(tick, pollMs); } });
      // 404 here is normal (sync never attempted in this process).
      fetch('/api/mailboxes/' + encodeURIComponent(mb) + '/sync-categories/last')
        .then(function(r){ return r.ok ? r.json() : null; })
        .then(function(j){ if (j) renderSyncCats(mb, j); })
        .catch(function(){})
        .finally(function(){ if (--pending === 0) { pollMs = anyRunning ? 2000 : 8000; setTimeout(tick, pollMs); } });
      fetch('/api/mailboxes/' + encodeURIComponent(mb) + '/sync-search-folders/last')
        .then(function(r){ return r.ok ? r.json() : null; })
        .then(function(j){ if (j) renderSyncFolders(mb, j); })
        .catch(function(){})
        .finally(function(){ if (--pending === 0) { pollMs = anyRunning ? 2000 : 8000; setTimeout(tick, pollMs); } });
    });
  }
  tick();
})();
</script>
"""


# --- Threads screen ---------------------------------------------------------

_THREADS_HTML = """\
<div class="ph">
  <h1>Threads</h1>
  <span class="sub">
    {% if compact %}{{ rows|length }} row(s) (collapsed from {{ raw_count }} thread(s))
    {% else %}{{ rows|length }} thread(s){% endif %}
    {% if current_mailbox %} · {{ current_mailbox }}{% endif %}
  </span>
  <div class="actions">
    <form method="get" style="display:inline-flex; gap: 8px; align-items: center;">
      <select name="mailbox" onchange="this.form.submit()">
        <option value="">All mailboxes</option>
        {% for m in sidebar.mailboxes %}<option value="{{ m.mailbox }}" {% if m.mailbox == current_mailbox %}selected{% endif %}>{{ m.mailbox }}</option>{% endfor %}
      </select>
      <select name="group" onchange="this.form.submit()">
        <option value="date"    {% if group_by == 'date' %}selected{% endif %}>by recent activity</option>
        <option value="verdict" {% if group_by == 'verdict' %}selected{% endif %}>by current verdict</option>
      </select>
      <select name="compact" onchange="this.form.submit()">
        <option value="0" {% if not compact %}selected{% endif %}>all threads</option>
        <option value="1" {% if compact %}selected{% endif %}>compact</option>
      </select>
      <select name="limit" onchange="this.form.submit()">
        {% for n in [100, 200, 500, 1000] %}<option value="{{ n }}" {% if n == limit %}selected{% endif %}>{{ n }}</option>{% endfor %}
      </select>
    </form>
  </div>
</div>

{% if group_counts %}
<div class="row-inline" style="margin-bottom: 16px;">
  <span class="help">verdict mix:</span>
  {% for v, n in group_counts.items() | sort %}
    <span class="vp {{ v | verdict_class }}">{{ v }} · {{ n }}</span>
  {% endfor %}
</div>
{% endif %}

<div class="table-wrap">
  <table>
    <thead><tr>
      <th>Last activity</th><th>Thread (latest)</th>
      <th>Verdict</th><th># msgs</th><th>History</th>
    </tr></thead>
    <tbody>
      {% set ns = namespace(prev_v=None) %}
      {% for r in rows %}
        {% if group_by == 'verdict' and r.latest_verdict != ns.prev_v %}
          {% set ns.prev_v = r.latest_verdict %}
          <tr>
            <td colspan="5" style="background: oklch(0.21 0.014 265); padding: 14px;">
              <span class="vp {{ r.latest_verdict | verdict_class }}">{{ r.latest_verdict or '(unknown)' }}</span>
              <span class="help" style="margin-left: 10px;">{{ group_counts.get(r.latest_verdict or '(unknown)', 0) }} thread(s)</span>
            </td>
          </tr>
        {% endif %}
      <tr>
        <td class="when">{{ r.last_activity[:19].replace('T',' ') if r.last_activity else '' }}</td>
        <td>
          <div class="subj">
            <a href="/threads/{{ r.conversation_id }}?mailbox={{ r.mailbox }}">{{ r.subject or '(no subject)' }}</a>
            {% if r.collapsed_count and r.collapsed_count > 1 %}
              <span class="applybadge" title="Collapsed {{ r.collapsed_count }} threads with this exact subject + sender.">× {{ r.collapsed_count }}</span>
            {% endif %}
          </div>
          <div class="from">{{ r.latest_sender or '' }} · {{ r.mailbox }} · {{ r.conversation_id[-8:] if r.conversation_id else '' }}</div>
          {% if r.latest_preview %}<div class="help" style="margin-top: 4px; max-width: 720px;">{{ r.latest_preview[:140] }}{% if r.latest_preview|length > 140 %}…{% endif %}</div>{% endif %}
        </td>
        <td><span class="vp {{ r.latest_verdict | verdict_class }}">{{ r.latest_verdict }}</span></td>
        <td class="when">{{ r.msg_count }}</td>
        <td class="help">{{ r.verdict_count or 0 }} verdict(s){% if r.verdict_count and r.verdict_count > 1 %} <span class="applybadge">changed</span>{% endif %}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
"""


_THREAD_DETAIL_HTML = """\
<div class="ph">
  <h1>Thread</h1>
  <span class="sub">{{ mailbox }} · {{ conversation_id[:24] }}…</span>
  <div class="actions">
    <a class="btn" href="/threads?mailbox={{ mailbox }}">← Back to threads</a>
  </div>
</div>

<div class="section-label">Verdict timeline ({{ history|length }} classification{{ 's' if history|length != 1 else '' }})</div>
<div class="table-wrap" style="margin-bottom: 24px;">
  <table>
    <thead><tr><th>When</th><th>Verdict</th><th>Trigger</th><th>Size</th><th>Reason</th></tr></thead>
    <tbody>
      {% for h in history %}
      <tr {% if h.prev_verdict and h.prev_verdict != h.verdict_folder %}class="changed-row"{% endif %}>
        <td class="when">{{ h.decided_at[:19].replace('T',' ') }}</td>
        <td>
          {% if h.prev_verdict and h.prev_verdict != h.verdict_folder %}
            <span class="vp {{ h.prev_verdict | verdict_class }}">{{ h.prev_verdict }}</span>
            <span class="arrow">→</span>
          {% endif %}
          <span class="vp {{ h.verdict_folder | verdict_class }}">{{ h.verdict_folder }}</span>
        </td>
        <td>
          <div class="subj">{{ (h.trigger_subject or '')[:70] }}</div>
          <div class="from">{{ h.trigger_sender or '' }}</div>
        </td>
        <td class="when">{{ h.thread_size }}</td>
        <td class="help" style="max-width: 360px;">{{ (h.reason or h.model_raw or '')[:240] }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<div class="section-label">Messages in thread ({{ decisions|length }})</div>
<div class="table-wrap">
  <table>
    <thead><tr><th>When</th><th>Sender</th><th>Subject</th><th>Verdict</th><th>Tag</th><th>Move</th><th>Error</th></tr></thead>
    <tbody>
      {% for d in decisions %}
      <tr>
        <td class="when">{{ d.created_at[:19].replace('T',' ') }}</td>
        <td>{{ d.sender }}</td>
        <td>{{ (d.subject or '(no subject)')[:80] }}</td>
        <td><span class="vp {{ d.verdict_folder | verdict_class }}">{{ d.verdict_folder }}</span></td>
        <td>{% if d.tagged %}✓{% else %}—{% endif %}</td>
        <td>{% if d.moved %}✓{% else %}—{% endif %}</td>
        <td class="err-line">{{ d.apply_error or '' }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
"""


_CHANGES_HTML = """\
<div class="ph">
  <h1>Verdict changes</h1>
  <span class="sub">{{ rows|length }} row(s){% if current_mailbox %} · {{ current_mailbox }}{% endif %}</span>
  <div class="actions">
    <form method="get" style="display:inline-flex; gap: 8px; align-items: center;">
      <select name="mailbox" onchange="this.form.submit()">
        <option value="">All mailboxes</option>
        {% for m in sidebar.mailboxes %}<option value="{{ m.mailbox }}" {% if m.mailbox == current_mailbox %}selected{% endif %}>{{ m.mailbox }}</option>{% endfor %}
      </select>
      <select name="changes_only" onchange="this.form.submit()">
        <option value="1" {% if only_changes %}selected{% endif %}>only changes</option>
        <option value="0" {% if not only_changes %}selected{% endif %}>every classification</option>
      </select>
      <select name="limit" onchange="this.form.submit()">
        {% for n in [100, 200, 500, 1000] %}<option value="{{ n }}" {% if n == limit %}selected{% endif %}>{{ n }}</option>{% endfor %}
      </select>
    </form>
  </div>
</div>

<div class="table-wrap">
  <table>
    <thead><tr><th>When</th><th>Thread (trigger)</th><th>Verdict</th><th>Reason</th></tr></thead>
    <tbody>
      {% for r in rows %}
      <tr>
        <td class="when">{{ r.decided_at[:19].replace('T',' ') }}</td>
        <td>
          <div class="subj"><a href="/threads/{{ r.conversation_id }}?mailbox={{ r.mailbox }}">{{ (r.trigger_subject or '(no subject)')[:80] }}</a></div>
          <div class="from">{{ r.trigger_sender or '' }} · {{ r.mailbox }} · {{ r.thread_size }} msgs</div>
        </td>
        <td>
          {% if r.prev_verdict %}
            <span class="vp {{ r.prev_verdict | verdict_class }}">{{ r.prev_verdict }}</span>
            <span class="arrow">→</span>
          {% endif %}
          <span class="vp {{ r.verdict_folder | verdict_class }}">{{ r.verdict_folder }}</span>
        </td>
        <td class="help" style="max-width: 420px;">{{ r.reason or r.model_raw or '' }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
"""


_HIERARCHY_HTML = """\
<div class="ph">
  <h1>Taxonomy</h1>
  <span class="sub">{{ mailbox }}</span>
  <div class="actions">
    <a class="btn" href="/mailboxes#mb-{{ mailbox }}">← Back to mailboxes</a>
  </div>
</div>

<div class="banner info">
  Source: <code>{{ path }}</code> — edit this JSON in your fork's <code>src/data/hierarchies/</code>
  and push to update. The cache invalidates on every feedback submission, so no restart is needed
  once the file lands in the container.
</div>

<pre>{{ data | tojson(indent=2) }}</pre>
"""


# --- Feedback review --------------------------------------------------------

_FEEDBACK_REVIEW_HTML = """\
<div class="ph">
  <h1>Feedback</h1>
  <span class="sub">{{ feedback|length }} correction(s){% if proposals %} · {{ proposals|length }} proposal(s){% endif %}</span>
  <div class="actions">
    <form method="get" style="display:inline-flex; gap: 8px; align-items: center;">
      <select name="mailbox" onchange="this.form.submit()">
        <option value="">All mailboxes</option>
        {% for m in sidebar.mailboxes %}<option value="{{ m.mailbox }}" {% if m.mailbox == current_mailbox %}selected{% endif %}>{{ m.mailbox }}</option>{% endfor %}
      </select>
      <select name="user" onchange="this.form.submit()">
        <option value="__all__" {% if not current_user %}selected{% endif %}>all users (pooled)</option>
        {% for u in feedback_users %}
          <option value="{{ u.user_identifier }}" {% if u.user_identifier == current_user %}selected{% endif %}>{{ u.user_identifier }} · {{ u.n }}</option>
        {% endfor %}
      </select>
    </form>
    {% if current_mailbox %}
    <form method="post" action="/feedback-review/{{ current_mailbox }}/propose"
          onsubmit="this.querySelector('button').disabled = true; this.querySelector('button').textContent='Thinking… (~30s)'; return true;">
      {% if current_user %}<input type="hidden" name="user_identifier" value="{{ current_user }}">{% endif %}
      <button type="submit" class="btn pri">↻ Generate proposal</button>
    </form>
    {% endif %}
  </div>
</div>

<div class="feed-split">
  <div>
    <div class="section-label">Recent corrections</div>
    <div class="table-wrap">
      <table>
        <tbody>
          {% for f in feedback %}
          <tr>
            <td class="when" style="width: 110px;">{{ f.created_at[:19].replace('T',' ') }}</td>
            <td>
              <div class="subj">{{ (f.subject or '(no subject)')[:70] }}</div>
              <div class="from">{{ f.mailbox }} · {{ f.user_identifier or '(anonymous)' }}</div>
              {% if f.note %}<div class="note-block">"{{ f.note }}"</div>{% endif %}
            </td>
            <td style="text-align: right; white-space: nowrap;">
              {% if f.correct %}
                <span class="vp {{ f.model_choice | verdict_class }}">{{ f.model_choice }}</span>
              {% else %}
                <span class="vp {{ f.model_choice | verdict_class }}">{{ f.model_choice }}</span>
                <span class="arrow">→</span>
                <span class="vp {{ f.suggested | verdict_class }}">{{ f.suggested }}</span>
              {% endif %}
            </td>
          </tr>
          {% else %}
          <tr><td style="text-align: center; padding: 32px; color: var(--t3);">No feedback rows yet.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <div>
    <div class="section-label">Taxonomy proposals</div>
    {% if not proposals %}
      <div class="proposal"><div class="help">No proposals yet. Submit some feedback and click "↻ Generate proposal".</div></div>
    {% endif %}
    {% for p in proposals %}
    <div class="proposal {% if not p.applied_at and not p.discarded_at %}pending{% elif p.applied_at %}applied{% else %}discarded{% endif %}">
      <h5><a href="/feedback-review/proposal/{{ p.id }}" style="color: inherit;">{{ p.mailbox }} · proposal {{ p.id[:8] }}</a></h5>
      <div class="meta">
        {{ p.created_at[:19].replace('T',' ') }} · based on {{ p.based_on_feedback_count }} feedback row(s)
        {% if p.applied_at %} · ✓ applied {{ p.applied_at[:19].replace('T',' ') }}
        {% elif p.discarded_at %} · ✗ discarded {{ p.discarded_at[:19].replace('T',' ') }}
        {% else %} · pending review{% endif %}
      </div>
      {% if not p.applied_at and not p.discarded_at %}
      <div class="pa">
        <form method="post" action="/feedback-review/proposal/{{ p.id }}/apply" style="display:inline"
              onsubmit="return confirm('Write taxonomy to persistent override path?')">
          <button class="btn pri" type="submit">✓ Apply</button>
        </form>
        <a class="btn" href="/feedback-review/proposal/{{ p.id }}">View diff</a>
        <form method="post" action="/feedback-review/proposal/{{ p.id }}/discard" style="display:inline">
          <button class="btn ghost" type="submit">Discard</button>
        </form>
      </div>
      {% endif %}
    </div>
    {% endfor %}
  </div>
</div>
"""


_PROPOSAL_DIFF_HTML = """\
<div class="ph">
  <h1>Proposal {{ p.id[:8] }}</h1>
  <span class="sub">{{ p.mailbox }} · {{ p.created_at[:19].replace('T',' ') }} · {{ p.based_on_feedback_count }} feedback row(s)</span>
  <div class="actions">
    <a class="btn" href="/feedback-review">← Back</a>
    {% if p.applied_at %}<span class="banner ok" style="margin: 0; padding: 4px 10px;">applied {{ p.applied_at[:19] }} UTC</span>
    {% elif p.discarded_at %}<span class="banner err" style="margin: 0; padding: 4px 10px;">discarded {{ p.discarded_at[:19] }} UTC</span>
    {% endif %}
  </div>
</div>

{% if p.rationale %}
<div class="section-label">Rationale</div>
<div class="banner info" style="white-space: pre-wrap;">{{ p.rationale }}</div>
{% endif %}

{% if not p.applied_at and not p.discarded_at %}
<div class="row-inline" style="margin: 16px 0 24px;">
  <form method="post" action="/feedback-review/proposal/{{ p.id }}/apply" style="display:inline"
        onsubmit="return confirm('Write this taxonomy to the persistent override path? Next classification picks it up immediately.')">
    <button type="submit" class="btn pri">✓ Apply proposal</button>
  </form>
  <form method="post" action="/feedback-review/proposal/{{ p.id }}/discard" style="display:inline">
    <button type="submit" class="btn danger">✗ Discard</button>
  </form>
  <span class="help">Apply writes to <code>/data/hierarchies/&lt;mailbox&gt;.json</code> (persistent volume).</span>
</div>
{% endif %}

<div class="section-label">Diff</div>
<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
  <div>
    <h3 style="font-size: 13px; color: var(--t3); margin: 0 0 8px; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;">Current</h3>
    <pre>{{ p.current_json }}</pre>
  </div>
  <div>
    <h3 style="font-size: 13px; color: var(--t3); margin: 0 0 8px; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;">Proposed</h3>
    <pre>{{ p.proposed_json }}</pre>
  </div>
</div>
"""


# --- Test classify ----------------------------------------------------------

_TEST_CLASSIFY_HTML = """\
<div class="ph">
  <h1>Test classify</h1>
  <span class="sub">replay a real thread through the classifier</span>
  <div class="actions">
    <form method="get" style="display:inline-flex; gap: 6px; align-items: center;">
      <span class="help">min messages</span>
      <input type="number" name="min" value="{{ min_msgs }}" min="2" max="500" style="width: 70px;" onchange="this.form.submit()">
    </form>
  </div>
</div>

<div class="banner info">
  Pick a real thread from your connected mailbox history and replay it through the classifier <em>right now</em> — no waiting, no full reclassify. Pure observation by default (no DB writes); tick "write summary" to also land a real thread_summaries row.
</div>

<div class="table-wrap">
  <table>
    <thead><tr><th>Mailbox</th><th>Subject</th><th># msgs</th><th>Last activity</th><th></th></tr></thead>
    <tbody>
      {% for r in rows %}
      <tr>
        <td>{{ r.mailbox }}</td>
        <td>
          <div class="subj">{{ (r.subject or '(no subject)')[:90] }}</div>
          <div class="from">{{ r.conversation_id[-12:] }}</div>
        </td>
        <td class="when">{{ r.msg_count }}</td>
        <td class="when">{{ r.last_activity[:19].replace('T',' ') if r.last_activity else '' }}</td>
        <td>
          <form method="post" action="/test-classify/run" style="display:inline-flex; gap: 6px; align-items: center;">
            <input type="hidden" name="mailbox" value="{{ r.mailbox }}">
            <input type="hidden" name="conversation_id" value="{{ r.conversation_id }}">
            <label class="help" style="display:inline-flex; gap: 4px; align-items: center;">
              <input type="checkbox" name="persist" value="1"> write
            </label>
            <button type="submit" class="btn pri sm">↻ Test</button>
          </form>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
"""


_TEST_RESULT_HTML = """\
<div class="ph">
  <h1>Test result</h1>
  <span class="sub">{{ mailbox }} · {{ thread_size }} message(s)</span>
  <div class="actions">
    <a class="btn" href="/test-classify">← Back</a>
  </div>
</div>

{% if verdict.parse_error %}
<div class="banner err banner-big">
  ✗ LLM did not return JSON. parse_error: <code>{{ verdict.parse_error }}</code>
</div>
{% elif verdict.summary %}
<div class="banner ok banner-big">
  ✓ LLM returned valid JSON with a summary ({{ verdict.summary|length }} chars). Cost-saving strategy working as designed.
</div>
{% else %}
<div class="banner err banner-big">
  ⚠ LLM returned JSON but the summary was empty. Folder verdict still works; cost-saving doesn't kick in.
</div>
{% endif %}

<div class="section-label">Run metadata</div>
<div class="table-wrap" style="margin-bottom: 24px;">
  <table class="kv">
    <tr><th>Mailbox</th><td>{{ mailbox }}</td></tr>
    <tr><th>Thread key</th><td><code>{{ thread_key }}</code></td></tr>
    <tr><th>Conversation id</th><td><code>{{ conv_id }}</code></td></tr>
    <tr><th>Thread size</th><td>{{ thread_size }} message(s)</td></tr>
    <tr><th>Latest message</th><td>{{ latest_msg.subject or '(no subject)' }} — from {{ latest_msg.from_address or latest_msg.from_name }}</td></tr>
    <tr><th>Prior summary used?</th><td>
      {% if used_prior_summary %}<span style="color: var(--ok); font-weight: 600;">YES</span> — cost-saving active{% else %}<span style="color: var(--err); font-weight: 600;">NO</span> — first classification of this thread{% endif %}
    </td></tr>
    <tr><th>Model</th><td><code>{{ model_used }}</code></td></tr>
    <tr><th>Elapsed</th><td>{{ '%.2f'|format(elapsed_seconds) }}s</td></tr>
    {% if persist %}
      <tr><th>Persisted?</th><td>{% if persisted %}<span style="color: var(--ok); font-weight: 600;">YES</span>{% else %}<span style="color: var(--err); font-weight: 600;">NO</span> (see logs){% endif %}</td></tr>
    {% else %}
      <tr><th>Persisted?</th><td>No — dry-run mode</td></tr>
    {% endif %}
  </table>
</div>

<div class="section-label">Parsed verdict</div>
<div class="table-wrap" style="margin-bottom: 24px;">
  <table class="kv">
    <tr><th>Folder</th><td><span class="vp {{ verdict.folder | verdict_class }}">{{ verdict.folder }}</span></td></tr>
    <tr><th>Summary</th><td>{{ verdict.summary or '(empty)' }}</td></tr>
    <tr><th>Key facts ({{ verdict.key_facts|length }})</th><td>
      {% if verdict.key_facts %}<ul style="margin: 0; padding-left: 18px;">
      {% for kf in verdict.key_facts %}<li><strong>{{ kf.label }}:</strong> {{ kf.value }}</li>{% endfor %}
      </ul>{% else %}<span class="help">(empty)</span>{% endif %}
    </td></tr>
    <tr><th>Timeline ({{ verdict.timeline|length }})</th><td>
      {% if verdict.timeline %}<ul style="margin: 0; padding-left: 18px;">
      {% for ev in verdict.timeline %}<li><code>{{ ev.date }}</code> — {{ ev.event }}</li>{% endfor %}
      </ul>{% else %}<span class="help">(empty)</span>{% endif %}
    </td></tr>
    <tr><th>Contacts ({{ verdict.contacts|length }})</th><td>
      {% if verdict.contacts %}<ul style="margin: 0; padding-left: 18px;">
      {% for c in verdict.contacts %}<li><strong>{{ c.name or '(unknown)' }}</strong>{% if c.email %} &lt;{{ c.email }}&gt;{% endif %}{% if c.role %} · {{ c.role }}{% endif %}{% if c.organization %} · {{ c.organization }}{% endif %}</li>{% endfor %}
      </ul>{% else %}<span class="help">(empty)</span>{% endif %}
    </td></tr>
  </table>
</div>

<div class="section-label">Raw LLM output</div>
<pre>{{ verdict.raw }}</pre>

{% if prior_summary %}
<div class="section-label" style="margin-top: 24px;">Prior summary (fed to LLM)</div>
<pre>{{ prior_summary | tojson(indent=2) }}</pre>
{% endif %}
"""


# --- Public feedback landing (no sidebar, no auth) --------------------------

_FEEDBACK_FORM_HTML = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>feedback · email-engine</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
""" + _INLINE_STYLE + """
<style>
  body { display: grid; place-items: center; min-height: 100vh; padding: 24px; }
  .form-card { max-width: 560px; width: 100%; background: var(--bg2); border: 1px solid var(--bd);
               border-radius: 3px; padding: 28px 32px; }
  .form-card h1 { font-size: 18px; font-weight: 600; margin: 0 0 18px; letter-spacing: -0.02em; }
  .form-card .meta-block { background: var(--surf); border-radius: 3px; padding: 12px 14px;
                            margin-bottom: 20px; font-size: 13px; color: var(--t2); }
  .form-card .meta-block strong { color: var(--t1); }
  .form-card label.row { display: block; margin: 14px 0 4px; color: var(--t3);
                          font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }
  .form-card select, .form-card input[type=text], .form-card textarea { width: 100%; }
  .form-card textarea { min-height: 100px; resize: vertical; }
  .form-card .pills { display: flex; gap: 10px; margin: 8px 0 12px; }
  .form-card .pills label { display: inline-flex; align-items: center; gap: 6px;
                             padding: 8px 14px; border-radius: 3px; border: 1px solid var(--bd);
                             background: var(--surf); cursor: pointer; color: var(--t1); }
  .form-card .pills label:has(input:checked) { border-color: var(--ac); background: var(--acSoft); }
</style>
</head>
<body>
<div class="form-card">
  <h1>Was this classification wrong?</h1>
  <div class="meta-block">
    <div><strong>Subject:</strong> {{ decision.subject or '(no subject)' }}</div>
    <div><strong>From:</strong> {{ decision.sender or '(unknown)' }}</div>
    <div><strong>Classified as:</strong> <span class="vp {{ decision.verdict_folder | verdict_class }}">{{ decision.verdict_folder }}</span></div>
  </div>
  <form method="post">
    <div class="pills">
      <label><input type="radio" name="correct" value="1" required> ✓ actually correct</label>
      <label><input type="radio" name="correct" value="0" checked> ✗ wrong</label>
    </div>

    <label class="row">What should it have been?</label>
    <select name="suggested">
      <option value="">(leave blank if correct)</option>
      {% for f in folders %}
        <option value="{{ f.id or f.name }}" {% if (f.id or f.name) == decision.verdict_folder %}disabled{% endif %}>{{ f.name }}</option>
      {% endfor %}
    </select>
    <div class="help" style="margin-top: 4px;">Required if you picked ✗ wrong.</div>

    <label class="row">Why? (helps the next taxonomy update)</label>
    <textarea name="note" placeholder="e.g. 'sender is internal; thread is about renewal; should always be high-priority'"></textarea>

    <label class="row">Your email</label>
    <input type="text" name="user_identifier" value="{{ prefilled_user }}" placeholder="you@example.com">
    <div class="help" style="margin-top: 4px;">So your taxonomy reflects YOUR preferences.</div>

    <button type="submit" class="btn pri" style="margin-top: 18px;">Submit feedback</button>
  </form>
</div>
</body>
</html>
"""


_FEEDBACK_DONE_HTML = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ title }} · email-engine</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
""" + _INLINE_STYLE + """
<style>
  body { display: grid; place-items: center; min-height: 100vh; padding: 24px; }
  .done-card { max-width: 480px; width: 100%; background: var(--bg2); border: 1px solid var(--bd);
               border-radius: 3px; padding: 28px 32px; }
  .done-card h1 { font-size: 18px; font-weight: 600; margin: 0 0 12px; letter-spacing: -0.02em; }
  .done-card p { color: var(--t2); margin: 0; line-height: 1.6; }
</style>
</head>
<body>
<div class="done-card"><h1>{{ title }}</h1><p>{{ body }}</p></div>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
