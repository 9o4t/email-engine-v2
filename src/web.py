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
from lib.storage import MailboxConfig, Store
from poller import reclassify_all


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
    )
    invalidate_cache()
    if request.headers.get("Accept", "").startswith("application/json"):
        return jsonify({"ok": True, "feedback_id": fid})
    return Response(status=303, headers={"Location": request.referrer or "/"})


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
    rows = store.list_threads(mailbox=mailbox, limit=limit)

    # Per-verdict counts for the section headers (always computed so we
    # can show the same info as a summary even when group=date).
    group_counts: dict[str, int] = {}
    for r in rows:
        v = r["latest_verdict"] or "(unknown)"
        group_counts[v] = group_counts.get(v, 0) + 1

    if group_by == "verdict":
        # Sort: verdict ASC (so 1- before 2- before ...), then most recent
        # activity first within each group.
        def sort_key(r):
            return (
                r["latest_verdict"] or "zzz",
                -1 * (datetime.fromisoformat(r["last_activity"]).timestamp()
                      if r["last_activity"] else 0),
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
    )


@app.post("/mailboxes")
@_require_auth
def mailboxes_add():
    mb = MailboxConfig(
        mailbox=request.form.get("mailbox", "").strip().lower(),
        provider=request.form.get("provider", "graph"),
        apply_mode=request.form.get("apply_mode", "tag_and_move"),
        enabled=request.form.get("enabled", "1") == "1",
        imap_server=request.form.get("imap_server", "").strip(),
        imap_port=int(request.form.get("imap_port", "993")),
        poll_interval=int(request.form.get("poll_interval", "30")),
        notes=request.form.get("notes", "").strip(),
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
    if cur.apply_mode not in APPLY_MODES:
        abort(400, f"apply_mode must be one of {APPLY_MODES}")
    store.upsert_mailbox(cur)
    return Response(status=303, headers={"Location": "/mailboxes"})


@app.post("/mailboxes/<path:email>/delete")
@_require_auth
def mailboxes_delete(email: str):
    store.delete_mailbox(email)
    return Response(status=303, headers={"Location": "/mailboxes"})


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
  .help, .when, .sender, .reclass-status { color: #98989f !important; }
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
{% endif %}
<h1>Mailboxes</h1>

<table>
  <thead><tr>
    <th>Mailbox</th><th>Provider</th><th>Apply mode</th><th>Enabled</th>
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
        <select name="apply_mode">
          {% for am in apply_modes %}
            <option value="{{ am }}" {% if am == m.apply_mode %}selected{% endif %}>{{ am }}</option>
          {% endfor %}
        </select>
      </td>
      <td>
        <select name="enabled">
          <option value="1" {% if m.enabled %}selected{% endif %}>yes</option>
          <option value="0" {% if not m.enabled %}selected{% endif %}>no</option>
        </select>
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
      <td colspan="7" style="border-bottom: 2px solid #f0f0f0; padding-bottom: 12px;">
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
  <label>Show:
    <select name="limit" onchange="this.form.submit()">
      {% for n in [100, 200, 500, 1000] %}<option value="{{ n }}" {% if n == limit %}selected{% endif %}>{{ n }}</option>{% endfor %}
    </select>
  </label>
  <span class="help">{{ rows|length }} thread(s) shown</span>
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
        </div>
        <div class="sender">{{ r.latest_sender or '' }}</div>
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
