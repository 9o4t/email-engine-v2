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
import os
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, Response, abort, jsonify, render_template_string, request

from classifier import hierarchy_path_for, invalidate_cache, list_folders
from lib.apply import APPLY_MODES
from lib.storage import MailboxConfig, Store


load_dotenv()
app = Flask(__name__)
store = Store()


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
  <a href="/mailboxes">Mailboxes</a> ·
  <a href="/api/feedback.csv">Feedback CSV</a>
</nav>
"""

_DECISIONS_HTML = """\
<!doctype html><title>email-engine-v2 — decisions</title>
<style>
  body { font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 1.5rem; }
  h1 { font-size: 1.2rem; margin: 0 0 1rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
  th { text-align: left; background: #fafafa; }
  .verdict { font-family: ui-monospace, monospace; font-size: 0.85rem; padding: 2px 6px; border-radius: 4px; background: #eef; }
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
""" + _NAV + """\
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
        <span class="verdict">{{ d.verdict_folder }}</span>
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
</style>
""" + _NAV + """\
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
        <input type="text" name="imap_server" value="{{ m.imap_server }}" size="20">
        :<input type="number" name="imap_port" value="{{ m.imap_port }}" size="5" style="width:60px">
      </td>
      <td><input type="number" name="poll_interval" value="{{ m.poll_interval }}" style="width:60px"> s</td>
      <td>
        <button type="submit">Save</button>
      </td>
    </tr>
    </form>
    <tr>
      <td colspan="7" style="border-bottom: 2px solid #f0f0f0; padding-bottom: 12px;">
        <form method="post" action="/mailboxes/{{ m.mailbox }}/delete" style="display:inline" onsubmit="return confirm('Remove this mailbox? Decisions stay, polling stops.')">
          <button type="submit" style="font-size:0.75rem;color:#a00">delete</button>
        </form>
        <span class="help">{{ m.notes }}</span>
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
"""


_HIERARCHY_HTML = """\
<!doctype html><title>{{ mailbox }} — taxonomy</title>
<style>
  body { font: 14px/1.45 -apple-system, system-ui, sans-serif; margin: 1.5rem; max-width: 900px; }
  pre { background: #f8f8f8; padding: 12px; border-radius: 6px; overflow: auto; }
  .path { color: #666; font-size: 0.85rem; }
</style>
""" + _NAV + """\
<h2>{{ mailbox }} — taxonomy</h2>
<p class="path">Source: <code>{{ path }}</code></p>
<p>Edit this file in your fork's <code>src/data/hierarchies/</code> and push to update. Cache invalidates on every feedback submission, so no restart needed once the file lands in the container.</p>
<pre>{{ data | tojson(indent=2) }}</pre>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
