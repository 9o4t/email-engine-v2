# email-engine-v2

AI-powered email triage with the architecture that won the [Barclays Hack-O-Hire 2024](https://github.com/shxntanu/email-classifier) — **RAG-over-JSON taxonomy + LLM picks the right leaf** — adapted for one mailbox owner (not a person-router), with per-mailbox training, multi-provider support (Microsoft Graph + Gmail), and a UI-toggleable apply mode (tag / move / both).

The classifier output is a folder/category name; the apply step does what the mailbox is configured to do with it.

---

## Why v2

The first iteration (Go, Outlook Graph only, flat priority categories embedded in the system prompt) shipped useful but stalled on:

- Hand-written categories baked into the prompt — no scaling to per-mailbox taxonomies.
- One protocol (Graph), no Gmail.
- Always tag AND move — no way to test if tag-only "smart folders" worked for a given client.
- Feedback was implicit (operator squints at decisions table) — no structured loop.

v2 lifts the hackathon-winning architecture into Python, fixes all four.

## Architecture

```
  ┌───────────────────────────────────────────────────────────────┐
  │  poller.py    every POLL_INTERVAL_SEC                         │
  │                                                               │
  │  for each ENABLED mailbox in mailbox_config:                  │
  │     provider = make_provider(graph|imap)                      │
  │     msgs = provider.list_inbox(since=watermark)               │
  │     for m in msgs:                                            │
  │        verdict = classify(mailbox, m)              ┐          │
  │        apply_verdict(provider, verdict, mode) ─────┼─► tag    │
  │        store.insert_decision(...)                  │  move    │
  │                                                    └─ both    │
  └───────────────────────────────────────────────────────────────┘
                                          ▲
  ┌─────────────────────────────────────┐ │
  │  web.py    Flask + gunicorn         │─┘  reads decisions,
  │   /                 decisions       │    writes feedback,
  │   /mailboxes        config + apply  │    edits mailbox config
  │   /feedback (POST)  the button      │
  └─────────────────────────────────────┘
```

### The three knobs that matter

| Knob | Where it lives | What it controls |
| --- | --- | --- |
| **Taxonomy** (per mailbox) | `src/data/hierarchies/<mailbox>.json` | The destination folders + descriptions BM25 retrieves over. This is how you "train" a mailbox — edit JSON, no model retraining. |
| **Apply mode** (per mailbox) | `mailbox_config.apply_mode` in SQLite, editable at `/mailboxes` | `tag` (set category, leave in inbox) / `move` (folder only) / `tag_and_move` (both, default). |
| **System prompt** (per mailbox, optional) | `src/data/prompts/<mailbox>.md` | Override the classifier's instructions for one mailbox — voice, edge cases, tone. Falls back to a sensible default. |

## Providers

### Microsoft Graph (primary)

Uses the existing n8n token broker. Same protocol as the previous email-engine: POST `[{"token_check":"start"}]` to `CALENDAR_URL` with header `bearer: $B2B_TOKEN`, expect `[{"bearer_token": "...", "minutes_left": 50}]` back.

In Graph land:
- "Folder" = mailFolder under Inbox; auto-created if missing.
- "Category" = Outlook category (color category); `PATCH /messages/{id}` with `categories: [...]` replaces the list.

### Gmail / Google Workspace (secondary)

Uses IMAP with an app password. Per-mailbox password lives in env: `IMAP_<SANITIZED_EMAIL>_PASSWORD`. Sanitization rule: lowercase, non-alphanumeric → `_`. So `dave@gmail.com` → `IMAP_DAVE_GMAIL_COM_PASSWORD`.

In Gmail land:
- "Folder" = IMAP mailbox; moving a message to a folder is how labeling-and-archiving works at the protocol level.
- "Category" = Gmail label, set via the `X-GM-LABELS` IMAP extension.
- Thread context comes from `X-GM-THRID`.

For non-Gmail IMAP servers, labels degrade to IMAP keywords (rendered as flags by most clients). Use Graph or Gmail for the cleanest UX.

## Apply modes — pick what your mailbox's client renders well

`apply_mode` per mailbox, edit at `/mailboxes`:

- **`tag`** — only set the category/label. Message stays in INBOX. Use when your client (Outlook, Gmail) shows category-filtered "smart folders" — fewer rules to maintain.
- **`move`** — only move to folder. No category set. Use when you don't care about cross-folder filtering.
- **`tag_and_move`** — both. The original email-engine behavior. Safest default; survives even if you later change your filter strategy.

Toggle takes effect on the next polling cycle. No restart.

## Run locally

```bash
git clone https://github.com/9o4t/email-engine-v2
cd email-engine-v2
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env: CALENDAR_URL/B2B_TOKEN (for Graph), LLM_*, WEB_USER/PASS

mkdir -p /data    # or set FEEDBACK_DB_PATH=./data/db.sqlite for Windows
export PYTHONPATH=$PWD/src

# Terminal 1 — poller
python -m src.poller

# Terminal 2 — UI
python -m src.web
# Open http://localhost:8000, basic-auth with WEB_USER / WEB_PASS
```

## Deploy on Railway

1. **Create** a project from this GitHub repo (the `main` branch). Railway auto-detects `Dockerfile` + `railway.json`.
2. **Add a Volume** mounted at `/data`. 1 GB is plenty. This is where the SQLite DB lives — without it you lose state on every redeploy.
3. **Set env vars** in Railway:
   - `CALENDAR_URL` + `B2B_TOKEN` — the token broker (reuse what your existing email-engine uses).
   - `MAILBOXES_GRAPH=dave@9o4t.com` — comma-separated emails. Seeds the table on first boot.
   - `LLM_BASE_URL` + `LLM_MODEL` + `LLM_API_KEY` — pick a provider (OpenAI, OpenRouter, Anthropic-via-proxy, local Ollama tunnel, etc.).
   - `WEB_USER` + `WEB_PASS` — dashboard credentials.
4. **Deploy.** Railway gives you a `*.up.railway.app` URL. Hit it with basic-auth.
5. **Sanity-check**: `/healthz` returns "ok". `/mailboxes` shows your seeded mailbox. Send yourself an email → check `/` for the decision row.

### Adding a Gmail mailbox later

1. Generate an app password at <https://myaccount.google.com/apppasswords> (requires 2FA on the account).
2. Add the Railway env var: `IMAP_DAVE_GMAIL_COM_PASSWORD=...` (substitute your sanitized email).
3. Restart the service (or just `/mailboxes` → Add: `dave@gmail.com`, provider=`imap`, server=`imap.gmail.com`, port=`993`).
4. Optionally copy `_default.json` to `dave_gmail_com.json` and edit the descriptions for what should land where.

### Microsoft 365 IMAP fallback

If your tenant allows it, you CAN connect a Microsoft 365 mailbox via IMAP instead of Graph. Server: `outlook.office365.com:993`. App password from `account.microsoft.com → Security → App passwords` (requires MFA). But Graph is the better path for M365 — richer thread model, no basic-auth deprecation risk.

## The feedback loop

Each row at `/` has two pills:

- **✓ right folder** — records a positive feedback row.
- **✗ wrong → move to ...** — pick the correct folder from the dropdown.

Both write to the `feedback` table. Pull the joined dataset any time at `/api/feedback.csv` — that's your refinement set:

1. Sort by `correct=0` and look for patterns — emails whose subject/body don't match your description language.
2. Edit `src/data/hierarchies/<mailbox>.json` to describe those cases better. The cache invalidates on every feedback click, so the next classification picks up your edits.
3. When the descriptions stop covering the long tail, the CSV is also a clean fine-tune dataset for a future locally-hosted model.

## Layout

```
src/
  classifier.py            RAG over per-mailbox JSON + OpenAI-compatible LLM
  poller.py                multi-provider mailbox daemon
  web.py                   Flask UI + feedback endpoints
  providers/
    base.py                Provider interface + Message dataclass
    graph.py               Microsoft Graph (token broker, /v1.0 API)
    imap.py                IMAP w/ Gmail X-GM-* extensions
  lib/
    apply.py               tag / move / tag_and_move composer
    storage.py             SQLite: mailbox_config, decisions, feedback, watermarks
  data/
    hierarchies/
      _default.json        executive 5-rule taxonomy
      <mailbox>.json       per-mailbox override (create when ready)
    prompts/
      <mailbox>.md         (optional) per-mailbox system prompt override
Dockerfile
entrypoint.sh
railway.json
requirements.txt
.env.example
```

## Inspiration / credit

The retrieval architecture (BM25 over a JSON node taxonomy → LLM picks the leaf id) is from [shxntanu/email-classifier](https://github.com/shxntanu/email-classifier) — winner at Barclays Hack-O-Hire 2024. This repo lifts that idea into a folder-routing context, makes it per-mailbox-trainable, and adds the feedback button the original only TODO'd.

## License

MIT — see [LICENSE](LICENSE).
