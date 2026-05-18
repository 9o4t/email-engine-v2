"""
taxonomy_review.py — turn accumulated feedback into a taxonomy edit.

The user clicks "✗ wrong" on a footer link; the form captures BOTH the
correct verdict AND a free-text reason. Over time you accumulate a pile
of (subject, sender, body_preview, model_choice, suggested, note) rows.

This module asks the LLM: "Here's the current taxonomy + recent
feedback. Propose a JSON replacement that would prevent these
misclassifications. Output the new JSON + a per-change rationale."

The proposal is stored (taxonomy_proposals table) so the user can review
the diff in the dashboard and apply it (writes to /data/hierarchies/)
or discard it. Nothing auto-applies — every change is a human decision.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from classifier import LLMConfig, hierarchy_path_for
from lib.storage import Store

log = logging.getLogger(__name__)


_PROPOSAL_SYSTEM = """\
You revise per-mailbox email-triage taxonomies based on accumulated
feedback. The taxonomy is a JSON file with `nodes`, each a destination
folder with id + name + description. BM25 retrieves over the
descriptions at classification time, then an LLM picks the leaf id.

Your job: given the current taxonomy + recent feedback rows showing
where the classifier was wrong (and the user's reason why), output a
revised taxonomy + a per-change rationale.

Editing principles:
  - Prefer DESCRIPTION edits over structural changes. Most misclassifications
    are description-coverage gaps — adding the right phrases/keywords to a
    description usually fixes the next batch of similar emails.
  - Keep existing leaf IDs stable. Renaming a leaf orphans every prior
    decision row that pointed at the old name.
  - Only add a new leaf when the feedback clearly indicates a distinct
    category that isn't representable by tweaking descriptions.
  - Preserve the leading-digit priority convention (1-/2-/3-/4-/5-) so the
    dashboard color buckets keep working.

Return a SINGLE JSON object with these top-level keys:
  - "taxonomy":  the FULL revised taxonomy JSON (same shape as the input —
                 must include the root node and all leaf children).
  - "rationale": prose explaining WHAT you changed and WHY, grouped by
                 leaf id. Markdown-friendly; this is what the user reads
                 in the diff view before accepting.
  - "summary":   one-sentence high-level summary suitable for a button-
                 hover preview.

No prose before or after the JSON. No markdown fences.
"""


def _feedback_block(rows: list[dict]) -> str:
    """Render feedback rows as a tight context block for the prompt.
    Each row is ~4 lines max — total prompt stays manageable even with
    hundreds of feedback rows."""
    out: list[str] = []
    for i, r in enumerate(rows, 1):
        verdict = (r.get("correct") and "right") or "WRONG"
        sub = (r.get("subject") or "").strip()[:160]
        sender = (r.get("sender") or "").strip()[:80]
        body = (r.get("body_preview") or "").strip()[:300]
        chosen = r.get("model_choice") or "?"
        sug = r.get("suggested") or ""
        note = (r.get("note") or "").strip()
        out.append(
            f"[{i}] {verdict} — chose {chosen!r}"
            + (f", user says should be {sug!r}" if sug else "")
        )
        out.append(f"    subj: {sub}")
        out.append(f"    from: {sender}")
        if body:
            out.append(f"    body: {body[:200]}")
        if note:
            out.append(f"    why:  {note}")
    return "\n".join(out)


def _user_prompt(current_taxonomy_json: str, feedback_rows: list[dict]) -> str:
    return (
        "# Current taxonomy (verbatim)\n"
        f"{current_taxonomy_json}\n\n"
        f"# Feedback rows ({len(feedback_rows)} total, newest first)\n"
        f"{_feedback_block(feedback_rows)}\n\n"
        "# Your output\n"
        "Return ONE JSON object: {taxonomy, rationale, summary}."
    )


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json(raw: str) -> dict | None:
    """Robust JSON extraction — same pattern as classifier.py's parser."""
    if not raw:
        return None
    txt = raw.strip()
    if txt.startswith("```"):
        txt = txt.strip("`")
        nl = txt.find("\n")
        if nl != -1 and txt[:nl].strip().lower() in {"json", ""}:
            txt = txt[nl + 1:]
        txt = txt.strip("` \n")
    try:
        v = json.loads(txt)
        if isinstance(v, dict):
            return v
    except json.JSONDecodeError:
        pass
    m = _JSON_OBJECT_RE.search(txt)
    if m:
        try:
            v = json.loads(m.group(0))
            if isinstance(v, dict):
                return v
        except json.JSONDecodeError:
            return None
    return None


def generate_proposal(
    mailbox: str,
    store: Store,
    cfg: LLMConfig | None = None,
    limit: int = 200,
) -> dict:
    """Run the LLM once with the current taxonomy + recent feedback.
    Stores the result as a taxonomy_proposals row and returns
    {ok, proposal_id, summary, error}.

    Uses the same OpenAI-compatible client as the classifier (Haystack's
    OpenAIGenerator is overkill here — direct httpx-style call). We do
    use the same LLM endpoint config though so the operator only
    configures one set of LLM_* env vars."""
    cfg = cfg or LLMConfig.from_env()
    feedback_rows = store.feedback_export(mailbox=mailbox)[:limit]
    if not feedback_rows:
        return {"ok": False, "error": "no feedback rows yet for this mailbox"}

    current_path = hierarchy_path_for(mailbox)
    try:
        current_json = current_path.read_text(encoding="utf-8")
    except Exception as e:
        return {"ok": False, "error": f"cannot read current taxonomy: {e}"}

    # Direct LLM call (OpenAI-compatible /v1/chat/completions).
    import requests
    url = cfg.base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": _PROPOSAL_SYSTEM},
            {"role": "user",   "content": _user_prompt(current_json, feedback_rows)},
        ],
        "temperature": 0.2,
        "max_tokens": 4000,
    }
    headers = {"Authorization": f"Bearer {cfg.api_key}",
               "Content-Type": "application/json"}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=90)
        r.raise_for_status()
        raw = (r.json().get("choices") or [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        log.exception("[%s] taxonomy proposal LLM call failed: %s", mailbox, e)
        return {"ok": False, "error": f"LLM call failed: {e}"}

    parsed = _extract_json(raw)
    if not parsed or "taxonomy" not in parsed:
        return {
            "ok": False, "error": "LLM did not return a parseable proposal",
            "raw": raw[:2000],
        }

    proposed_json_text = json.dumps(parsed["taxonomy"], indent=2)
    rationale = parsed.get("rationale") or ""
    summary = parsed.get("summary") or ""

    pid = store.insert_taxonomy_proposal(
        mailbox=mailbox,
        based_on_feedback_count=len(feedback_rows),
        current_json=current_json,
        proposed_json=proposed_json_text,
        rationale=rationale if isinstance(rationale, str) else json.dumps(rationale, indent=2),
        llm_raw=raw[:8000],
    )
    return {"ok": True, "proposal_id": pid, "summary": summary,
            "based_on": len(feedback_rows)}


def apply_proposal(
    proposal_id: str, store: Store,
) -> dict:
    """Write the proposed JSON to the persistent override path for the
    mailbox, mark the proposal applied. Validates the JSON parses
    before writing so a malformed proposal doesn't brick classification.

    The classifier's @lru_cache on _load_hierarchy and _build_pipeline
    must be invalidated after this — the web handler calls
    invalidate_cache() so the next classification picks up the new file."""
    from classifier import hierarchy_override_path

    p = store.get_taxonomy_proposal(proposal_id)
    if not p:
        return {"ok": False, "error": "proposal not found"}
    if p.get("applied_at") or p.get("discarded_at"):
        return {"ok": False, "error": "proposal already resolved"}
    try:
        json.loads(p["proposed_json"])  # validate
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"proposed JSON does not parse: {e}"}

    dest = hierarchy_override_path(p["mailbox"])
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(p["proposed_json"], encoding="utf-8")
    except OSError as e:
        return {"ok": False, "error": f"could not write override: {e}"}

    store.mark_taxonomy_proposal(proposal_id, applied=True, discarded=False)
    log.info("[%s] applied taxonomy proposal %s → %s",
             p["mailbox"], proposal_id, dest)
    return {"ok": True, "path": str(dest)}


def discard_proposal(proposal_id: str, store: Store) -> dict:
    p = store.get_taxonomy_proposal(proposal_id)
    if not p:
        return {"ok": False, "error": "proposal not found"}
    if p.get("applied_at") or p.get("discarded_at"):
        return {"ok": False, "error": "proposal already resolved"}
    store.mark_taxonomy_proposal(proposal_id, applied=False, discarded=True)
    return {"ok": True}
