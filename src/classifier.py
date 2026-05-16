"""
classifier.py — RAG-over-JSON folder classifier + multi-consumer prompt.

Same hackathon-winning architecture (BM25 retrieval over a JSON taxonomy
→ LLM picks the best leaf), repointed at folders + per-mailbox.

  1. Per-mailbox taxonomy. data/hierarchies/<sanitized_mailbox>.json
     with _default.json fallback. Editing JSON IS the training loop.

  2. OpenAI-compatible LLM client. Point LLM_BASE_URL at Ollama, OpenAI,
     OpenRouter, vLLM, Anthropic-via-proxy, etc.

The ONE classifier call is shared with downstream consumers via
src/consumers.py. Each consumer fragment appends its own instructions
to the system prompt + claims a slice of the JSON response. Today
that's `synct` (ThreadSummary). Adding `portals` later just appends to
the fragments tuple — the loop is unchanged.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from haystack import Document, Pipeline
from haystack.components.builders.prompt_builder import PromptBuilder
from haystack.components.retrievers.in_memory import InMemoryBM25Retriever
from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack.components.generators import OpenAIGenerator
from haystack.utils import Secret

from consumers import CONSUMERS, all_output_keys
from providers.base import sanitize_mailbox


HIERARCHY_DIR = Path(__file__).parent / "data" / "hierarchies"
DEFAULT_HIERARCHY = HIERARCHY_DIR / "_default.json"
PROMPT_DIR = Path(__file__).parent / "data" / "prompts"


def hierarchy_path_for(mailbox: str) -> Path:
    p = HIERARCHY_DIR / f"{sanitize_mailbox(mailbox)}.json"
    return p if p.exists() else DEFAULT_HIERARCHY


def prompt_path_for(mailbox: str) -> Path | None:
    p = PROMPT_DIR / f"{sanitize_mailbox(mailbox)}.md"
    return p if p.exists() else None


# --- LLM config -------------------------------------------------------------

@dataclass(frozen=True)
class LLMConfig:
    base_url: str
    model: str
    api_key: str

    @classmethod
    def from_env(cls) -> "LLMConfig":
        return cls(
            base_url=os.getenv("LLM_BASE_URL", "http://localhost:11434/v1"),
            model=os.getenv("LLM_MODEL", "qwen2.5:7b"),
            api_key=os.getenv("LLM_API_KEY", "ollama"),
        )


# --- Prompt -----------------------------------------------------------------

# Base classifier instructions. Consumer fragments (see consumers.py)
# append their own instructions to this. The whole thing is the system
# prompt — kept stable across calls so prompt caches (Anthropic ephemeral
# cache, OpenAI implicit caching) get a high hit rate. Per-message
# variability lives in the user message only.
_SYSTEM_PROMPT_BASE = """\
You are the triage classifier and thread-state maintainer for the
mailbox owner. You will be given:
  1. A list of destination folders, each with an id + description
     (already retrieved by a BM25 search over the mailbox's taxonomy).
  2. The NEW inbound email (sender, subject, body).
  3. Optionally: prior thread context — either a compact PRIOR SUMMARY
     STATE (when the thread has been seen before) or older messages
     (when seeding a thread from scratch).

Your job has two parts, output together as a SINGLE JSON object:

PART 1 — Folder verdict.
  Pick the SINGLE destination folder this email belongs in.
  Return its `id` verbatim in the "folder" field. The id must be copied
  exactly from one of the retrieved folders — no prose, no markdown, no
  quoting, no transformations.

PART 2 — Downstream consumers.
  See the consumer instructions below. Each consumer claims its own
  JSON fields. Produce every field a consumer requests.

Hard rules:
  - Return ONE JSON OBJECT and nothing else. No prose before or after.
    No markdown fences. No trailing commas.
  - Use null (not empty string) for unknown leaf values in nested objects.
  - Keep keyFacts/timeline/contacts arrays small — only items worth
    surfacing to a human reviewing the thread.
  - "folder" is REQUIRED. The other fields are required by their
    consumers but may be empty arrays / empty strings when there's
    genuinely nothing to record.
"""


def _composed_system_prompt(mailbox_override: str | None) -> str:
    """Per-mailbox prompt override (if any) + base + every consumer fragment."""
    parts: list[str] = []
    if mailbox_override:
        parts.append(mailbox_override.rstrip())
    else:
        parts.append(_SYSTEM_PROMPT_BASE.rstrip())
    for c in CONSUMERS:
        parts.append("")
        parts.append(c.system_instructions.rstrip())

    keys = ["folder", *all_output_keys()]
    schema_hint = (
        "Expected JSON shape (top-level keys, in order): "
        + ", ".join(f'"{k}"' for k in keys)
    )
    parts.append("")
    parts.append(schema_hint)
    return "\n".join(parts)


# User-message template. When prior_summary is provided we feed THAT
# instead of historical thread messages — the cost trick that keeps
# per-update LLM cost constant regardless of thread depth.
_USER_TEMPLATE = """\
# Destination folders (ranked by relevance)
{% for d in documents %}
---
{{ d.content }}
{% endfor %}
---

# Inbound email (NEW message)
From: {{ sender }}
Subject: {{ subject }}
MessageId: {{ message_id or '(unknown)' }}
ReceivedAt: {{ received_at or '(unknown)' }}

{{ body }}

{% if prior_summary %}
# PRIOR SUMMARY STATE (authoritative through the previous message — UPDATE this, do NOT re-derive)
{{ prior_summary }}
{% elif thread %}
# Thread context (older messages, oldest first — only used when no prior summary exists)
{% for m in thread %}
---
From: {{ m.sender }}
At:   {{ m.received }}
{{ m.body }}
{% endfor %}
{% endif %}

# Your output
Return ONE JSON object only.
"""


@dataclass
class Verdict:
    folder: str
    raw: str
    retrieved: list[str]
    # Synct consumer outputs (empty when JSON parsing failed — see `parse_error`).
    summary: str = ""
    key_facts: list[dict] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    contacts: list[dict] = field(default_factory=list)
    parse_error: str | None = None


@lru_cache(maxsize=32)
def _load_hierarchy(path_str: str) -> tuple[Document, ...]:
    with open(path_str, "r", encoding="utf-8") as f:
        data = json.load(f)
    docs: list[Document] = []
    for node in data.get("nodes", []):
        if not node.get("is_leaf"):
            continue
        nid = node.get("id") or node.get("name")
        content = (
            f"id: {nid}\n"
            f"name: {node.get('name')}\n"
            f"description: {node.get('description', '')}"
        )
        docs.append(Document(content=content, meta={"id": nid, "name": node.get("name")}))
    return tuple(docs)


@lru_cache(maxsize=32)
def _build_pipeline(mailbox: str, base_url: str, model: str, api_key: str) -> Pipeline:
    docs = _load_hierarchy(str(hierarchy_path_for(mailbox)))
    store = InMemoryDocumentStore()
    store.write_documents(list(docs))
    retriever = InMemoryBM25Retriever(document_store=store, top_k=3)

    override = None
    pp = prompt_path_for(mailbox)
    if pp is not None:
        override = pp.read_text(encoding="utf-8")
    sys_prompt = _composed_system_prompt(override)

    builder = PromptBuilder(template=_USER_TEMPLATE)
    # Token budget: large enough to fit folder id + ~4-sentence summary
    # + a handful of keyFacts/timeline/contacts entries. Trimming the
    # prompt is cheap relative to truncating a valid JSON mid-array,
    # which forces a re-summarize next pass.
    generator = OpenAIGenerator(
        api_key=Secret.from_token(api_key),
        api_base_url=base_url,
        model=model,
        system_prompt=sys_prompt,
        generation_kwargs={"temperature": 0.1, "max_tokens": 1500},
    )

    p = Pipeline()
    p.add_component("retriever", retriever)
    p.add_component("prompt", builder)
    p.add_component("llm", generator)
    p.connect("retriever.documents", "prompt.documents")
    p.connect("prompt.prompt", "llm.prompt")
    return p


def _compact_prior_summary(prior: dict) -> str:
    """Render a prior ThreadSummary as the compact context block the
    LLM sees on subsequent updates. Plain text > JSON here — easier for
    smaller models to read, and the LLM emits fresh JSON regardless."""
    out: list[str] = []
    s = (prior.get("summary") or "").strip()
    if s:
        out.append(f"Summary: {s}")
    msg_count = prior.get("message_count")
    if msg_count:
        out.append(f"Messages seen so far: {msg_count}")
    key_facts = prior.get("key_facts") or []
    if key_facts:
        out.append("Key facts:")
        for kf in key_facts[:20]:
            label = kf.get("label", "?")
            value = kf.get("value", "")
            out.append(f"  - {label}: {value}")
    timeline = prior.get("timeline") or []
    if timeline:
        out.append("Timeline so far:")
        for ev in timeline[-15:]:  # most recent 15
            date = ev.get("date", "?")
            event = ev.get("event", "")
            out.append(f"  - {date}: {event}")
    contacts = prior.get("contacts") or []
    if contacts:
        out.append("Contacts known:")
        for ct in contacts[:20]:
            name = ct.get("name") or ct.get("email") or "(unknown)"
            org = ct.get("organization") or ""
            role = ct.get("role") or ""
            email = ct.get("email") or ""
            suffix = " · ".join(x for x in [role, org, email] if x)
            out.append(f"  - {name}{(' — ' + suffix) if suffix else ''}")
    return "\n".join(out).strip()


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_llm_json(raw: str) -> tuple[dict | None, str | None]:
    """Best-effort: pull a JSON object out of the model's reply.
    Returns (parsed_dict, error_message). Tolerates code fences, leading
    'json:' labels, and trailing prose. None + reason on hard failure."""
    if not raw:
        return None, "empty reply"
    txt = raw.strip()
    # Strip ```json ... ``` fences if the model produced any.
    if txt.startswith("```"):
        txt = txt.strip("`")
        # remove an optional leading language tag like "json\n"
        nl = txt.find("\n")
        if nl != -1 and txt[:nl].strip().lower() in {"json", ""}:
            txt = txt[nl + 1:]
        txt = txt.strip("` \n")
    # Direct parse first.
    try:
        v = json.loads(txt)
        if isinstance(v, dict):
            return v, None
    except json.JSONDecodeError:
        pass
    # Fallback: first {...} block by greedy outer match.
    m = _JSON_OBJECT_RE.search(txt)
    if m:
        try:
            v = json.loads(m.group(0))
            if isinstance(v, dict):
                return v, None
        except json.JSONDecodeError as e:
            return None, f"json decode: {e}"
    return None, "no JSON object in reply"


def classify(
    mailbox: str,
    sender: str,
    subject: str,
    body: str,
    thread: list[dict[str, Any]] | None = None,
    prior_summary: dict | None = None,
    message_id: str | None = None,
    received_at: str | None = None,
    cfg: LLMConfig | None = None,
) -> Verdict:
    """One LLM call → folder verdict + every consumer's slice.

    When `prior_summary` is provided, `thread` is IGNORED (the prior
    summary IS the compressed thread context — that's the cost trick).
    When `prior_summary` is None, `thread` is used to seed a brand-new
    thread's first summary.
    """
    cfg = cfg or LLMConfig.from_env()
    pipeline = _build_pipeline(mailbox, cfg.base_url, cfg.model, cfg.api_key)

    query = f"From: {sender}\nSubject: {subject}\n\n{body[:4000]}"
    prior_text = _compact_prior_summary(prior_summary) if prior_summary else ""

    result = pipeline.run({
        "retriever": {"query": query},
        "prompt": {
            "sender": sender,
            "subject": subject,
            "body": body[:8000],
            "message_id": message_id or "",
            "received_at": received_at or "",
            "thread": [] if prior_text else (thread or []),
            "prior_summary": prior_text,
        },
    })

    raw = result["llm"]["replies"][0].strip()
    retrieved_ids = [
        d.meta.get("id")
        for d in (result.get("retriever", {}).get("documents") or [])
    ]

    parsed, err = _parse_llm_json(raw)
    if parsed is None:
        # JSON parse failed — recover what we can. Treat the raw reply as
        # a single-line folder id (the pre-multi-consumer behavior) so the
        # classifier still moves the email even if the summary slice is
        # absent.
        folder = _legacy_folder_from_raw(raw)
        return Verdict(
            folder=folder, raw=raw, retrieved=retrieved_ids,
            parse_error=err or "parse failed",
        )

    folder = str(parsed.get("folder") or "").strip().strip("`'\" \n\t")
    if not folder:
        folder = _legacy_folder_from_raw(raw)

    def _as_list(v: Any) -> list[dict]:
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
        return []

    return Verdict(
        folder=folder,
        raw=raw,
        retrieved=retrieved_ids,
        summary=str(parsed.get("summary") or "").strip(),
        key_facts=_as_list(parsed.get("keyFacts")),
        timeline=_as_list(parsed.get("timeline")),
        contacts=_as_list(parsed.get("contacts")),
    )


def _legacy_folder_from_raw(raw: str) -> str:
    """Pre-JSON behavior: treat raw as a folder id. Recovers from models
    that ignore the JSON instruction and just dump the folder name."""
    cleaned = raw.strip("`'\" \n\t")
    if cleaned.lower().startswith("id:"):
        cleaned = cleaned[3:].strip()
    if "\n" in cleaned:
        for line in cleaned.splitlines():
            line = line.strip()
            if line:
                cleaned = line
                break
    return cleaned


def list_folders(mailbox: str) -> list[dict[str, Any]]:
    """Leaf folders for the mailbox's taxonomy (for the UI dropdown)."""
    with open(hierarchy_path_for(mailbox), "r", encoding="utf-8") as f:
        data = json.load(f)
    return [n for n in data.get("nodes", []) if n.get("is_leaf")]


def invalidate_cache() -> None:
    _load_hierarchy.cache_clear()
    _build_pipeline.cache_clear()
