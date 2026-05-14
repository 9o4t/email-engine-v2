"""
classifier.py — RAG-over-JSON folder classifier.

Same architecture shxntanu's hackathon entry won with (BM25 retrieval
over a JSON taxonomy + LLM picks the best leaf), repointed at folders
+ per-mailbox.

  1. Per-mailbox taxonomy. data/hierarchies/<sanitized_mailbox>.json
     with _default.json fallback. Editing JSON IS the training loop.

  2. OpenAI-compatible LLM client. Point LLM_BASE_URL at Ollama, OpenAI,
     OpenRouter, vLLM, whatever speaks /v1/chat/completions.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from haystack import Document, Pipeline
from haystack.components.builders.prompt_builder import PromptBuilder
from haystack.components.retrievers.in_memory import InMemoryBM25Retriever
from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack_integrations.components.generators.openai import OpenAIGenerator
from haystack.utils import Secret

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


# --- Pipeline ---------------------------------------------------------------

_SYSTEM_PROMPT_FALLBACK = """\
You are the triage classifier for the mailbox owner. You will be given:
  1. A list of destination folders, each with a description.
  2. An inbound email (sender, subject, body, optionally thread context).

Your job is to pick the SINGLE destination folder this email belongs in.
Return ONLY the folder's `id` field — nothing else, no prose, no
markdown, no quotes. The id must be copied verbatim from the
retrieved folder list.
"""


_USER_TEMPLATE = """\
# Destination folders (ranked by relevance)
{% for d in documents %}
---
{{ d.content }}
{% endfor %}
---

# Inbound email
From: {{ sender }}
Subject: {{ subject }}

{{ body }}

{% if thread %}
# Thread context (older messages, oldest first)
{% for m in thread %}
---
From: {{ m.sender }}
At:   {{ m.received }}
{{ m.body }}
{% endfor %}
{% endif %}

# Your verdict
Return ONLY the destination folder's id, verbatim.
"""


@dataclass
class Verdict:
    folder: str
    raw: str
    retrieved: list[str]


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

    sys_prompt = _SYSTEM_PROMPT_FALLBACK
    pp = prompt_path_for(mailbox)
    if pp is not None:
        sys_prompt = pp.read_text(encoding="utf-8")

    builder = PromptBuilder(template=_USER_TEMPLATE)
    generator = OpenAIGenerator(
        api_key=Secret.from_token(api_key),
        api_base_url=base_url,
        model=model,
        system_prompt=sys_prompt,
        generation_kwargs={"temperature": 0.1, "max_tokens": 64},
    )

    p = Pipeline()
    p.add_component("retriever", retriever)
    p.add_component("prompt", builder)
    p.add_component("llm", generator)
    p.connect("retriever.documents", "prompt.documents")
    p.connect("prompt.prompt", "llm.prompt")
    return p


def classify(
    mailbox: str,
    sender: str,
    subject: str,
    body: str,
    thread: list[dict[str, Any]] | None = None,
    cfg: LLMConfig | None = None,
) -> Verdict:
    cfg = cfg or LLMConfig.from_env()
    pipeline = _build_pipeline(mailbox, cfg.base_url, cfg.model, cfg.api_key)
    query = f"From: {sender}\nSubject: {subject}\n\n{body[:4000]}"

    result = pipeline.run({
        "retriever": {"query": query},
        "prompt": {
            "sender": sender,
            "subject": subject,
            "body": body[:8000],
            "thread": thread or [],
        },
    })

    raw = result["llm"]["replies"][0].strip()
    cleaned = raw.strip("`'\" \n\t")
    if cleaned.lower().startswith("id:"):
        cleaned = cleaned[3:].strip()
    if "\n" in cleaned:
        for line in cleaned.splitlines():
            line = line.strip()
            if line:
                cleaned = line
                break
    retrieved_ids = [
        d.meta.get("id")
        for d in (result.get("retriever", {}).get("documents") or [])
    ]
    return Verdict(folder=cleaned, raw=raw, retrieved=retrieved_ids)


def list_folders(mailbox: str) -> list[dict[str, Any]]:
    """Leaf folders for the mailbox's taxonomy (for the UI dropdown)."""
    with open(hierarchy_path_for(mailbox), "r", encoding="utf-8") as f:
        data = json.load(f)
    return [n for n in data.get("nodes", []) if n.get("is_leaf")]


def invalidate_cache() -> None:
    _load_hierarchy.cache_clear()
    _build_pipeline.cache_clear()
