"""
consumers.py — registry of downstream prompt fragments.

The classifier makes ONE LLM call per processed message. The base prompt
asks for a folder verdict; each registered consumer fragment appends its
own instructions + claims its own keys in the structured JSON response.

Today's only consumer is `synct` (ThreadSummary for synct_utility). A
later session will add a `portals` fragment that extracts actionable
items. Adding a consumer = appending a ConsumerFragment to CONSUMERS;
nothing else in the loop changes.

Why this pattern: every consumer benefits from one LLM call per message
(cost is bounded). Splitting into per-consumer calls is the obvious
naive thing and the obvious wrong thing.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConsumerFragment:
    name: str                       # short id, for logs
    system_instructions: str        # appended to the classifier's system prompt
    output_schema_keys: tuple[str, ...]  # JSON keys this consumer reads from the response


# --- synct: ThreadSummary ----------------------------------------------------

_SYNCT_INSTRUCTIONS = """\
SYNCT — Thread summary (downstream consumer).

In addition to the folder verdict, maintain a rolling per-thread summary
that downstream apps query for human context. Produce these fields:

  - "summary":   2-4 sentence prose describing the thread's CURRENT state
                 (not a changelog of edits — a snapshot).
  - "keyFacts":  list of {"label", "value"} pairs worth surfacing
                 (deal name, renewal date, contract amount, customer id,
                 ticket number, etc.). Keep stable facts; update values
                 when revised.
  - "timeline":  list of {"date", "event", "messageId"} for notable events
                 (initial inquiry, quote sent, objection raised, decision
                 made, etc.). Append new events; never remove old ones.
                 "date" can be an ISO date or a natural phrase from the
                 message. "messageId" is the id of the message that
                 introduced the event when known, else null.
  - "contacts":  list of {"name", "email", "role", "organization", "phone"}
                 for people in the thread. ALWAYS include the latest
                 message's sender. Pull role/organization/phone from
                 signatures when present. Use null for unknown fields.

When PRIOR SUMMARY STATE is provided below, treat it as the authoritative
state through the previous message. UPDATE it from THIS new message only:
append new timeline events, merge/refresh contacts in place, revise
keyFacts whose values changed, and rewrite the "summary" prose to reflect
the thread's current state. Do not re-derive from full thread history —
the prior summary already encodes it.
"""

SYNCT_FRAGMENT = ConsumerFragment(
    name="synct",
    system_instructions=_SYNCT_INSTRUCTIONS,
    output_schema_keys=("summary", "keyFacts", "timeline", "contacts"),
)


# Registered fragments, in the order they appear in the system prompt.
CONSUMERS: tuple[ConsumerFragment, ...] = (SYNCT_FRAGMENT,)


def all_output_keys() -> list[str]:
    """Every JSON key any registered consumer claims, in declared order.
    Used to build the expected-shape hint at the end of the system prompt."""
    keys: list[str] = []
    for c in CONSUMERS:
        for k in c.output_schema_keys:
            if k not in keys:
                keys.append(k)
    return keys
