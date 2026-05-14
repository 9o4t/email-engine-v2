"""
lib/apply.py — execute the verdict on a message, honoring apply_mode.

  apply_mode == 'tag'          → only set category; message stays in INBOX.
  apply_mode == 'move'         → only move; no category set.
  apply_mode == 'tag_and_move' → both (what email-engine v1 always did).

The tag-only mode is the new flexibility: if your client (Outlook,
Gmail) shows category-filtered "smart folders", you can leave messages
in the inbox and just tag them, getting filterable views without folder
hierarchy maintenance. Toggle from the web UI per-mailbox; the change
takes effect on the next classification.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from providers.base import Provider

log = logging.getLogger(__name__)


APPLY_MODES = ("tag", "move", "tag_and_move")


@dataclass
class ApplyResult:
    apply_mode: str
    tagged: bool
    moved: bool
    new_message_id: str
    error: str | None = None


def apply_verdict(
    provider: Provider,
    *,
    message_id: str,
    src_folder: str,
    dest_folder: str,
    category: str | None,
    apply_mode: str,
    existing_categories: list[str] | None = None,
    all_rule_categories: list[str] | None = None,
) -> ApplyResult:
    """Apply the verdict.

    `category` is the tag string to set (usually equals dest_folder, but
    they're separate args so a future taxonomy could decouple them).
    `existing_categories` lets us strip OTHER rule tags before applying
    the new one — same hygiene email-engine v1 enforced — so a message
    doesn't accumulate stale category labels across reclassifications.
    `all_rule_categories` is the full list of tags this engine manages;
    anything in that list gets stripped before the new category is added.
    """
    if apply_mode not in APPLY_MODES:
        return ApplyResult(apply_mode, False, False, message_id,
                           error=f"unknown apply_mode {apply_mode!r}")

    do_tag = apply_mode in ("tag", "tag_and_move") and category
    do_move = apply_mode in ("move", "tag_and_move") and dest_folder

    # Step 1: tag (if requested). Replace the rule-managed tag, preserve
    # everything else the user might have set manually.
    tagged = False
    err: str | None = None
    if do_tag:
        existing = list(existing_categories or [])
        preserved = (
            [c for c in existing if c not in (all_rule_categories or [])]
            if all_rule_categories else existing
        )
        final = preserved + ([category] if category not in preserved else [])
        try:
            provider.set_categories(message_id, final)
            tagged = True
        except Exception as e:
            log.exception("set_categories failed: %s", e)
            err = f"tag: {e}"

    # Step 2: move (if requested AND src != dest). Move returns the new id —
    # Graph and Gmail-via-IMAP both mint fresh handles on move.
    moved = False
    new_id = message_id
    if do_move and src_folder != dest_folder and err is None:
        try:
            new_id = provider.move_message(message_id, dest_folder) or message_id
            moved = new_id != message_id or src_folder != dest_folder
            # If the provider returned the same id, we still treat it as moved
            # because the source/dest differ — some providers (Graph) ALWAYS
            # return a new id, some (IMAP) may return our synthetic.
            if not moved:
                moved = True
        except Exception as e:
            log.exception("move_message failed: %s", e)
            err = f"move: {e}"

    return ApplyResult(
        apply_mode=apply_mode,
        tagged=tagged,
        moved=moved,
        new_message_id=new_id,
        error=err,
    )
