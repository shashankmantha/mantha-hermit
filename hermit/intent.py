"""Understand a plain-English request without the model (used when Ollama is off or unsure).

Covers the common shapes: "add/include/update ... new rules ... <pack or alias>",
"remove <RuleName> from <pack>", "what changed in <pack> since <date>".
"""
from __future__ import annotations

import re
from datetime import date, timedelta

from .llm import IntentError, validate_intent

REMOVE_RE = re.compile(r"\b(remove|delete|drop|take\s+out|exclude|get\s+rid\s+of)\b", re.I)
ADD_RE = re.compile(r"\b(add|include|update|pull\s+in|bring\s+in|import|refresh|put)\b", re.I)
REPORT_RE = re.compile(r"\b(what\s+changed|report|show|status|summar\w*|what'?s\s+in|how\s+many|list\s+(the|all|what))\b|^\s*(what|which|how)\b", re.I)
ALL_RE = re.compile(r"\b(all|every|everything|any)\b", re.I)
NEW_RE = re.compile(r"\b(new|newest|latest|recent|since\s+last)\b", re.I)
RULE_NAME_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]{2,}\b")


def parse_since(text: str, today: date) -> str | None:
    if m := re.search(r"\b(\d{4}-\d{2}-\d{2})\b", text):
        return m.group(1)
    t = text.lower()
    if "this month" in t:
        return today.replace(day=1).isoformat()
    if "last month" in t:
        return (today.replace(day=1) - timedelta(days=1)).replace(day=1).isoformat()
    if "this week" in t or "last week" in t or "past week" in t:
        return (today - timedelta(days=7)).isoformat()
    if m := re.search(r"\b(?:last|past)\s+(\d{1,3})\s+days?\b", t):
        return (today - timedelta(days=int(m.group(1)))).isoformat()
    if "today" in t:
        return today.isoformat()
    return None


def find_packs(text: str, aliases: dict[str, list[str]]) -> list[tuple[int, str]]:
    """(position, pack) for every pack name or alias mentioned, longest phrases first."""
    low = " " + re.sub(r"[_]", "-", text.lower()) + " "
    phrases = sorted(((a.lower(), p) for p, al in aliases.items() for a in [p, *al]), key=lambda x: -len(x[0]))
    found, taken = [], []
    for phrase, pack in phrases:
        for m in re.finditer(r"(?<![a-z0-9-])" + re.escape(phrase) + r"(?![a-z0-9-])", low):
            if any(s <= m.start() < e for s, e in taken):
                continue
            taken.append((m.start(), m.end()))
            found.append((m.start(), pack))
    return sorted(found)


def parse(request: str, packs: dict[str, str], aliases: dict[str, list[str]], today: date) -> dict:
    t = request.strip()
    action = ("remove" if REMOVE_RE.search(t) else "report" if REPORT_RE.search(t) and not ADD_RE.search(t)
              else "add")
    since = parse_since(t, today)
    selection = "since" if since else ("all" if ALL_RE.search(t) and not NEW_RE.search(t) else "new")
    if action != "add" and not since:
        selection = "all"
    names = [n for n in RULE_NAME_RE.findall(t) if n.lower() not in packs]
    mentioned = find_packs(t, aliases)
    target = topic = None
    # "... to/into/from <pack>" names the target; another mentioned pack is the topic
    for pos, pack in mentioned:
        before = t.lower()[max(0, pos - 8):pos]
        if re.search(r"\b(to|into|in|from|of)\s*$", before):
            target = pack
    if mentioned:
        topic = mentioned[0][1] if mentioned[0][1] != target or len(mentioned) == 1 else mentioned[-1][1]
        target = target or topic
    if not target:
        raise IntentError("couldn't tell which pack this is about; name one of: " + ", ".join(sorted(packs)))
    raw = {"action": action, "selection": selection, "since": since,
           "topic_pack": None if names else topic, "topic_text": None,
           "target_pack": target, "rule_names": names}
    if action == "remove" and not names:
        raise IntentError("without the model, removals need rule names (e.g. remove MAL_Foo from games)")
    return validate_intent(raw, packs, allow_new_pack=False)
