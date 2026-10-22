"""Work out what a rule is about and which kinds of file it can match."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .parse import Rule

# File-type gates found in conditions (lower-cased, whitespace collapsed).
TARGET_CONDITION_PATTERNS: dict[str, list[str]] = {
    "pe": [r"uint16\(0\) == 0x5a4d", r"uint16be\(0\) == 0x4d5a", r"\bpe\.", r"\bdotnet\.",
           r"uint32\(uint32\(0x3c\)\) == 0x0*4550", r"\$mz at 0"],
    "elf": [r"uint32\(0\) == 0x464c457f", r"uint32be\(0\) == 0x7f454c46", r"\belf\."],
    "macho": [r"0xfeedfac[ef]", r"0xcefaedfe", r"0xcffaedfe", r"0xbebafeca", r"\bmacho\."],
    "ole": [r"0xe011cfd0", r"0xd0cf11e0"],
    "pdf": [r"0x46445025", r"0x25504446"],
    "rtf": [r"0x74725c7b", r"0x7b5c7274", r"0x7b5c72"],
    "zip": [r"uint32\(0\) == 0x04034b50", r"uint32be\(0\) == 0x504b0304", r"uint16\(0\) == 0x4b50"],
    "lnk": [r"uint32\(0\) == 0x0*4c\b", r"\blnk\."],
    "android": [r"0x0a786564", r"\bdex\."],
}

# Hints from the rule's name, tags and description.
TARGET_NAME_HINTS: dict[str, list[str]] = {
    "webshell": [r"webshells?", r"web ?shell", r"\bphp\b", r"\baspx?\b", r"\bjsp\b"],
    "ole": [r"maldoc", r"\bvba\b", r"\bmacro", r"\bdocx?\b", r"\bxlsx?\b", r"\bxlsm\b",
            r"\bppt", r"\boffice\b", r"\bole\b"],
    "pdf": [r"\bpdf\b"],
    "rtf": [r"\brtf\b"],
    "email": [r"\beml\b", r"\bemail attachment", r"\bphish"],
    "memory": [r"\bmem\b", r"\bmemory\b", r"in memory", r"memory dump", r"process memory", r"\bmemdump"],
    "android": [r"\bandroid\b", r"\bapk\b", r"\bdex\b"],
    "macho": [r"\bmacos\b", r"\bosx\b", r"\bmac\b", r"\bmacho\b"],
    "lnk": [r"\blnk\b", r"shortcut file"],
    "script": [r"powershell", r"\bps1\b", r"\bvbs\b", r"vbscript", r"jscript", r"\bjs\b",
               r"javascript", r"\bbat\b", r"batch", r"\bhta\b", r"\bbash\b", r"shell ?script",
               r"\bpython\b", r"\blua\b", r"\bnode(js)?\b"],
    "elf": [r"\belf\b", r"\blinux\b"],
    "pe": [r"\bexe\b", r"\bdll\b", r"\bwin(32|64)\b", r"\bpe\b", r"\bdotnet\b", r"\.net\b"],
}

# Hints from string contents (substring, lower-cased).
TARGET_STRING_HINTS: dict[str, list[str]] = {
    "webshell": ["<?php", "<%@", "<asp:", "request.form", "$_post[", "$_get[", "eval($_"],
    "script": ["#!/bin/sh", "#!/bin/bash", "powershell", "wscript.shell", "createobject(",
               "-encodedcommand", "function(", "require('child_process", 'require("child_process'],
    "ole": ["attribute vb_name", "autoopen", "document_open", "workbook_open"],
    "email": ["received: from", "content-type: multipart", "x-mailer:"],
}

_COMPILED_COND = {t: [re.compile(p) for p in ps] for t, ps in TARGET_CONDITION_PATTERNS.items()}
_COMPILED_NAME = {t: [re.compile(p) for p in ps] for t, ps in TARGET_NAME_HINTS.items()}


def normalise_words(s: str) -> str:
    """'MAL_LummaC2_Stealer' -> 'mal lumma c2 stealer' (keeps the joined form too)."""
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)
    s = re.sub(r"([A-Za-z])([0-9])", r"\1 \2", s)
    s = re.sub(r"[_\-/:.,;()\[\]{}\"'|]+", " ", s)
    return " ".join(s.lower().split())


def name_variants(name: str) -> list[str]:
    """'SIGNATURE_BASE_MAL_X' -> [..., 'base_mal_x', 'mal_x']: YARA Forge prefixes the upstream repo."""
    low = name.lower()
    parts = low.split("_")
    return [low] + ["_".join(parts[i:]) for i in range(1, min(4, len(parts)))]


def upstream(rule) -> tuple[str | None, str | None]:
    """(upstream repo, licence URL) from YARA Forge-style metadata, if present."""
    url = rule.meta.get("source_url", "")
    m = re.search(r"github\.com/([^/]+/[^/]+)", url)
    lic = rule.meta.get("license_url") or rule.meta.get("license")
    return (m.group(1) if m else None), (lic if lic and lic != "N/A" else None)


@dataclass
class Features:
    name: str
    name_words: str
    tags: str
    description: str
    reference: str
    author: str
    strings: str
    condition: str
    targets: list[str] = field(default_factory=list)
    target_reasons: list[str] = field(default_factory=list)

    def field(self, name: str) -> str:
        return {
            "name": self.name_words, "tags": self.tags, "description": self.description,
            "reference": self.reference, "author": self.author, "strings": self.strings,
            "condition": self.condition, "targets": " ".join(self.targets),
        }.get(name, "")


def extract(rule: Rule) -> Features:
    meta = rule.meta
    desc = " ".join(meta.get(k, "") for k in ("description", "desc", "info", "malware",
                                              "family", "malware_family", "category",
                                              "threat_name", "malware_type",
                                              "tc_detection_type", "tc_detection_name"))
    strings = " ".join(s["value"] for s in rule.strings if s.get("type") in ("text", "regex"))
    strings = strings.replace("\\\\", "\\").lower()
    cond = " ".join(rule.condition.lower().split())
    cond = re.sub(r"\s*([()\[\]])\s*", r"\1", cond)
    cond = re.sub(r"\s*\.\s*", ".", cond)
    cond = re.sub(r"\s*==\s*", " == ", cond)
    f = Features(
        name=rule.name,
        name_words=f"{normalise_words(rule.name)} {rule.name.lower()}",
        tags=normalise_words(" ".join(rule.tags)),
        description=normalise_words(desc) + " " + desc.lower(),
        reference=meta.get("reference", "").lower(),
        author=meta.get("author", "").lower(),
        strings=strings,
        condition=cond,
    )
    targets: dict[str, str] = {}
    for t, pats in _COMPILED_COND.items():
        for p in pats:
            if p.search(cond):
                targets.setdefault(t, f"condition gate /{p.pattern}/")
    hint_text = f"{f.name_words} {f.tags} {normalise_words(desc)}"
    gated = bool(targets)
    for t, pats in _COMPILED_NAME.items():
        if gated and t in ("pe", "elf"):
            continue  # a real gate beats a name hint
        for p in pats:
            if p.search(hint_text):
                targets.setdefault(t, f"name/description mentions /{p.pattern}/")
                break
    for t, subs in TARGET_STRING_HINTS.items():
        for s in subs:
            if s in strings:
                targets.setdefault(t, f"string contains '{s}'")
                break
    if not targets:
        targets["any"] = "no file-type gate"
    f.targets = sorted(targets)
    f.target_reasons = [f"{t}: {why}" for t, why in sorted(targets.items())]
    return f
