"""Deterministic, explainable scoring of rules against categories."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from .features import Features, name_variants
from .parse import Rule

FIELDS = {"name", "tags", "description", "reference", "author", "strings", "condition",
          "targets", "name_prefix"}
SEVERITIES = ("threat", "suspicious", "info")


def _term_regex(term: str) -> re.Pattern:
    """Word-bounded match; a trailing * allows any word ending ('pirat*')."""
    t = term.lower().strip()
    star = t.endswith("*")
    t = t.rstrip("*")
    body = re.escape(t).replace(r"\ ", r"[ _\-]?")
    return re.compile(r"(?<![a-z0-9])" + body + (r"[a-z0-9]*" if star else r"(?![a-z0-9])"))


@dataclass
class Signal:
    weight: int
    fields: list[str]
    terms: list[str]
    label: str = ""
    _res: list[re.Pattern] = field(default_factory=list, repr=False)

    def __post_init__(self):
        bad = set(self.fields) - FIELDS
        if bad:
            raise ValueError(f"unknown signal field(s) {sorted(bad)}; allowed: {sorted(FIELDS)}")
        self._res = [_term_regex(t) for t in self.terms]

    def match(self, f: Features) -> list[str]:
        hits: list[str] = []
        for fld in self.fields:
            if fld == "name_prefix":
                names = name_variants(f.name)
                hits += [f"name starts '{t}'" for t in self.terms
                         if any(n.startswith(t.lower()) for n in names)]
                continue
            text = f.field(fld)
            if not text:
                continue
            if fld == "strings":  # plain substring: strings hold paths, commands, etc.
                hits += [f"{fld}: '{t}'" for t in self.terms if t.lower().rstrip("*") in text]
            else:
                hits += [f"{fld}: '{t}'" for t, rx in zip(self.terms, self._res) if rx.search(text)]
        return hits


@dataclass
class Category:
    name: str
    description: str
    kind: str = "detection"
    include_score: int = 4
    review_score: int = 2
    targets_allow: list[str] = field(default_factory=list)
    targets_deny: list[str] = field(default_factory=list)
    severity_default: str = "suspicious"
    severity_cap: str | None = None
    label: str | None = None
    signals: list[Signal] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    editions: list[str] = field(default_factory=lambda: ["standard"])

    def fingerprint(self) -> str:
        blob = json.dumps({"d": self.description, "s": [(s.weight, s.fields, s.terms) for s in self.signals],
                           "a": self.targets_allow, "x": self.targets_deny,
                           "t": [self.include_score, self.review_score]}, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]


def load_categories(data: dict) -> dict[str, Category]:
    defaults = data.get("defaults", {})
    cats: dict[str, Category] = {}
    for name, c in data.get("categories", {}).items():
        sigs = [Signal(weight=int(s["weight"]), fields=list(s["fields"]), terms=list(s["terms"]),
                       label=s.get("label", "")) for s in c.get("signals", [])]
        cat = Category(
            name=name, description=c["description"].strip(), kind=c.get("kind", "detection"),
            include_score=int(c.get("include_score", defaults.get("include_score", 4))),
            review_score=int(c.get("review_score", defaults.get("review_score", 2))),
            targets_allow=list(c.get("targets_allow", defaults.get("targets_allow", []))),
            targets_deny=list(c.get("targets_deny", defaults.get("targets_deny", []))),
            severity_default=c.get("severity_default", "suspicious"),
            severity_cap=c.get("severity_cap"), label=c.get("label"), signals=sigs,
            aliases=[str(a) for a in c.get("aliases", [])],
            editions=[str(e) for e in c.get("editions", defaults.get("editions", ["standard"]))])
        for s in (cat.severity_default, cat.severity_cap):
            if s is not None and s not in SEVERITIES:
                raise ValueError(f"category {name}: severity must be one of {SEVERITIES}")
        cats[name] = cat
    return cats


@dataclass
class Decision:
    category: str
    score: int
    band: str           # include | review | below | not_applicable | dropped
    reasons: list[str]
    decided_by: str = "rules"   # rules | llm | demotion
    llm_reason: str | None = None
    llm_confidence: float | None = None


def score(rule: Rule, f: Features, cat: Category) -> Decision:
    allow = set(cat.targets_allow) | {"any"}
    targets = set(f.targets)
    if targets & set(cat.targets_deny) and not (targets & allow):
        return Decision(cat.name, 0, "not_applicable",
                        [f"targets {sorted(targets)} are outside this category"])
    if cat.targets_allow and not (targets & allow):
        return Decision(cat.name, 0, "not_applicable",
                        [f"targets {sorted(targets)} not in {cat.targets_allow}"])
    total, reasons = 0, []
    for s in cat.signals:
        hits = s.match(f)
        if hits:
            total += s.weight
            shown = ", ".join(hits[:4]) + (f" (+{len(hits) - 4} more)" if len(hits) > 4 else "")
            reasons.append(f"{s.weight:+d} {s.label + ': ' if s.label else ''}{shown}")
    band = ("include" if total >= cat.include_score
            else "review" if total >= cat.review_score else "below")
    return Decision(cat.name, total, band, reasons)


# ---------------------------------------------------------------- severity

PREFIX_SEVERITY = [
    ("threat", ("mal_", "apt_", "crime_", "ransom", "troj_", "trojan_", "miner_", "stealer_",
                "backdoor_", "rat_")),
    ("suspicious", ("susp_", "hktl_", "hacktool_", "expl_", "exploit_", "webshell_", "gen_", "obfus", "indicator_")),
    ("info", ("pua_", "info_", "vuln_", "test_", "pup_", "packer_", "pe_", "file_", "lnk_", "tool_",
              "riskware_", "adware_")),
]


def propose_severity(rule: Rule, cat: Category) -> tuple[str, str]:
    raw = rule.meta.get("score") or rule.meta.get("severity") or ""
    sev, why = None, ""
    m = re.match(r"\s*(\d{1,3})\b", raw)
    if m:
        n = int(m.group(1))
        sev = "threat" if n >= 75 else "suspicious" if n >= 60 else "info"
        why = f"meta score {n}"
    elif raw.lower() in ("critical", "high", "malicious"):
        sev, why = "threat", f"meta severity {raw}"
    elif raw.lower() in ("medium", "suspicious"):
        sev, why = "suspicious", f"meta severity {raw}"
    elif raw.lower() in ("low", "informational", "info"):
        sev, why = "info", f"meta severity {raw}"
    if sev is not None:
        # An explicit SUSP_/HKTL_/PUA_ name beats a blanket score (YARA Forge gives most rules 75).
        names = name_variants(rule.name)
        for s, prefixes in PREFIX_SEVERITY[1:]:
            if any(n.startswith(prefixes) for n in names) and SEVERITIES.index(s) > SEVERITIES.index(sev):
                sev, why = s, f"name prefix (lowered from {why})"
                break
    if sev is None:
        tags = {t.lower() for t in rule.tags}
        if "malicious" in tags or "malware" in tags:
            sev, why = "threat", "tagged malicious"
        elif "suspicious" in tags or "hacktool" in tags:
            sev, why = "suspicious", "tagged suspicious"
    if sev is None:
        names = name_variants(rule.name)
        for s, prefixes in PREFIX_SEVERITY:
            if any(n.startswith(prefixes) for n in names):
                sev, why = s, "name prefix"
                break
    if sev is None:
        sev, why = cat.severity_default, "category default"
    if cat.severity_cap and SEVERITIES.index(sev) < SEVERITIES.index(cat.severity_cap):
        why += f", capped to {cat.severity_cap} by {cat.name}"
        sev = cat.severity_cap
    return sev, why


# ---------------------------------------------------------------- demotions

@dataclass
class Demotion:
    rule: str
    action: str           # drop | info
    reason: str
    source: str | None = None
    category: str | None = None

    def applies(self, rule: Rule, cat: str) -> bool:
        return (self.rule == rule.name and (self.source in (None, rule.source))
                and (self.category in (None, cat)))


def load_demotions(data: dict) -> list[Demotion]:
    out = []
    for d in data.get("demote", []):
        if d.get("action") not in ("drop", "info"):
            raise ValueError(f"demotion for {d.get('rule')}: action must be 'drop' or 'info'")
        if not d.get("reason"):
            raise ValueError(f"demotion for {d.get('rule')}: a reason is required")
        out.append(Demotion(rule=d["rule"], action=d["action"], reason=d["reason"],
                            source=d.get("source"), category=d.get("category")))
    return out
