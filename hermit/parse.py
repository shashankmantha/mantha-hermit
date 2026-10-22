"""Find, parse and compile-check community YARA rules.

Rule files are untrusted text. They are only parsed and compiled, never run.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path

import plyara
import plyara.utils
import yara_x

RULE_EXTENSIONS = {".yar", ".yara", ".rule", ".rules"}
IMPORT_RE = re.compile(r'^\s*import\s+"([A-Za-z0-9_]+)"', re.M)
INCLUDE_RE = re.compile(r'^\s*include\s+"', re.M)

# External variables used by LOKI/THOR-style rules. The scanner must set them per file
# (Mantha Ray's YARA-X stage: scanner.set_global(...)); hermit defines them so these rules
# compile, and records which rules need them.
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}


@dataclass
class Source:
    name: str
    root: Path
    commit: str | None = None
    origin: str | None = None
    license: str = "unknown"
    license_file: str | None = None


@dataclass
class Rule:
    source: str
    relpath: str
    name: str
    text: str
    imports: list[str]
    tags: list[str]
    scopes: list[str]
    meta: dict[str, str]
    strings: list[dict]
    condition: str
    deps: list[str]
    sha256: str
    compile_ok: bool = True
    compile_error: str | None = None
    duplicate_of: str | None = None
    externals: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.source}|{self.relpath}|{self.name}"

    @property
    def is_private(self) -> bool:
        return "private" in self.scopes

    @property
    def is_global(self) -> bool:
        return "global" in self.scopes

    def to_cache(self) -> dict:
        return asdict(self)


@dataclass
class RuleFile:
    source: str
    relpath: str
    path: Path
    text: str
    imports: list[str]
    rules: list[Rule] = field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------- sources

LICENSE_PATTERNS = [
    ("DRL-1.1", re.compile(r"detection rule license", re.I)),
    ("CC0-1.0", re.compile(r"\bCC0\b|creative commons zero|public domain dedication", re.I)),
    ("Elastic-2.0", re.compile(r"elastic license", re.I)),
    ("CC-BY-NC", re.compile(r"creative commons.*non-?commercial|by-nc", re.I | re.S)),
    ("CC-BY", re.compile(r"creative commons attribution", re.I)),
    ("GPL-3.0", re.compile(r"gnu general public license.*version 3", re.I | re.S)),
    ("GPL-2.0", re.compile(r"gnu general public license.*version 2", re.I | re.S)),
    ("Apache-2.0", re.compile(r"apache license", re.I)),
    ("MIT", re.compile(r"permission is hereby granted, free of charge", re.I)),
    ("BSD", re.compile(r"redistribution and use in source and binary forms", re.I)),
]


def detect_license(root: Path) -> tuple[str, str | None]:
    candidates = sorted(
        p for p in root.iterdir()
        if p.is_file() and re.match(r"(license|licence|copying)", p.name, re.I)
    ) if root.is_dir() else []
    for p in candidates:
        try:
            head = p.read_text(errors="replace")[:6000]
        except OSError:
            continue
        for spdx, pat in LICENSE_PATTERNS:
            if pat.search(head):
                return spdx, p.name
        return "unrecognised", p.name
    return "unknown", None


def git_commit(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=20)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def describe_source(name: str, root: Path) -> Source:
    src = Source(name=name, root=root)
    src.license, src.license_file = detect_license(root)
    src.commit = git_commit(root)
    if src.commit:
        try:
            out = subprocess.run(["git", "-C", str(root), "remote", "get-url", "origin"],
                                 capture_output=True, text=True, timeout=20)
            src.origin = out.stdout.strip() or None
        except (OSError, subprocess.SubprocessError):
            pass
    marker = root / ".hermit-source.json"
    if not marker.is_file():
        marker = root / ".rulesort-source.json"  # sources fetched before the rename
    if marker.is_file():
        try:
            info = json.loads(marker.read_text())
            src.origin = info.get("origin")
            src.commit = src.commit or info.get("commit") or info.get("sha256")
        except (OSError, ValueError):
            pass
    return src


def iter_rule_files(src: Source, exclude_globs: list[str]):
    for p in sorted(src.root.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        if p.suffix.lower() not in RULE_EXTENSIONS:
            continue
        rel = p.relative_to(src.root).as_posix()
        if any(part.startswith(".") for part in rel.split("/")):
            continue
        if any(fnmatch.fnmatch(rel, g) for g in exclude_globs):
            continue
        yield p, rel


# ---------------------------------------------------------------- parsing

def _norm_hash(text: str) -> str:
    return hashlib.sha256(" ".join(text.split()).encode()).hexdigest()


def _meta_dict(entries) -> dict[str, str]:
    meta: dict[str, str] = {}
    for item in entries or []:
        for k, v in item.items():
            k = str(k).lower()
            v = str(v)
            meta[k] = f"{meta[k]} | {v}" if k in meta else v
    return meta


def parse_file(src: Source, path: Path, rel: str, cache) -> RuleFile:
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    rf = RuleFile(source=src.name, relpath=rel, path=path, text=text,
                  imports=sorted(set(IMPORT_RE.findall(text))))
    file_hash = hashlib.sha256(raw).hexdigest()
    cached = cache.get_parse(file_hash) if cache else None
    if cached is not None:
        rf.rules = [Rule(**r) for r in cached["rules"]]
        rf.error = cached["error"]
        for r in rf.rules:
            r.source, r.relpath = src.name, rel
        return rf

    if INCLUDE_RE.search(text):
        rf.error = "file uses include directives (not supported; rules dropped)"
    else:
        try:
            parsed = plyara.Plyara().parse_string(text)
        except Exception as exc:  # plyara raises several types
            parsed = []
            rf.error = f"parse error: {exc}"[:400]
        lines = text.splitlines()
        line_owner: dict[int, int] = {}
        for p in parsed:
            for ln in (p.get("start_line"), p.get("stop_line")):
                if ln:
                    line_owner[ln] = line_owner.get(ln, 0) + 1
        names = {p["rule_name"] for p in parsed}
        for p in parsed:
            s, e = p.get("start_line"), p.get("stop_line")
            shared = line_owner.get(s, 0) > 1 or line_owner.get(e, 0) > 1
            if s and e and not shared:
                body = "\n".join(lines[s - 1:e])
            else:
                body = plyara.utils.rebuild_yara_rule(p)
            cond_terms = p.get("condition_terms", [])
            deps = sorted({t for t in cond_terms if t in names and t != p["rule_name"]})
            rf.rules.append(Rule(
                source=src.name, relpath=rel, name=p["rule_name"], text=body,
                imports=sorted(set(p.get("imports", [])) | set(rf.imports)),
                tags=list(p.get("tags", [])), scopes=list(p.get("scopes", [])),
                meta=_meta_dict(p.get("metadata")),
                strings=[{"name": x.get("name"), "type": x.get("type"),
                          "value": str(x.get("value", ""))[:400]}
                         for x in p.get("strings", [])],
                condition=" ".join(str(t) for t in cond_terms),
                deps=deps, sha256=_norm_hash(body),
                externals=sorted({t for t in cond_terms if t in EXTERNALS})))
        compile_check(rf)
    if cache:
        cache.put_parse(file_hash, {"rules": [r.to_cache() for r in rf.rules],
                                    "error": rf.error})
    return rf


def closure(rule: Rule, by_name: dict[str, Rule]) -> list[Rule]:
    """The rule plus every rule it references (transitively), in file order."""
    seen: dict[str, Rule] = {}
    stack = [rule]
    while stack:
        r = stack.pop()
        if r.name in seen:
            continue
        seen[r.name] = r
        stack.extend(by_name[d] for d in r.deps if d in by_name)
    return list(seen.values())


def subset_text(rf: RuleFile, wanted: list[Rule]) -> str:
    """Rule-file text holding `wanted`, their dependencies and the file's global rules."""
    by_name = {r.name: r for r in rf.rules}
    keep: set[str] = {r.name for r in rf.rules if r.is_global}
    for r in wanted:
        keep.update(x.name for x in closure(r, by_name))
    for g in [r for r in rf.rules if r.name in keep and r.is_global]:
        keep.update(x.name for x in closure(g, by_name))
    imports = sorted({i for r in rf.rules if r.name in keep for i in r.imports} | set(rf.imports))
    parts = [f'import "{i}"' for i in imports]
    parts += [r.text for r in rf.rules if r.name in keep]
    return "\n\n".join(parts) + "\n"


def new_compiler() -> "yara_x.Compiler":
    c = yara_x.Compiler()
    for name, value in EXTERNALS.items():
        c.define_global(name, value)
    return c


def _compile(text: str) -> str | None:
    try:
        c = new_compiler()
        c.add_source(text)
        c.build()
        return None
    except yara_x.CompileError as exc:
        return str(exc).strip().splitlines()[0][:300] if str(exc).strip() else "compile error"
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"[:300]


def compile_check(rf: RuleFile) -> None:
    if not rf.rules:
        return
    if _compile(subset_text(rf, rf.rules)) is None:
        return
    for r in rf.rules:
        err = _compile(subset_text(rf, [r]))
        r.compile_ok = err is None
        r.compile_error = err


def load_rules(sources: list[Source], exclude_globs: list[str], cache, log) -> tuple[list[RuleFile], list[dict]]:
    files: list[RuleFile] = []
    problems: list[dict] = []
    for src in sources:
        n_before = len(files)
        for path, rel in iter_rule_files(src, exclude_globs):
            rf = parse_file(src, path, rel, cache)
            if rf.error:
                problems.append({"source": src.name, "file": rel, "error": rf.error})
            files.append(rf)
        n_rules = sum(len(f.rules) for f in files[n_before:])
        log(f"  {src.name}: {len(files) - n_before} files, {n_rules} rules "
            f"(licence {src.license}, {src.commit[:12] if src.commit else 'no commit'})")
    # cross-source duplicates: identical rule bodies keep the first copy
    first: dict[str, str] = {}
    for rf in files:
        for r in rf.rules:
            if r.sha256 in first:
                r.duplicate_of = first[r.sha256]
            else:
                first[r.sha256] = r.key
    return files, problems
