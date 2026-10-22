"""The live rule packs.

packs/<id>/                     a pack folder in bundle contract v1 layout (see contract.py)
  pack.json, severities.json, rules/<namespace>.yar, pack.yarx
  .hermit/                      Hermit's own state, never shipped
    state.json                  entries (rule text, severity, status, why), excluded rules
    baseline.json               every rule (key -> hash) this pack has considered ("new" = new to it)
    CHANGELOG.md, history.jsonl one entry per version
    history/vNNNN/              state.json + baseline.json of earlier versions (for rollback)

Entries are self-contained (rule text, the rules it depends on, imports), so a pack can be
rebuilt or rolled back even if the upstream source has since changed or deleted a rule.
"""
from __future__ import annotations

import json
import re
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yara_x

from . import __version__
from . import contract
from .parse import Rule, RuleFile, closure, new_compiler

KEEP_VERSIONS = 30


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def namespace(source: str, relpath: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", f"{source}__{relpath}")


def safe_rel(rel: str) -> str:
    return re.sub(r"[^A-Za-z0-9._/-]", "_", rel).lstrip("/").replace("..", "_")


def effective_severity(e: dict) -> str:
    if e.get("status") == "probation" or e.get("uncertain") or e.get("demoted"):
        return "info"
    return e["proposed_severity"]


def make_entry(rule: Rule, rf: RuleFile, *, proposed_severity: str, severity_reason: str,
               decided_by: str, reasons: list[str], llm_reason: str | None, uncertain: bool,
               probation_days: int, version: int, upstream: tuple, source_info: dict | None = None) -> dict:
    by_name = {r.name: r for r in rf.rules}
    order = {r.name: i for i, r in enumerate(rf.rules)}
    support = {x.name: x for x in closure(rule, by_name) if x.name != rule.name}
    for g in (r for r in rf.rules if r.is_global):
        support[g.name] = g
        support.update({x.name: x for x in closure(g, by_name)})
    support.pop(rule.name, None)
    probation_until = (datetime.now(timezone.utc) + timedelta(days=probation_days)).strftime("%Y-%m-%d")
    e = {
        "key": rule.key, "name": rule.name, "source": rule.source, "relpath": rule.relpath,
        "sha256": rule.sha256, "order": order.get(rule.name, 0),
        "rule": rule.to_cache(),
        "support": [{"name": s.name, "text": s.text, "order": order.get(s.name, 0), "imports": s.imports}
                    for s in support.values()],
        "imports": sorted(set(rule.imports) | {i for s in support.values() for i in s.imports} | set(rf.imports)),
        "proposed_severity": proposed_severity, "severity_reason": severity_reason,
        "status": "probation" if probation_days > 0 and not uncertain else "active",
        "probation_until": probation_until if probation_days > 0 and not uncertain else None,
        "uncertain": uncertain, "demoted": None,
        "decided_by": decided_by, "reasons": reasons, "llm_reason": llm_reason,
        "added_version": version, "updated_version": version, "added_at": now_iso(),
        "upstream": upstream[0], "license_url": upstream[1],
        "source_info": source_info or {},
    }
    e["severity"] = effective_severity(e)
    return e


def entry_rule(e: dict) -> Rule:
    return Rule(**e["rule"])


def entry_licence(e: dict) -> str | None:
    """The rule's licence: its own (YARA Forge gives one per rule), else its source's, else None."""
    if e.get("license_url"):
        return e["license_url"]
    lic = (e.get("source_info") or {}).get("licence")
    return lic if lic and lic not in ("unknown", "unrecognised") else None


def rule_files(entries: list[dict], header: str = "") -> dict[str, dict]:
    """namespace -> {"text", "rules": [{name, source, licence}], "lines": {name: (start, end)}}.

    One file per upstream source file, holding the entries plus the private/global rules they
    depend on, in their original order. Line ranges let YARA-X warnings be traced to a rule."""
    groups: dict[tuple[str, str], list[dict]] = {}
    for e in entries:
        groups.setdefault((e["source"], e["relpath"]), []).append(e)
    out = {}
    for (src, rel), es in sorted(groups.items()):
        blocks: dict[str, tuple[int, str]] = {}
        imports: set[str] = set()
        for e in es:
            imports.update(e["imports"])
            for s in e["support"]:
                blocks.setdefault(s["name"], (s["order"], s["text"]))
            blocks[e["name"]] = (e["order"], e["rule"]["text"])
        parts = ([header.rstrip("\n").replace("{src}", src).replace("{rel}", rel)] if header else [])
        parts += [f'import "{i}"' for i in sorted(imports)]
        line_no = 1 + sum(p.count("\n") + 2 for p in parts)   # parts are joined by a blank line
        lines = {}
        for name, (_, text) in sorted(blocks.items(), key=lambda kv: kv[1][0]):
            end = line_no + text.count("\n")
            lines[name] = (line_no, end)
            line_no = end + 2
            parts.append(text)
        ns = namespace(src, rel)
        out[ns] = {"text": "\n\n".join(parts) + "\n", "lines": lines,
                   "rules": [{"name": e["name"], "source": e.get("upstream") or e["source"],
                              "licence": entry_licence(e)} for e in sorted(es, key=lambda e: e["order"])]}
    return out


def group_texts(entries: list[dict]) -> dict[tuple[str, str], str]:
    """(source, relpath) -> rule-file text (used for clean-set compiles)."""
    by_ns = {namespace(e["source"], e["relpath"]): (e["source"], e["relpath"]) for e in entries}
    return {by_ns[ns]: f["text"] for ns, f in rule_files(entries).items()}


def severity_maps(entries: list[dict]) -> tuple[dict, dict, dict]:
    sev, demoted, probation = {}, {}, {}
    for e in entries:
        key = f'{namespace(e["source"], e["relpath"])}:{e["name"]}'
        sev[key] = e["severity"]
        if e.get("demoted"):
            demoted[key] = e["demoted"]
        elif e.get("uncertain"):
            demoted[key] = "the model wasn't sure this rule belongs; kept at info"
        if e.get("status") == "probation" and e.get("probation_until"):
            probation[key] = e["probation_until"]
    return sev, demoted, probation


def compile_entries(entries: list[dict]) -> tuple["yara_x.Rules | None", list[dict]]:
    compiler = new_compiler()
    errors = []
    for (src, rel), text in group_texts(entries).items():
        try:
            compiler.new_namespace(namespace(src, rel))
            compiler.add_source(text, origin=f"{src}/{rel}")
        except yara_x.CompileError as exc:
            errors.append({"file": f"{src}/{rel}", "error": str(exc)[:400]})
    if errors:
        return None, errors
    return compiler.build(), []


@dataclass
class LivePack:
    root: Path
    name: str
    data: dict = field(default_factory=dict)
    baseline: dict = field(default_factory=dict)
    last_write: dict = field(default_factory=dict)

    @property
    def dir(self) -> Path:
        return self.root / self.name

    @property
    def state_dir(self) -> Path:
        return self.dir / ".hermit"

    @classmethod
    def open(cls, root: Path, name: str, kind: str = "detection", description: str = "",
             editions: list[str] | None = None) -> "LivePack":
        p = cls(root, name)
        p._migrate()
        f = p.state_dir / "state.json"
        if f.is_file():
            p.data = json.loads(f.read_text())
            b = p.state_dir / "baseline.json"
            p.baseline = json.loads(b.read_text()) if b.is_file() else {}
        else:
            p.data = {"name": name, "kind": kind, "description": description, "version": 0,
                      "updated_at": None, "entries": {}, "excluded": {}}
        if editions:
            p.data["editions"] = editions
        return p

    def _migrate(self) -> None:
        """Move a pre-contract pack (state in pack.json at the top level) into .hermit/."""
        old = self.dir / "pack.json"
        if not old.is_file() or (self.state_dir / "state.json").is_file():
            return
        try:
            data = json.loads(old.read_text())
        except ValueError:
            return
        if "entries" not in data:
            return
        self.state_dir.mkdir(parents=True, exist_ok=True)
        old.rename(self.state_dir / "state.json")
        for name in ("baseline.json", "history.jsonl", "CHANGELOG.md", "history"):
            if (self.dir / name).exists():
                (self.dir / name).rename(self.state_dir / name)
        for h in (self.state_dir / "history").glob("v*/pack.json") if (self.state_dir / "history").is_dir() else []:
            h.rename(h.with_name("state.json"))
        shutil.rmtree(self.dir / "rules", ignore_errors=True)
        (self.dir / "severities.json").unlink(missing_ok=True)
        self.data = data
        b = self.state_dir / "baseline.json"
        self.baseline = json.loads(b.read_text()) if b.is_file() else {}
        self._write_current()

    @property
    def exists(self) -> bool:
        return (self.state_dir / "state.json").is_file()

    @property
    def version(self) -> int:
        return self.data["version"]

    @property
    def entries(self) -> dict[str, dict]:
        return self.data["entries"]

    @property
    def editions(self) -> list[str]:
        return self.data.get("editions") or ["standard"]

    def is_new_to_pack(self, rule: Rule) -> bool:
        return self.baseline.get(rule.key) != rule.sha256[:16]

    # ---------------------------------------------------------------- write

    def write_contract(self, dest: Path, entries: list[dict], *, compile_yarx: bool) -> dict:
        sev, demoted, probation = severity_maps(entries)
        header = f"// {self.name} v{self.version} (hermit {__version__}); from {{src}}/{{rel}}\n"
        return contract.write_pack(
            dest, pack_id=self.name, version=max(self.version, 1), kind=self.data.get("kind", "detection"),
            editions=self.editions, description=self.data.get("description", ""),
            files=rule_files(entries, header), severities=sev, demoted=demoted, probation=probation,
            compile_yarx=compile_yarx)

    def _write_current(self) -> list[dict]:
        d = self.dir
        d.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(exist_ok=True)
        entries = list(self.entries.values())
        staging = self.state_dir / "contract.new"
        shutil.rmtree(staging, ignore_errors=True)
        res = self.write_contract(staging, entries, compile_yarx=True)
        if res["errors"]:
            shutil.rmtree(staging, ignore_errors=True)
            return res["errors"]
        self.last_write = res
        for name in ("pack.json", "severities.json", "pack.yarx"):
            if (staging / name).is_file():
                (staging / name).replace(d / name)
            else:
                (d / name).unlink(missing_ok=True)
        shutil.rmtree(d / "rules", ignore_errors=True)
        (staging / "rules").rename(d / "rules")
        shutil.rmtree(staging, ignore_errors=True)
        for name, obj in (("state.json", self.data), ("baseline.json", self.baseline)):
            tmp = self.state_dir / (name + ".new")
            tmp.write_text(json.dumps(obj, indent=1, ensure_ascii=False))
            tmp.replace(self.state_dir / name)
        return []

    def _snapshot(self) -> None:
        if not self.exists:
            return
        h = self.state_dir / "history" / f"v{self.version:04d}"
        h.mkdir(parents=True, exist_ok=True)
        for name in ("state.json", "baseline.json"):
            if (self.state_dir / name).is_file():
                shutil.copy2(self.state_dir / name, h / name)
        versions = sorted((self.state_dir / "history").glob("v*"))
        for old in versions[:-KEEP_VERSIONS]:
            shutil.rmtree(old, ignore_errors=True)

    def commit(self, summary: str, details: list[str], seen: dict[str, str]) -> list[dict]:
        """Save a new version. `seen` (key -> hash) is added to the baseline."""
        self._snapshot()
        self.data["version"] += 1
        self.data["updated_at"] = now_iso()
        self.baseline.update({k: v[:16] for k, v in seen.items()})
        errors = self._write_current()
        if errors:
            return errors
        log = self.state_dir / "CHANGELOG.md"
        entry = [f"## v{self.version}, {self.data['updated_at']}", "", summary, ""] + [f"- {x}" for x in details[:400]]
        if len(details) > 400:
            entry.append(f"- … and {len(details) - 400} more (see history/)")
        prev = log.read_text() if log.is_file() else f"# {self.name} changelog\n\n"
        head, _, rest = prev.partition("\n\n")
        log.write_text(head + "\n\n" + "\n".join(entry) + "\n\n" + rest)
        hist = self.state_dir / "history.jsonl"
        with open(hist, "a") as fh:
            fh.write(json.dumps({"version": self.version, "at": self.data["updated_at"],
                                 "summary": summary, "details": details[:2000]}) + "\n")
        return []

    def remember_seen(self, seen: dict[str, str]) -> None:
        """Record considered rules without a new version (nothing in the pack changed)."""
        if not self.exists or not seen:
            return
        self.baseline.update({k: v[:16] for k, v in seen.items()})
        tmp = self.state_dir / "baseline.json.new"
        tmp.write_text(json.dumps(self.baseline, indent=1))
        tmp.replace(self.state_dir / "baseline.json")

    def rollback(self, to: int | None = None) -> int:
        target = to if to is not None else self.version - 1
        h = self.state_dir / "history" / f"v{target:04d}"
        if target == 0:  # before the first update: an empty pack that has considered nothing
            current = self.version
            self.data = {**self.data, "version": current, "entries": {}, "excluded": {}}
            self.baseline = {}
            errors = self.commit("Rolled back to the empty pack (v0).", [], {})
            if errors:
                raise SystemExit(f"rollback failed: {errors[:2]}")
            return self.version
        if target < 0 or not (h / "state.json").is_file():
            hist = self.state_dir / "history"
            avail = sorted(int(p.name[1:]) for p in hist.glob("v*")) if hist.is_dir() else []
            raise SystemExit(f"{self.name}: no saved version {target}; available: {avail}")
        current = self.version
        old = json.loads((h / "state.json").read_text())
        self.baseline = json.loads((h / "baseline.json").read_text()) if (h / "baseline.json").is_file() else {}
        self.data = old
        self.data["version"] = current  # commit() bumps it, so history stays linear
        errors = self.commit(f"Rolled back to the contents of v{target}.", [], {})
        if errors:
            raise SystemExit(f"rollback failed to compile: {errors[:2]}")
        return self.version

    def history(self) -> list[dict]:
        f = self.state_dir / "history.jsonl"
        return [json.loads(x) for x in f.read_text().splitlines() if x.strip()] if f.is_file() else []


def list_packs(root: Path) -> list[LivePack]:
    if not root.is_dir():
        return []
    return [LivePack.open(root, p.name) for p in sorted(root.iterdir())
            if (p / ".hermit" / "state.json").is_file() or (p / "pack.json").is_file()]
