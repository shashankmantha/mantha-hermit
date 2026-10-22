"""Write candidate packs: rule files, compiled check, manifest, review list and report."""
from __future__ import annotations

import csv
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path

import yara_x

from . import __version__
from .features import upstream
from .parse import EXTERNALS, RuleFile, Source, new_compiler, subset_text


def _safe(rel: str) -> str:
    return re.sub(r"[^A-Za-z0-9._/-]", "_", rel).lstrip("/").replace("..", "_")


def build_pack(out_dir: Path, cat, picks: list[dict], files_by_key: dict, sources: dict[str, Source],
               extra: dict) -> dict:
    """picks: [{'rule', 'decision', 'severity', 'severity_reason', 'novelty'}]"""
    pack = out_dir / cat.name
    rules_dir = pack / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    grouped: dict[tuple[str, str], list] = defaultdict(list)
    for p in picks:
        grouped[(p["rule"].source, p["rule"].relpath)].append(p["rule"])

    compiler = new_compiler()
    compile_errors = []
    written = []
    for (src, rel), rules in sorted(grouped.items()):
        rf: RuleFile = files_by_key[(src, rel)]
        text = subset_text(rf, rules)
        dest = rules_dir / src / _safe(rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        header = (f"// hermit {__version__}: subset of {src}/{rel} for pack '{cat.name}'\n"
                  f"// licence: {sources[src].license}; commit: {sources[src].commit or 'unknown'}\n")
        dest.write_text(header + text)
        ns = re.sub(r"[^A-Za-z0-9_]", "_", f"{src}__{rel}")
        try:
            compiler.new_namespace(ns)
            compiler.add_source(text, origin=str(dest.relative_to(pack)))
        except yara_x.CompileError as exc:
            compile_errors.append({"file": str(dest.relative_to(pack)), "error": str(exc)[:400]})
        written.append(str(dest.relative_to(pack)))
    compiled = None
    if picks and not compile_errors:
        rules = compiler.build()
        compiled = pack / "pack.yarx"
        with open(compiled, "wb") as fh:
            rules.serialize_into(fh)

    sev_counts = Counter(p["severity"] for p in picks)
    manifest = {
        "pack": cat.name, "kind": cat.kind, "label": cat.label, "description": cat.description,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generator": f"hermit {__version__}", "category_fingerprint": cat.fingerprint(),
        "status": "candidate - review before adding to a bundle",
        "sources": [{"name": s.name, "origin": s.origin, "commit": s.commit, "license": s.license,
                     "license_file": s.license_file}
                    for s in sources.values() if any(p["rule"].source == s.name for p in picks)],
        "counts": {"rules": len(picks), "files": len(written), "by_severity": dict(sev_counts),
                   "by_decided_by": dict(Counter(p["decision"].decided_by for p in picks)),
                   "new_or_changed": sum(p["novelty"] != "seen" for p in picks)},
        "compiled": compiled.name if compiled else None,
        "externals_required": sorted({e for p in picks for e in p["rule"].externals}),
        "externals_note": ("Some rules read external variables; the scanner must set them per file "
                           f"(defaults {sorted(EXTERNALS)}), or those conditions see empty strings."),
        "compile_errors": compile_errors,
        **extra,
        "rules": [{
            "name": p["rule"].name, "source": p["rule"].source, "file": p["rule"].relpath,
            "sha256": p["rule"].sha256, "novelty": p["novelty"],
            "score": p["decision"].score, "decided_by": p["decision"].decided_by,
            "reasons": p["decision"].reasons, "llm_reason": p["decision"].llm_reason,
            "llm_confidence": p["decision"].llm_confidence,
            "proposed_severity": p["severity"], "severity_reason": p["severity_reason"],
            "targets": p["targets"], "externals": p["rule"].externals,
            "upstream": upstream(p["rule"])[0], "license_url": upstream(p["rule"])[1],
            "meta": {k: p["rule"].meta.get(k) for k in ("description", "author", "reference", "date", "score")
                     if p["rule"].meta.get(k)},
        } for p in sorted(picks, key=lambda p: (-p["decision"].score, p["rule"].name))],
    }
    (pack / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    return manifest


def write_review(out_dir: Path, rows: list[dict]) -> Path:
    path = out_dir / "review.csv"
    cols = ["category", "status", "rule", "source", "file", "score", "decided_by", "llm_confidence",
            "proposed_severity", "novelty", "targets", "reasons", "llm_reason", "description"]
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in cols})
    return path


def write_report(out_dir: Path, summary: dict) -> Path:
    L = [f"# hermit run, {summary['generated_at']}", ""]
    L.append(f"Command: `{summary['command']}`  ")
    L.append(f"Rules parsed: {summary['rules_total']} from {summary['files_total']} files "
             f"({summary['duplicates']} exact duplicates across sources skipped).  ")
    L.append(f"New since last run: {summary['novelty'].get('new', 0)}, changed: "
             f"{summary['novelty'].get('changed', 0)}"
             + (" (first run, so everything counts as new)" if summary["first_run"] else "") + ".  ")
    L.append(f"Local model: {summary['llm']}")
    L += ["", "## Packs", "", "| Pack | Included | of which by model | Needs review | Not applicable | Severity (threat / suspicious / info) | Compiles |",
          "|---|---|---|---|---|---|---|"]
    for c in summary["categories"]:
        s = c["severity"]
        L.append(f"| `{c['name']}` | {c['included']} | {c['by_llm']} | {c['review']} | {c['not_applicable']} "
                 f"| {s.get('threat', 0)} / {s.get('suspicious', 0)} / {s.get('info', 0)} "
                 f"| {'yes' if c['compiles'] else 'NO'} |")
    L += ["", "Each pack folder has `rules/` (original rule text, grouped by source file), "
          "`manifest.json` (why each rule is in), and `pack.yarx` (compiled with YARA-X).",
          "`review.csv` lists borderline rules and everything the model decided, for you to check.", ""]
    L += ["## Rules no pack could use", ""]
    for t, n in summary["not_applicable_targets"].most_common():
        L.append(f"- `{t}`: {n}")
    if summary["compile_failures"]:
        L += ["", f"## Rules that don't compile with YARA-X ({len(summary['compile_failures'])})", ""]
        reasons = Counter(re.sub(r"`[^`]*`|\"[^\"]*\"", "…", f["error"])[:90] for f in summary["compile_failures"])
        for reason, n in reasons.most_common(12):
            L.append(f"- {n} × {reason}")
    if summary["file_problems"]:
        L += ["", f"## Files skipped ({len(summary['file_problems'])})", ""]
        for p in summary["file_problems"][:30]:
            L.append(f"- {p['source']}/{p['file']}: {p['error']}")
    if summary["demoted"]:
        L += ["", "## Demotions applied", ""]
        for d in summary["demoted"]:
            L.append(f"- {d}")
    if summary.get("llm_errors"):
        L += ["", f"## Model errors ({len(summary['llm_errors'])}); those rules stayed in review", ""]
        for e in summary["llm_errors"][:20]:
            L.append(f"- {e}")
    L += ["", "## Licences", "", "| Source | Licence | Commit |", "|---|---|---|"]
    for s in summary["sources"]:
        L.append(f"| {s.name} | {s.license} | {(s.commit or '')[:16]} |")
    if summary.get("upstreams"):
        L += ["", "Rules in the packs by upstream repository (from rule metadata, e.g. YARA Forge). "
              "Check each licence before redistributing; \"none given\" needs a decision.", "",
              "| Upstream | Rules in packs | Licence |", "|---|---|---|"]
        for (up, lic), n in summary["upstreams"].most_common():
            L.append(f"| {up} | {n} | {lic or 'none given'} |")
    path = out_dir / "report.md"
    path.write_text("\n".join(L) + "\n")
    return path
