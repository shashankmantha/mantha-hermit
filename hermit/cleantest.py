"""Scan known-clean files with rules; anything that fires there is a false positive."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import yara_x


def scan_dirs(rules: "yara_x.Rules", dirs: list[Path], log, timeout: int = 30,
              max_bytes: int = 1024 * 2**20) -> tuple[dict[tuple[str, str], list[str]], dict]:
    """Returns ({(namespace, rule): [paths]}, stats)."""
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(timeout)
    scanner.max_matches_per_pattern(100)
    hits: dict[tuple[str, str], list[str]] = defaultdict(list)
    stats = {"files": 0, "skipped_large": 0, "errors": 0, "timeouts": 0}
    for root in dirs:
        root = Path(root).expanduser()
        if not root.is_dir():
            log(f"  clean folder {root} not found, skipped")
            stats["errors"] += 1
            continue
        for p in sorted(root.rglob("*")):
            if p.is_symlink() or not p.is_file():
                continue
            try:
                size = p.stat().st_size
            except OSError:
                stats["errors"] += 1
                continue
            if size > max_bytes:
                stats["skipped_large"] += 1
                continue
            stats["files"] += 1
            scanner.set_global("filename", p.name)
            scanner.set_global("filepath", str(p.parent))
            scanner.set_global("extension", p.suffix.lower())
            try:
                res = scanner.scan_file(str(p))
            except yara_x.TimeoutError:
                stats["timeouts"] += 1
                continue
            except (yara_x.ScanError, OSError):
                stats["errors"] += 1
                continue
            for m in res.matching_rules:
                hits[(m.namespace, m.identifier)].append(str(p))
            if stats["files"] % 2000 == 0:
                log(f"  {stats['files']} clean files scanned")
    return dict(hits), stats


def run(pack_dir: Path, clean_dirs: list[Path], log, timeout: int = 30,
        max_bytes: int = 1024 * 2**20) -> dict:
    """`hermit test`: works on a candidate pack (manifest.json) or a live pack (pack.json)."""
    if (pack_dir / "severities.json").is_file() and (pack_dir / "pack.json").is_file():
        meta = json.loads((pack_dir / "pack.json").read_text())
        sev = json.loads((pack_dir / "severities.json").read_text())
        severity = {k.split(":", 1)[1]: v for k, v in sev.get("severities", {}).items()}
        name, compiled = meta.get("id", pack_dir.name), pack_dir / "pack.yarx"
    else:
        manifest = json.loads((pack_dir / "manifest.json").read_text())
        severity = {r["name"]: r["proposed_severity"] for r in manifest["rules"]}
        name, compiled = manifest["pack"], pack_dir / (manifest.get("compiled") or "pack.yarx")
    if not compiled.is_file():
        raise SystemExit(f"{compiled} not found; the pack did not compile or is empty")
    with open(compiled, "rb") as fh:
        rules = yara_x.Rules.deserialize_from(fh)
    raw, stats = scan_dirs(rules, clean_dirs, log, timeout, max_bytes)
    hits: dict[str, list[str]] = defaultdict(list)
    for (_, rule), files in raw.items():
        hits[rule].extend(files)
    fp = {r: f for r, f in hits.items() if severity.get(r, "suspicious") != "info"}
    result = {"pack": name, "clean_dirs": [str(d) for d in clean_dirs], **stats,
              "rules_fired": {r: {"severity": severity.get(r), "files": len(f), "examples": f[:5]}
                              for r, f in sorted(hits.items(), key=lambda kv: -len(kv[1]))},
              "false_positives": sorted(fp)}
    (pack_dir / "clean-test.json").write_text(json.dumps(result, indent=2))
    if fp:
        lines = ["# Suggested demotions from the clean-set test. Review, then copy into demotions.toml.", ""]
        for r in sorted(fp, key=lambda r: -len(fp[r])):
            lines += ["[[demote]]", f'rule = "{r}"', f'category = "{name}"', 'action = "info"   # or "drop"',
                      f'reason = "fired on {len(fp[r])} clean file(s), e.g. {Path(fp[r][0]).name}"', ""]
        (pack_dir / "demotions.suggested.toml").write_text("\n".join(lines))
    return result
