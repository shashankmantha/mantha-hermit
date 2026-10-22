"""Bundle contract v1: the boundary between Hermit and Mantha Ray.

Writes pack folders and bundles in the contract layout, and validates them strictly.
`validate_bundle` is also the reference for Mantha Ray's loader: anything it rejects,
Mantha Ray should reject too.

  manifest.json
  packs/<pack-id>/pack.json
  packs/<pack-id>/severities.json
  packs/<pack-id>/rules/<namespace>.yar     one YARA-X namespace per file (namespace = file stem)
  packs/<pack-id>/pack.yarx                 optional; only for signed bundles, same YARA-X version
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yara_x

FORMAT = 1
SEVERITIES = ("threat", "suspicious", "info")
KINDS = ("detection", "recognition")
EXTERNALS = ("filename", "filepath", "extension")
PACK_ID_RE = re.compile(r"^(local:)?[a-z0-9][a-z0-9-]{0,62}$")
NAMESPACE_RE = re.compile(r"^[A-Za-z0-9_]{1,200}$")
RULE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
EDITION_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
BUNDLE_VERSION_RE = re.compile(r"^\d{4}\.\d{1,2}\.\d{1,2}\.\d{1,4}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PACK_FILES = {"pack.json", "severities.json", "rules", "pack.yarx"}
MAX_RULE_FILE = 8 * 2**20
MAX_JSON = 32 * 2**20


class ContractError(ValueError):
    pass


def new_compiler(externals=EXTERNALS) -> "yara_x.Compiler":
    c = yara_x.Compiler()
    for name in externals:
        c.define_global(name, "")
    return c


def yara_x_version() -> str:
    try:
        from importlib.metadata import version
        return version("yara-x")
    except Exception:
        return "unknown"


# ------------------------------------------------------------------ hashing

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def pack_digest(pack_dir: Path) -> str:
    """sha256 over the pack folder's contents: one line "<sha256>  <relative path>\\n" per file,
    sorted by path (the same text `sha256sum` prints, so it can be checked by hand)."""
    files = sorted((p.relative_to(pack_dir).as_posix(), p) for p in pack_dir.rglob("*") if p.is_file())
    lines = [f"{sha256_file(p)}  {rel}\n" for rel, p in files]
    return hashlib.sha256("".join(lines).encode()).hexdigest()


# ------------------------------------------------------------------ writing

def write_json(path: Path, obj) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=False) + "\n")
    tmp.replace(path)


def write_pack(dest: Path, *, pack_id: str, version: int, kind: str, editions: list[str],
               description: str, files: dict[str, dict], severities: dict[str, str],
               demoted: dict[str, str], probation: dict[str, str], compile_yarx: bool) -> dict:
    """Write one pack folder.

    files: namespace -> {"text": rule-file text, "rules": [{name, source, licence}], "lines": {name: (start, end)}}
    Returns {"errors": [...], "slow": {"ns:rule": warning}, "externals": [...]}.
    Rules in `slow` are capped at info (performance guard) before severities.json is written.
    """
    dest.mkdir(parents=True, exist_ok=True)
    rules_dir = dest / "rules"
    if rules_dir.exists():
        for old in rules_dir.iterdir():
            old.unlink()
    rules_dir.mkdir(exist_ok=True)
    errors, slow, used_ext = [], {}, set()
    compiler = new_compiler() if compile_yarx else None
    for ns, f in sorted(files.items()):
        text = f["text"]
        (rules_dir / f"{ns}.yar").write_text(text)
        used_ext.update(e for e in EXTERNALS if re.search(rf"\b{e}\b", _conditions(text)))
        c = new_compiler()
        try:
            c.add_source(text, origin=f"rules/{ns}.yar")
        except yara_x.CompileError as exc:
            errors.append({"file": f"rules/{ns}.yar", "error": str(exc).strip()[:400]})
            continue
        for w in c.warnings():
            if w.get("code") == "slow_pattern":
                for name, (start, end) in f.get("lines", {}).items():
                    if start <= w.get("line", -1) <= end:
                        slow[f"{ns}:{name}"] = w.get("title", "slow pattern")
        if compiler is not None:
            compiler.new_namespace(ns)
            compiler.add_source(text, origin=f"rules/{ns}.yar")
    for key in slow:
        if severities.get(key, "info") != "info":
            severities[key] = "info"
            demoted.setdefault(key, "slow pattern: kept at info by the performance guard")
    rules = [{"namespace": ns, "name": r["name"], "file": f"rules/{ns}.yar",
              "source": r.get("source"), "licence": r.get("licence")}
             for ns, f in sorted(files.items()) for r in f["rules"]]
    write_json(dest / "pack.json", {
        "format": FORMAT, "id": pack_id, "version": version, "kind": kind, "editions": editions,
        "description": description, "rules": rules, "externals": sorted(used_ext)})
    write_json(dest / "severities.json", {
        "format": FORMAT, "severities": dict(sorted(severities.items())),
        "demoted": dict(sorted(demoted.items())), "probation": dict(sorted(probation.items()))})
    yarx = dest / "pack.yarx"
    if compiler is not None and not errors and files:
        tmp = dest / "pack.yarx.tmp"
        with open(tmp, "wb") as fh:
            compiler.build().serialize_into(fh)
        tmp.replace(yarx)
    else:
        yarx.unlink(missing_ok=True)
    return {"errors": errors, "slow": slow, "externals": sorted(used_ext)}


def _conditions(text: str) -> str:
    return " ".join(m.group(1) for m in re.finditer(r"condition\s*:(.*?)(?=\n\s*\}|\Z)", text, re.S))


# ------------------------------------------------------------------ validation

def _load_json(p: Path) -> dict:
    if not p.is_file():
        raise ContractError(f"missing {p.name}")
    if p.stat().st_size > MAX_JSON:
        raise ContractError(f"{p.name} is too large")
    try:
        obj = json.loads(p.read_text())
    except (ValueError, UnicodeDecodeError) as exc:
        raise ContractError(f"{p.name} is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ContractError(f"{p.name} must be a JSON object")
    return obj


def _expect(cond: bool, msg: str) -> None:
    if not cond:
        raise ContractError(msg)


def _keys(obj: dict, where: str, required: set[str], optional: set[str] = frozenset()) -> None:
    missing = required - obj.keys()
    extra = obj.keys() - required - optional
    _expect(not missing, f"{where}: missing field(s) {sorted(missing)}")
    _expect(not extra, f"{where}: unknown field(s) {sorted(extra)}")


def validate_pack(pack_dir: Path, *, compile_rules: bool = True, allow_state: bool = False) -> dict:
    """Strictly validate one pack folder. Returns a summary; raises ContractError."""
    where = f"pack {pack_dir.name}"
    for p in pack_dir.iterdir():
        if p.is_symlink():
            raise ContractError(f"{where}: symlinks are not allowed ({p.name})")
        if p.name not in PACK_FILES and not (allow_state and p.name == ".hermit"):
            raise ContractError(f"{where}: unexpected file {p.name}")
    meta = _load_json(pack_dir / "pack.json")
    _keys(meta, f"{where}/pack.json", {"format", "id", "version", "kind", "editions", "rules", "externals"},
          {"description"})
    _expect(meta["format"] == FORMAT, f"{where}: pack.json format must be {FORMAT}")
    _expect(isinstance(meta["id"], str) and bool(PACK_ID_RE.match(meta["id"])), f"{where}: bad id {meta['id']!r}")
    _expect(meta["id"].removeprefix("local:") == pack_dir.name, f"{where}: id {meta['id']!r} doesn't match folder")
    _expect(isinstance(meta["version"], int) and meta["version"] >= 1, f"{where}: version must be an integer >= 1")
    _expect(meta["kind"] in KINDS, f"{where}: kind must be one of {KINDS}")
    _expect(isinstance(meta["editions"], list) and meta["editions"]
            and all(isinstance(e, str) and EDITION_RE.match(e) for e in meta["editions"]),
            f"{where}: editions must be a non-empty list of lowercase names")
    _expect(isinstance(meta.get("description", ""), str), f"{where}: description must be text")
    _expect(isinstance(meta["externals"], list) and set(meta["externals"]) <= set(EXTERNALS),
            f"{where}: externals must come from {EXTERNALS}")
    _expect(isinstance(meta["rules"], list), f"{where}: rules must be a list")

    rules_dir = pack_dir / "rules"
    _expect(rules_dir.is_dir(), f"{where}: missing rules/")
    files = {}
    for p in rules_dir.iterdir():
        _expect(p.is_file() and not p.is_symlink() and p.suffix == ".yar" and NAMESPACE_RE.match(p.stem),
                f"{where}: unexpected entry rules/{p.name}")
        _expect(p.stat().st_size <= MAX_RULE_FILE, f"{where}: rules/{p.name} is too large")
        files[p.stem] = p
    keys = set()
    for i, r in enumerate(meta["rules"]):
        w = f"{where}/pack.json rules[{i}]"
        _expect(isinstance(r, dict), f"{w}: must be an object")
        _keys(r, w, {"namespace", "name", "file", "source", "licence"})
        _expect(isinstance(r["namespace"], str) and r["namespace"] in files, f"{w}: no rule file for namespace {r['namespace']!r}")
        _expect(r["file"] == f"rules/{r['namespace']}.yar", f"{w}: file must be rules/<namespace>.yar")
        _expect(isinstance(r["name"], str) and bool(RULE_NAME_RE.match(r["name"])), f"{w}: bad rule name")
        for k in ("source", "licence"):
            _expect(r[k] is None or isinstance(r[k], str), f"{w}: {k} must be text or null")
        key = f"{r['namespace']}:{r['name']}"
        _expect(key not in keys, f"{w}: duplicate rule {key}")
        keys.add(key)

    sev = _load_json(pack_dir / "severities.json")
    _keys(sev, f"{where}/severities.json", {"format", "severities", "demoted", "probation"})
    _expect(sev["format"] == FORMAT, f"{where}: severities.json format must be {FORMAT}")
    for field in ("severities", "demoted", "probation"):
        _expect(isinstance(sev[field], dict), f"{where}: severities.json {field} must be an object")
        unknown = set(sev[field]) - keys
        _expect(not unknown, f"{where}: severities.json {field} names rules not in pack.json: {sorted(unknown)[:3]}")
    _expect(all(v in SEVERITIES for v in sev["severities"].values()), f"{where}: severities must be one of {SEVERITIES}")
    _expect(all(isinstance(v, str) for v in sev["demoted"].values()), f"{where}: demoted reasons must be text")
    _expect(all(isinstance(v, str) and DATE_RE.match(v) for v in sev["probation"].values()),
            f"{where}: probation dates must be YYYY-MM-DD")
    for k, v in sev["probation"].items():
        _expect(sev["severities"].get(k, "info") == "info", f"{where}: {k} is on probation but not info")

    compiled_names: set[str] = set()
    if compile_rules:
        for ns, p in sorted(files.items()):
            c = new_compiler(meta["externals"])
            try:
                c.add_source(p.read_text(), origin=f"rules/{p.name}")
                rules = c.build()
            except yara_x.CompileError as exc:
                raise ContractError(f"{where}: rules/{p.name} doesn't compile: {str(exc).strip()[:300]}") from exc
            except UnicodeDecodeError as exc:
                raise ContractError(f"{where}: rules/{p.name} is not UTF-8") from exc
            for r in rules:
                compiled_names.add(f"{ns}:{r.identifier}")
        missing = keys - compiled_names
        _expect(not missing, f"{where}: pack.json lists rules that aren't in the rule files: {sorted(missing)[:3]}")
    return {"id": meta["id"], "version": meta["version"], "rules": len(keys),
            "without_severity": len(keys - set(sev["severities"])),
            "has_yarx": (pack_dir / "pack.yarx").is_file()}


def validate_bundle(root: Path, *, compile_rules: bool = True) -> dict:
    """Strictly validate an unpacked bundle folder. Returns a summary; raises ContractError."""
    for p in root.iterdir():
        _expect(p.name in ("manifest.json", "packs") and not p.is_symlink(), f"bundle: unexpected entry {p.name}")
    m = _load_json(root / "manifest.json")
    _keys(m, "manifest.json", {"format", "bundle_version", "created_at", "min_app_version", "yara_x_version",
                               "packs", "sources", "changes"})
    _expect(m["format"] == FORMAT, f"manifest.json: format must be {FORMAT}")
    _expect(isinstance(m["bundle_version"], str) and bool(BUNDLE_VERSION_RE.match(m["bundle_version"])),
            "manifest.json: bundle_version must look like 2026.10.25.1")
    _expect(isinstance(m["created_at"], str) and bool(re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", m["created_at"])),
            "manifest.json: created_at must be a UTC timestamp like 2026-10-25T03:00:00Z")
    _expect(isinstance(m["min_app_version"], str) and bool(SEMVER_RE.match(m["min_app_version"])),
            "manifest.json: min_app_version must be like 0.3.0")
    _expect(isinstance(m["yara_x_version"], str), "manifest.json: yara_x_version must be text")
    _expect(isinstance(m["changes"], str), "manifest.json: changes must be text")
    _expect(isinstance(m["sources"], list), "manifest.json: sources must be a list")
    for i, s in enumerate(m["sources"]):
        _expect(isinstance(s, dict), f"manifest.json sources[{i}]: must be an object")
        _keys(s, f"manifest.json sources[{i}]", {"name", "url", "revision", "licence"})
        _expect(all(v is None or isinstance(v, str) for v in s.values()), f"manifest.json sources[{i}]: values must be text or null")
    _expect(isinstance(m["packs"], list), "manifest.json: packs must be a list")
    packs_dir = root / "packs"
    _expect(packs_dir.is_dir(), "bundle: missing packs/")
    listed = {}
    for i, p in enumerate(m["packs"]):
        _expect(isinstance(p, dict), f"manifest.json packs[{i}]: must be an object")
        _keys(p, f"manifest.json packs[{i}]", {"id", "version", "sha256"})
        _expect(isinstance(p["id"], str) and bool(PACK_ID_RE.match(p["id"])) and not p["id"].startswith("local:"),
                f"manifest.json packs[{i}]: bad id (local: packs never ship in bundles)")
        _expect(p["id"] not in listed, f"manifest.json: pack {p['id']} listed twice")
        listed[p["id"]] = p
    on_disk = {d.name for d in packs_dir.iterdir()}
    _expect(on_disk == set(listed), f"bundle: packs/ ({sorted(on_disk)}) doesn't match manifest ({sorted(listed)})")
    summaries = []
    for pid, p in sorted(listed.items()):
        d = packs_dir / pid
        _expect(d.is_dir() and not d.is_symlink(), f"bundle: packs/{pid} must be a folder")
        _expect(pack_digest(d) == p["sha256"], f"bundle: packs/{pid} doesn't match its sha256 in manifest.json")
        s = validate_pack(d, compile_rules=compile_rules)
        _expect(s["version"] == p["version"], f"bundle: packs/{pid} version differs from manifest.json")
        summaries.append(s)
    return {"bundle_version": m["bundle_version"], "yara_x_version": m["yara_x_version"],
            "min_app_version": m["min_app_version"], "packs": summaries}
