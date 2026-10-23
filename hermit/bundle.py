"""Build, sign, verify and publish bundles (bundle contract v1).

  hermit export-bundle --unsigned DIR   phase 1a: the bundle layout, unpacked into a folder
  hermit publish                        phase 1b: tar.gz + minisign signature (+ GitHub release)
  hermit verify BUNDLE.tar.gz           what Mantha Ray's updater does: signature, safe unpack, validate
  hermit validate DIR                   strict contract check of a bundle folder or one pack folder
"""
from __future__ import annotations

import gzip
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import contract, signing
from .livepacks import entry_licence, list_packs

MAX_BUNDLE_BYTES = 256 * 2**20
MAX_MEMBERS = 50_000


class BundleError(Exception):
    pass


# ------------------------------------------------------------------ settings

class BundleSettings:
    def __init__(self, cfg):
        b = cfg.main.get("bundle", {})
        self.yara_x_pin = str(b.get("yara_x_version", "")).strip()
        self.min_app_version = str(b.get("min_app_version", "0.0.0"))
        self.require_licence = bool(b.get("require_licence", True))
        self.allowed_licences = [str(x).lower() for x in b.get("allowed_licences", [])]
        self.include_compiled = bool(b.get("include_compiled", True))
        self.release_repo = str(b.get("release_repo", "")).strip()
        self.secret_key = Path(os.path.expanduser(b.get("secret_key", "~/.config/hermit/minisign.key")))
        pk = Path(os.path.expanduser(b.get("public_key", "config/minisign.pub")))
        self.public_key = pk if pk.is_absolute() else cfg.root / pk
        od = Path(os.path.expanduser(b.get("out_dir", "out/bundles")))
        self.out_dir = od if od.is_absolute() else cfg.root / od
        self.state_file = cfg.state_db.parent / "bundles.json"


def licence_ok(e: dict, s: BundleSettings) -> tuple[bool, str]:
    lic = entry_licence(e)
    if lic is None:
        return (not s.require_licence), "no known licence"
    if s.allowed_licences and not any(a in lic.lower() for a in s.allowed_licences):
        return False, f"licence not on the allowlist ({lic[:80]})"
    return True, ""


# ------------------------------------------------------------------ state

def load_state(s: BundleSettings) -> dict:
    if s.state_file.is_file():
        return json.loads(s.state_file.read_text())
    return {"published": [], "last_contents": {}}


def next_version(state: dict, today: str) -> str:
    """YYYY.M.D.N, always newer than every published version (installs refuse older bundles,
    so a clock that went backwards must not produce one)."""
    y, m, d = today.split("-")
    date = (int(y), int(m), int(d))
    published = [contract.bundle_version_key(v["bundle_version"]) for v in state["published"]]
    latest = max(published, default=None)
    if latest and latest[:3] >= date:
        date = latest[:3]
    n = max((k[3] for k in published if k[:3] == date), default=0) + 1
    return ".".join(str(x) for x in (*date, n))


SIGNED_COMMENT_RE = re.compile(r"^mantha-packs (\S+) sha256:([0-9a-f]{64})$")


def describe_changes(old: dict, new: dict) -> str:
    """old/new: pack -> {rule key: severity}."""
    if not old:
        total = sum(len(v) for v in new.values())
        return f"First bundle: {len(new)} packs, {total} rules (" + ", ".join(
            f"{p} {len(v)}" for p, v in sorted(new.items())) + ")."
    parts = []
    for p in sorted(set(old) | set(new)):
        a, b = old.get(p, {}), new.get(p, {})
        if p not in old:
            parts.append(f"{p}: new pack, {len(b)} rules")
            continue
        if p not in new:
            parts.append(f"{p}: removed")
            continue
        added, removed = len(b.keys() - a.keys()), len(a.keys() - b.keys())
        changed = sum(1 for k in a.keys() & b.keys() if a[k] != b[k])
        if added or removed or changed:
            bits = [f"+{added}" if added else "", f"-{removed}" if removed else "",
                    f"{changed} severity change{'s' if changed != 1 else ''}" if changed else ""]
            parts.append(f"{p}: " + ", ".join(x for x in bits if x))
    return "; ".join(parts) + "." if parts else "No rule changes (rebuild)."


# ------------------------------------------------------------------ build

def build_tree(cfg, dest: Path, log, *, only: list[str] | None = None, version: str | None = None,
               include_compiled: bool | None = None) -> dict:
    """Write an unpacked bundle into dest (must not exist). Returns a summary."""
    s = BundleSettings(cfg)
    if dest.exists():
        raise BundleError(f"{dest} already exists")
    state = load_state(s)
    now = datetime.now(timezone.utc)
    version = version or next_version(state, now.strftime("%Y-%m-%d"))
    compiled = s.include_compiled if include_compiled is None else include_compiled
    packs = [p for p in list_packs(cfg.packs_dir) if not only or p.name in only]
    if only and (missing := set(only) - {p.name for p in packs}):
        raise BundleError(f"no live pack named {', '.join(sorted(missing))}")
    if not packs:
        raise BundleError(f"no live packs in {cfg.packs_dir}; build some with `hermit ask` first")
    staging = dest.with_name(dest.name + ".partial")
    shutil.rmtree(staging, ignore_errors=True)
    (staging / "packs").mkdir(parents=True)
    listed, sources, contents, report = [], {}, {}, []
    for p in packs:
        entries, dropped = [], {}
        for e in p.entries.values():
            ok, why = licence_ok(e, s)
            if ok:
                entries.append(e)
            else:
                dropped[why] = dropped.get(why, 0) + 1
        if not entries:
            log(f"  {p.name}: skipped (no rules{' after the licence filter' if dropped else ''})")
            report.append({"pack": p.name, "rules": 0, "excluded": dropped, "skipped": True})
            continue
        pdir = staging / "packs" / p.name
        res = p.write_contract(pdir, entries, compile_yarx=compiled)
        if res["errors"]:
            shutil.rmtree(staging, ignore_errors=True)
            raise BundleError(f"{p.name}: rules don't compile: {res['errors'][:2]}")
        sev = json.loads((pdir / "severities.json").read_text())["severities"]
        contents[p.name] = sev
        listed.append({"id": p.name, "version": max(p.version, 1), "sha256": contract.pack_digest(pdir)})
        for e in entries:
            si = e.get("source_info") or {}
            name = si.get("name") or e["source"]
            sources.setdefault(name, {"name": name, "url": si.get("url"), "revision": si.get("revision"),
                                      "licence": si.get("licence") if si.get("licence") not in ("unknown", None)
                                      else "per rule (see pack.json)"})
        counts = {}
        for v in sev.values():
            counts[v] = counts.get(v, 0) + 1
        report.append({"pack": p.name, "rules": len(entries), "excluded": dropped, "severity": counts,
                       "slow": len(res["slow"]), "externals": res["externals"]})
        log(f"  {p.name} v{p.version}: {len(entries)} rule{'' if len(entries) == 1 else 's'} "
            f"(threat {counts.get('threat', 0)}, suspicious {counts.get('suspicious', 0)}, info {counts.get('info', 0)})"
            + (f"; left out {sum(dropped.values())} ({', '.join(f'{v} {k}' for k, v in dropped.items())})" if dropped else "")
            + (f"; {len(res['slow'])} slow rules kept at info" if res["slow"] else ""))
    if not listed:
        shutil.rmtree(staging, ignore_errors=True)
        raise BundleError("every pack was empty after the licence filter; nothing to bundle")
    manifest = {
        "format": contract.FORMAT, "bundle_version": version, "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "min_app_version": s.min_app_version, "yara_x_version": contract.yara_x_version(),
        "packs": listed, "sources": sorted(sources.values(), key=lambda x: x["name"]),
        "changes": describe_changes(state.get("last_contents", {}), contents),
    }
    contract.write_json(staging / "manifest.json", manifest)
    summary = contract.validate_bundle(staging)  # never hand out something that fails our own check
    staging.rename(dest)
    return {"manifest": manifest, "packs": report, "validated": summary, "contents": contents}


def check_yara_x_pin(s: BundleSettings) -> str | None:
    have = contract.yara_x_version()
    if s.yara_x_pin and s.yara_x_pin != have:
        return (f"installed yara-x is {have} but [bundle] yara_x_version pins {s.yara_x_pin} "
                f"(Mantha Ray's version). Install it with: pip install yara-x=={s.yara_x_pin}")
    return None


# ------------------------------------------------------------------ archive

def make_tarball(tree: Path, out: Path) -> None:
    """Deterministic tar.gz: sorted names, fixed owner/mode/time."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for p in sorted(tree.rglob("*")):
            rel = p.relative_to(tree).as_posix()
            info = tarfile.TarInfo(rel)
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
            if p.is_dir():
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            else:
                info.size, info.mode = p.stat().st_size, 0o644
                with open(p, "rb") as fh:
                    tar.addfile(info, fh)
    with open(out, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz:
        gz.write(buf.getvalue())


def safe_extract(tarball: Path, dest: Path) -> None:
    """Unpack a bundle refusing anything but plain files and folders inside dest."""
    if tarball.stat().st_size > MAX_BUNDLE_BYTES:
        raise BundleError("bundle is larger than allowed")
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    total = 0
    with tarfile.open(tarball, "r:gz") as tar:
        members = tar.getmembers()
        if len(members) > MAX_MEMBERS:
            raise BundleError("bundle has too many files")
        for m in members:
            if not (m.isfile() or m.isdir()):
                raise BundleError(f"bundle contains a link or special file: {m.name}")
            target = (dest / m.name).resolve()
            if target != root and root not in target.parents:
                raise BundleError(f"bundle path escapes the destination: {m.name}")
            total += m.size
            if total > 4 * MAX_BUNDLE_BYTES:
                raise BundleError("bundle unpacks to more than allowed")
        tar.extractall(dest, members=members, filter="data")


def verify_bundle(tarball: Path, public_key_text: str, *, compile_rules: bool = True,
                  installed_version: str | None = None) -> dict:
    """What Mantha Ray's updater does, in order:
    1. the signature, and the signed comment's exact form (`mantha-packs <version> sha256:<hash>`);
    2. the archive's sha256 against the signed hash;
    3. rollback: a signed but older bundle than `installed_version` is refused;
    4. a safe unpack into a temporary folder, strict validation, and the manifest's
       bundle_version against the signed version (exact match)."""
    sig = tarball.with_name(tarball.name + ".minisig")
    if not sig.is_file():
        raise BundleError(f"no signature next to the bundle ({sig.name})")
    comment = signing.verify_file(tarball, sig, public_key_text)
    m = SIGNED_COMMENT_RE.match(comment)
    if not m:
        raise BundleError(f"signed comment '{comment}' isn't 'mantha-packs <version> sha256:<hash>'")
    signed_version, signed_sha = m.groups()
    if not contract.BUNDLE_VERSION_RE.match(signed_version):
        raise BundleError(f"signed comment names a bad version {signed_version!r}")
    if contract.sha256_file(tarball) != signed_sha:
        raise BundleError("the archive's sha256 doesn't match the signed comment")
    if installed_version and (contract.bundle_version_key(signed_version)
                              < contract.bundle_version_key(installed_version)):
        raise BundleError(f"bundle {signed_version} is older than the installed {installed_version} "
                          "(rollback refused; only a local, explicit rollback may install an older bundle)")
    with tempfile.TemporaryDirectory() as tmp:
        safe_extract(tarball, Path(tmp))
        summary = contract.validate_bundle(Path(tmp), compile_rules=compile_rules)
    if summary["bundle_version"] != signed_version:
        raise BundleError(f"manifest says {summary['bundle_version']} but the signature is for {signed_version}")
    summary["trusted_comment"] = comment
    summary["same_as_installed"] = installed_version == signed_version
    return summary


# ------------------------------------------------------------------ publish

def publish(cfg, log, *, only: list[str] | None, push: bool, allow_version_mismatch: bool) -> dict:
    s = BundleSettings(cfg)
    if (msg := check_yara_x_pin(s)) and not allow_version_mismatch:
        raise BundleError(msg + " (or pass --allow-version-mismatch to skip pack.yarx)")
    if not s.secret_key.is_file():
        raise BundleError(f"no signing key at {s.secret_key}; create one with `hermit keygen`")
    if not s.public_key.is_file():
        raise BundleError(f"no public key at {s.public_key}; `hermit keygen` writes it there")
    if not signing.is_encrypted(s.secret_key):
        log("Warning: the signing key has no password. That's fine for testing, but a release key "
            "can push rules to every install: protect it with `minisign -C -s " + str(s.secret_key) + "`")
    state = load_state(s)
    version = next_version(state, datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    out = s.out_dir / version
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    log(f"Building bundle {version}")
    built = build_tree(cfg, out / "tree", log, only=only, version=version,
                       include_compiled=s.include_compiled and not (msg and allow_version_mismatch))
    tarball = out / f"mantha-packs-{version}.tar.gz"
    make_tarball(out / "tree", tarball)
    sha = contract.sha256_file(tarball)
    signing.sign_file(tarball, s.secret_key, f"mantha-packs {version} sha256:{sha}")
    log(f"Signed {tarball.name}")
    verified = verify_bundle(tarball, s.public_key.read_text())  # round trip, as Mantha Ray will
    log(f"Verified: signature, safe unpack, contract ({len(verified['packs'])} packs)")
    notes = out / "RELEASE_NOTES.md"
    notes.write_text(release_notes(built))
    shutil.rmtree(out / "tree")
    url = None
    if push:
        if not s.release_repo:
            raise BundleError("set [bundle] release_repo (e.g. you/mantha-packs) or use --no-push")
        if not shutil.which("gh"):
            raise BundleError("the GitHub CLI (gh) is needed to push; install it and run `gh auth login`")
        log(f"Creating release v{version} on {s.release_repo}")
        r = subprocess.run(["gh", "release", "create", f"v{version}", str(tarball),
                            str(tarball.with_name(tarball.name + ".minisig")),
                            "--repo", s.release_repo, "--title", f"Mantha packs {version}",
                            "--notes-file", str(notes)], capture_output=True, text=True)
        if r.returncode != 0:
            raise BundleError(f"gh release create failed: {r.stderr.strip()[:400]} "
                              f"(the signed bundle is in {out}; nothing was recorded)")
        url = r.stdout.strip()
    state["published"].append({"bundle_version": version, "created_at": built["manifest"]["created_at"],
                               "sha256": sha, "pushed_to": s.release_repo if push else None, "url": url})
    state["last_contents"] = built["contents"]
    s.state_file.parent.mkdir(parents=True, exist_ok=True)
    s.state_file.write_text(json.dumps(state, indent=1))
    return {"version": version, "dir": out, "tarball": tarball, "sha256": sha, "url": url, **built}


def release_notes(built: dict) -> str:
    m = built["manifest"]
    lines = [f"# Mantha packs {m['bundle_version']}", "", m["changes"], "",
             "| Pack | Version | Rules | threat / suspicious / info |", "|---|---|---|---|"]
    versions = {p["id"]: p["version"] for p in m["packs"]}
    for r in built["packs"]:
        if r.get("skipped"):
            continue
        c = r["severity"]
        lines.append(f"| `{r['pack']}` | {versions[r['pack']]} | {r['rules']} | "
                     f"{c.get('threat', 0)} / {c.get('suspicious', 0)} / {c.get('info', 0)} |")
    lines += ["", f"Built with YARA-X {m['yara_x_version']}; needs Mantha Ray {m['min_app_version']} or newer.",
              "", "Verify: `minisign -Vm <bundle>.tar.gz -p minisign.pub` or `hermit verify <bundle>.tar.gz`."]
    return "\n".join(lines) + "\n"