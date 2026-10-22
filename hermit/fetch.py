"""Download rule sources listed in sources.toml (git repos or zip releases)."""
from __future__ import annotations

import hashlib
import json
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path


class FetchError(Exception):
    pass


def _git(*args, cwd: Path | None = None, timeout: int = 600) -> str:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise FetchError(f"git {args[0]} failed: {exc}") from exc
    if out.returncode != 0:
        raise FetchError(f"git {' '.join(args[:2])} failed: {out.stderr.strip()[:300]}")
    return out.stdout.strip()


def fetch_git(name: str, url: str, ref: str | None, dest: Path, log) -> str:
    if not (dest / ".git").exists():
        if dest.exists():
            raise FetchError(f"{dest} exists but is not a git checkout; remove it first")
        log(f"  cloning {url}")
        _git("clone", "--quiet", "--filter=blob:none", url, str(dest))
    else:
        log(f"  updating {name}")
        _git("fetch", "--quiet", "--tags", "origin", cwd=dest)
    target = ref or "origin/HEAD"
    if not ref:
        try:
            _git("remote", "set-head", "origin", "--auto", cwd=dest)
        except FetchError:
            pass
        log(f"  WARNING: {name} has no pinned ref; using the default branch")
    _git("-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", target, cwd=dest)
    return _git("rev-parse", "HEAD", cwd=dest)


def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    root = dest.resolve()
    for info in zf.infolist():
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise FetchError(f"zip contains a symlink: {info.filename}")
        target = (dest / info.filename).resolve()
        if root not in target.parents and target != root:
            raise FetchError(f"zip path escapes destination: {info.filename}")
    zf.extractall(dest)


def fetch_zip(name: str, url: str, sha256: str | None, dest: Path, log, max_bytes=512 * 2**20) -> str:
    log(f"  downloading {url}")
    h = hashlib.sha256()
    with tempfile.TemporaryDirectory() as tmp:
        zpath = Path(tmp) / "src.zip"
        with urllib.request.urlopen(url, timeout=300) as resp, open(zpath, "wb") as out:
            total = 0
            while chunk := resp.read(1 << 20):
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(f"{name}: download larger than {max_bytes >> 20} MiB")
                h.update(chunk)
                out.write(chunk)
        digest = h.hexdigest()
        if sha256 and digest != sha256.lower():
            raise FetchError(f"{name}: sha256 mismatch (got {digest}, expected {sha256})")
        if not sha256:
            log(f"  WARNING: {name} has no pinned sha256; got {digest}")
        staging = dest.with_name(dest.name + ".new")
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        with zipfile.ZipFile(zpath) as zf:
            _safe_extract(zf, staging)
    (staging / ".hermit-source.json").write_text(json.dumps(
        {"origin": url, "sha256": digest, "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
    shutil.rmtree(dest, ignore_errors=True)
    staging.rename(dest)
    return digest


def fetch_all(sources_cfg: dict, sources_dir: Path, log, only: list[str] | None = None) -> None:
    sources_dir.mkdir(parents=True, exist_ok=True)
    failures = []
    for s in sources_cfg.get("source", []):
        name = s["name"]
        if only and name not in only:
            continue
        if not s.get("enabled", True):
            log(f"- {name}: disabled, skipped")
            continue
        dest = sources_dir / name
        log(f"- {name}")
        try:
            if "git" in s:
                rev = fetch_git(name, s["git"], s.get("ref"), dest, log)
            elif "zip" in s:
                rev = fetch_zip(name, s["zip"], s.get("sha256"), dest, log)
            else:
                raise FetchError("source needs either 'git' or 'zip'")
            log(f"  ok: {rev[:16]}")
        except (FetchError, OSError) as exc:
            failures.append(name)
            log(f"  FAILED: {exc} (keeping any previous copy)")
    if failures:
        raise FetchError(f"failed sources: {', '.join(failures)}")
