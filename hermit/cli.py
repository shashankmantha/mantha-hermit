"""Mantha Hermit (hermit): keeps Mantha Ray's YARA rule packs up to date from community rules."""
from __future__ import annotations

import argparse
import re
import os
import shlex
import sys
import time
import tomllib
from collections import Counter
from pathlib import Path

from . import __version__
from .classify import Category, Decision, Signal, load_categories, load_demotions, propose_severity, score
from .features import extract, upstream
from .parse import describe_source, load_rules
from .store import Store


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- config

class Config:
    def __init__(self, config_dir: Path):
        self.dir = config_dir.resolve()
        self.root = self.dir.parent

        def load(name, required=True):
            p = self.dir / name
            if not p.is_file():
                if required:
                    raise SystemExit(f"missing {p}")
                return {}
            with open(p, "rb") as fh:
                return tomllib.load(fh)
        self.main = load("hermit.toml")
        self.categories = load_categories(load("categories.toml"))
        self.sources = load("sources.toml", required=False)
        self.demotions = load_demotions(load("demotions.toml", required=False))
        paths = self.main.get("paths", {})
        self.sources_dir = self._path(paths.get("sources_dir", "sources"))
        self.state_db = self._path(paths.get("state_db", "state/hermit.sqlite"))
        self.out_dir = self._path(paths.get("out_dir", "out"))
        self.packs_dir = self._path(paths.get("packs_dir", "packs"))
        self.exclude_globs = list(self.main.get("parse", {}).get("exclude_globs", []))
        o = self.main.get("ollama", {})
        self.ollama_endpoint = os.environ.get("HERMIT_OLLAMA", o.get("endpoint", "http://127.0.0.1:11434"))
        self.ollama_model = os.environ.get("HERMIT_MODEL", o.get("model", "qwen2.5:7b-instruct"))
        self.ollama_timeout = int(o.get("timeout_seconds", 180))
        self.llm_min_conf = float(o.get("min_confidence", 0.6))
        self.llm_enabled = bool(o.get("enabled", True))
        think = o.get("think", False)
        self.ollama_think = None if think == "default" else bool(think)

    def _path(self, p: str) -> Path:
        p = Path(os.path.expanduser(p))
        return p if p.is_absolute() else self.root / p


def default_config_dir() -> Path:
    if env := os.environ.get("HERMIT_CONFIG"):
        return Path(env)
    here = Path.cwd() / "config"
    if (here / "hermit.toml").is_file():
        return here
    return Path(__file__).resolve().parent.parent / "config"


# ---------------------------------------------------------------- pipeline

def gather_sources(cfg: Config, extra: list[str]):
    roots: list[tuple[str, Path]] = []
    enabled: dict = {}
    conf_for: dict[str, dict] = {}
    if extra:
        for p in extra:
            path = Path(p).expanduser().resolve()
            if not path.is_dir():
                raise SystemExit(f"--rules {p}: not a directory")
            name = path.name
            if name.lower() in ("yara", "rules", "src", "signatures", "yara-rules") and path.parent != path:
                name = path.parent.name
            base, n = name, 2
            while name in {x[0] for x in roots}:
                name, n = f"{base}-{n}", n + 1
            roots.append((name, path))
    else:
        enabled = {s["name"]: s for s in cfg.sources.get("source", []) if s.get("enabled", True)}
        if not cfg.sources_dir.is_dir():
            raise SystemExit(f"no rule sources in {cfg.sources_dir}; run `hermit fetch` or pass --rules DIR")
        for d in sorted(cfg.sources_dir.iterdir()):
            if d.is_dir() and not d.name.endswith(".new") and (not enabled or d.name in enabled):
                sub = enabled.get(d.name, {}).get("paths")
                if sub:
                    for s in sub:
                        n = d.name if len(sub) == 1 else f"{d.name}-{Path(s).name}"
                        roots.append((n, d / s))
                        conf_for[n] = enabled.get(d.name, {})
                else:
                    roots.append((d.name, d))
                    conf_for[d.name] = enabled.get(d.name, {})
    sources = {}
    for name, root in roots:
        src = describe_source(name, root)
        if src.license == "unknown" and root != root.parent:  # licence may sit at the repo root
            for parent in list(root.parents)[:3]:
                lic = describe_source(name, parent)
                if lic.license != "unknown":
                    src.license, src.license_file, src.commit = lic.license, lic.license_file, src.commit or lic.commit
                    src.origin = src.origin or lic.origin
                    break
        if not src.origin:
            conf = conf_for.get(name, {})
            src.origin = conf.get("git") or conf.get("zip")
        if not src.commit and not extra:
            for parent in list(root.parents)[:3]:
                if c := describe_source(name, parent).commit:
                    src.commit, src.origin = c, src.origin or describe_source(name, parent).origin
                    break
        sources[name] = src
    return sources


def run_pipeline(cfg: Config, cats: list[Category], args, label: str, extra_manifest: dict | None = None):
    from . import emit, pipeline

    log(f"Reading rules ({'--rules' if args.rules else cfg.sources_dir})")
    sources = gather_sources(cfg, args.rules)
    ev = pipeline.load(cfg, sources, log)
    select = (lambda r: ev.novelty[r.key] != "seen") if args.new_only else None
    pipeline.score_all(ev, cfg, cats, select, log)
    if args.new_only:
        log(f"Only new or changed rules: {len(ev.candidates)}")
    pipeline.judge_borderline(ev, cfg, cats, use_llm=cfg.llm_enabled and not args.no_llm,
                              limit=args.llm_limit, two_pass=False, log=log)
    if ev.llm_status.startswith(("off", "unavailable")) and any(
            d.band == "review" for per in ev.decisions.values() for d in per.values()):
        ev.llm_status += "; borderline rules left for review"
    store, files, problems, all_rules = ev.store, ev.files, ev.problems, ev.all_rules
    novelty, first_run, files_by_key = ev.novelty, ev.first_run, ev.files_by_key
    candidates, feats, decisions = ev.candidates, ev.feats, ev.decisions
    compile_failures, demoted_log, not_applicable = ev.compile_failures, ev.demoted_log, ev.not_applicable
    llm_status, llm_errors = ev.llm_status, ev.llm_errors

    # ---- assemble packs
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out_dir = Path(args.out).resolve() if args.out else cfg.out_dir / f"{stamp}-{label}"
    out_dir.mkdir(parents=True, exist_ok=True)
    review_rows, cat_summaries = [], []
    for c in cats:
        picks, n_review, n_na = [], 0, 0
        for r in candidates:
            d = decisions.get(r.key, {}).get(c.name)
            if d is None:
                continue
            f = feats[r.key]
            sev, why = propose_severity(r, c)
            for dm in cfg.demotions:
                if dm.applies(r, c.name) and dm.action == "info" and sev != "info":
                    sev, why = "info", f"demoted: {dm.reason}"
                    demoted_log.append(f"{r.name} ({c.name}): info, {dm.reason}")
            n_na += d.band == "not_applicable"
            row = {"category": c.name, "rule": r.name, "source": r.source, "file": r.relpath,
                   "score": d.score, "decided_by": d.decided_by, "llm_confidence": d.llm_confidence or "",
                   "proposed_severity": sev, "novelty": novelty[r.key], "targets": " ".join(f.targets),
                   "reasons": " ; ".join(d.reasons), "llm_reason": d.llm_reason or "",
                   "description": r.meta.get("description", "")[:200]}
            if d.band == "include":
                picks.append({"rule": r, "decision": d, "severity": sev, "severity_reason": why,
                              "novelty": novelty[r.key], "targets": f.targets})
                if d.decided_by == "llm":
                    review_rows.append({**row, "status": "included by model"})
            elif d.band == "review":
                n_review += 1
                review_rows.append({**row, "status": "needs review"})
            elif d.decided_by == "llm":
                review_rows.append({**row, "status": "rejected by model"})
        manifest = emit.build_pack(out_dir, c, picks, files_by_key, sources, extra_manifest or {})
        cat_summaries.append({"name": c.name, "included": len(picks), "review": n_review,
                              "not_applicable": n_na,
                              "by_llm": sum(p["decision"].decided_by == "llm" for p in picks),
                              "severity": manifest["counts"]["by_severity"],
                              "compiles": not manifest["compile_errors"]})
    upstreams = Counter()
    for r in candidates:
        if any(d.band == "include" for d in decisions.get(r.key, {}).values()):
            up, lic = upstream(r)
            if up:
                upstreams[(up, lic)] += 1
    emit.write_review(out_dir, sorted(review_rows, key=lambda r: (r["category"], r["status"], -r["score"])))
    cmd = "hermit " + " ".join(shlex.quote(a) for a in sys.argv[1:])
    report = emit.write_report(out_dir, {
        "generated_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "command": cmd,
        "rules_total": len(all_rules), "files_total": len(files),
        "duplicates": sum(1 for r in all_rules if r.duplicate_of),
        "novelty": Counter(novelty[r.key] for r in all_rules), "first_run": first_run,
        "llm": llm_status, "categories": cat_summaries, "not_applicable_targets": not_applicable,
        "compile_failures": compile_failures, "file_problems": problems,
        "demoted": sorted(set(demoted_log)), "llm_errors": llm_errors,
        "sources": list(sources.values()), "upstreams": upstreams})
    if not args.dry_run:
        store.record_run(cmd, all_rules)
    latest = cfg.out_dir / "latest"
    if not args.out:
        try:
            if latest.is_symlink():
                latest.unlink()
            latest.symlink_to(out_dir.name)
        except OSError:
            pass
    log("")
    for s in cat_summaries:
        log(f"  {s['name']:<18} {s['included']:>5} included ({s['by_llm']} by model), "
            f"{s['review']} need review")
    log(f"\nReport: {report}")
    return out_dir


# ---------------------------------------------------------------- commands

def cmd_fetch(cfg, args):
    from .fetch import FetchError, fetch_all
    try:
        fetch_all(cfg.sources, cfg.sources_dir, log, args.only)
    except FetchError as exc:
        raise SystemExit(str(exc))


def cmd_sort(cfg, args):
    names = args.category or list(cfg.categories)
    unknown = [n for n in names if n not in cfg.categories]
    if unknown:
        raise SystemExit(f"unknown categories {unknown}; known: {list(cfg.categories)}")
    label = "new" if args.new_only else "sort"
    run_pipeline(cfg, [cfg.categories[n] for n in names], args, label)


def cmd_find(cfg, args):
    from . import llm as llm_mod
    plan = None
    if args.terms or args.strings:
        slug = re.sub(r"[^a-z0-9]+", "-", args.query.lower()).strip("-")[:40] or "find"
        plan = {"slug": slug, "description": args.query, "name_terms": args.terms or [],
                "string_terms": args.strings or [], "exclude_terms": args.exclude or [],
                "targets_allow": [], "targets_deny": []}
    elif args.no_llm or not cfg.llm_enabled:
        raise SystemExit("without the model, give search terms: --terms ... [--strings ...]")
    else:
        client = llm_mod.Ollama(cfg.ollama_endpoint, cfg.ollama_model, cfg.ollama_timeout,
                            think=cfg.ollama_think)
        try:
            client.check()
            plan = llm_mod.plan_query(client, args.query)
        except llm_mod.LLMError as exc:
            raise SystemExit(f"model unavailable ({exc}); pass --terms to search without it")
        if args.exclude:
            plan["exclude_terms"] += args.exclude
    if not plan["name_terms"] and not plan["string_terms"]:
        raise SystemExit("no usable search terms; pass --terms")
    log("Search plan:")
    for k in ("description", "name_terms", "string_terms", "exclude_terms", "targets_allow", "targets_deny"):
        log(f"  {k}: {plan[k]}")
    defaults = cfg.categories.get("core-threats")
    deny = plan["targets_deny"] or (defaults.targets_deny if defaults else [])
    sigs = []
    if plan["name_terms"]:
        sigs.append(Signal(4, ["name", "tags"], plan["name_terms"], "query terms in name/tags"))
        sigs.append(Signal(2, ["description"], plan["name_terms"], "query terms in description"))
    if plan["string_terms"]:
        sigs.append(Signal(2, ["strings"], plan["string_terms"], "query strings"))
        sigs.append(Signal(2, ["name", "description"], plan["string_terms"], "query strings in name"))
    if plan["exclude_terms"]:
        sigs.append(Signal(-4, ["name", "tags", "description"], plan["exclude_terms"], "excluded"))
    cat = Category(name=plan["slug"],
                   description=plan["description"], kind="query", include_score=4, review_score=2,
                   targets_allow=plan["targets_allow"],
                   targets_deny=[t for t in deny if t not in plan["targets_allow"]], signals=sigs)
    run_pipeline(cfg, [cat], args, f"find-{cat.name}", {"query": args.query, "search_plan": plan})


def cmd_test(cfg, args):
    from . import cleantest
    res = cleantest.run(Path(args.pack), [Path(d) for d in args.clean], log, timeout=args.timeout)
    log(f"Scanned {res['files']} clean files; {len(res['rules_fired'])} rules fired, "
        f"{len(res['false_positives'])} of them threat/suspicious (false positives).")
    for r in res["false_positives"][:25]:
        info = res["rules_fired"][r]
        log(f"  {r} [{info['severity']}]: {info['files']} files, e.g. {info['examples'][0]}")
    if res["false_positives"]:
        log(f"Suggested demotions written to {Path(args.pack) / 'demotions.suggested.toml'}")


def cmd_explain(cfg, args):
    store = Store(cfg.state_db)
    sources = gather_sources(cfg, args.rules)
    files, _ = load_rules(list(sources.values()), cfg.exclude_globs, store, lambda m: None)
    store.commit()
    found = [r for f in files for r in f.rules if r.name == args.rule or r.name.lower() == args.rule.lower()]
    if not found:
        raise SystemExit(f"no rule named {args.rule}")
    for r in found:
        f = extract(r)
        print(f"\n{r.name}  ({r.source}/{r.relpath})")
        print(f"  description: {r.meta.get('description', '-')[:200]}")
        print(f"  compiles: {r.compile_ok}{'' if r.compile_ok else ' - ' + str(r.compile_error)}")
        if r.duplicate_of:
            print(f"  duplicate of {r.duplicate_of}")
        print("  file types: " + "; ".join(f.target_reasons))
        for c in cfg.categories.values():
            d = score(r, f, c)
            sev, why = propose_severity(r, c)
            print(f"  [{c.name}] score {d.score} -> {d.band}, severity {sev} ({why})")
            for reason in d.reasons:
                print(f"      {reason}")


def cmd_ask(cfg, args):
    from .ask import Ask
    sys.exit(Ask(cfg, args, log).run(args.request))


def cmd_auto(cfg, args):
    from .ask import run_auto
    sys.exit(run_auto(cfg, args, log))


def cmd_apply(cfg, args):
    import json
    from .ask import apply_proposal, summarise
    proposal = json.loads(Path(args.proposal).read_text())
    if proposal.get("hermit_proposal") != 1:
        raise SystemExit(f"{args.proposal} is not a hermit proposal")
    log(summarise(proposal))
    v = apply_proposal(cfg, proposal, log)
    log(f"{proposal['target_pack']}: now v{v}. Undo with: hermit rollback {proposal['target_pack']}")


def cmd_promote(cfg, args):
    from .ask import Ask
    from .livepacks import LivePack, list_packs
    a = Ask(cfg, args, log)
    packs = [LivePack.open(cfg.packs_dir, n) for n in args.pack] if args.pack else list_packs(cfg.packs_dir)
    for p in packs:
        if not p.exists:
            log(f"{p.name}: no live pack")
            continue
        if args.now and not args.yes:
            n = sum(1 for e in p.entries.values() if e.get("status") == "probation")
            if n and sys.stdin.isatty():
                if input(f"{p.name}: end probation now for {n} rules (clean-set tested first)? [y/N] ").strip().lower() not in ("y", "yes"):
                    continue
            elif n:
                raise SystemExit("--now changes many severities; confirm interactively or add --yes")
        done = a.promote_due(p, now=args.now)
        log(f"{p.name}: {len(done)} rule{'' if len(done) == 1 else 's'} finished probation" + (f" (now v{p.version})" if done else ""))
        for d in done[:20]:
            log(f"  {d}")


def cmd_packs(cfg, args):
    from .ask import pack_status
    from .livepacks import list_packs
    packs = list_packs(cfg.packs_dir)
    if not packs:
        print(f"No live packs in {cfg.packs_dir} yet. Try: hermit ask \"add all new rules related to video games\"")
    for p in packs:
        print(pack_status(p))
        if args.history:
            for h in p.history()[-args.history:]:
                print(f"    v{h['version']} {h['at'][:16]}  {h['summary']}")


def cmd_rollback(cfg, args):
    from .livepacks import LivePack
    p = LivePack.open(cfg.packs_dir, args.pack)
    if not p.exists:
        raise SystemExit(f"no live pack named {args.pack}")
    before = p.version
    v = p.rollback(args.to)
    log(f"{args.pack}: rolled back to the contents of v{args.to or before - 1}, saved as v{v}")


def cmd_export_bundle(cfg, args):
    from .bundle import BundleError, build_tree, check_yara_x_pin, BundleSettings
    if not args.unsigned:
        raise SystemExit("export-bundle only writes unsigned folders (phase 1a); pass --unsigned, "
                         "or use `hermit publish` for a signed bundle")
    dest = Path(args.dir).expanduser().resolve()
    if dest.exists():
        if not args.force:
            raise SystemExit(f"{dest} already exists (use --force to replace it)")
        if dest.is_dir() and not (dest / "manifest.json").is_file() and any(dest.iterdir()):
            raise SystemExit(f"{dest} isn't empty and isn't a bundle folder; refusing to replace it")
    if msg := check_yara_x_pin(BundleSettings(cfg)):
        log(f"Note: {msg}. Leaving out pack.yarx; Mantha Ray will compile the rule text.")
    log(f"Exporting packs to {dest}")
    tmp = dest.with_name(dest.name + ".new")
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        built = build_tree(cfg, tmp, log, only=args.pack or None,
                           include_compiled=False if msg else None)
    except BundleError as exc:
        raise SystemExit(str(exc))
    if dest.exists():
        shutil.rmtree(dest)
    tmp.rename(dest)
    m = built["manifest"]
    log(f"\nBundle {m['bundle_version']} (unsigned) in {dest}: {len(m['packs'])} packs, validated against contract v1.")
    log(f"Changes: {m['changes']}")


def cmd_publish(cfg, args):
    from .bundle import BundleError, publish
    try:
        res = publish(cfg, log, only=args.pack or None, push=not args.no_push,
                      allow_version_mismatch=args.allow_version_mismatch)
    except BundleError as exc:
        raise SystemExit(str(exc))
    log(f"\nPublished {res['version']}: {res['tarball']}")
    log(f"  sha256 {res['sha256']}")
    log(f"  changes: {res['manifest']['changes']}")
    if res["url"]:
        log(f"  release: {res['url']}")


def cmd_verify(cfg, args):
    from .bundle import BundleError, BundleSettings, verify_bundle
    from .contract import ContractError
    from .signing import SignatureError
    pub = Path(args.pubkey) if args.pubkey else BundleSettings(cfg).public_key
    if not pub.is_file():
        raise SystemExit(f"public key {pub} not found (pass --pubkey)")
    try:
        s = verify_bundle(Path(args.bundle), pub.read_text(), compile_rules=not args.no_compile,
                          installed_version=args.installed)
    except (BundleError, ContractError, SignatureError) as exc:
        raise SystemExit(f"REJECTED: {exc}")
    print(f"OK: bundle {s['bundle_version']} (signed: \"{s['trusted_comment']}\"), "
          f"YARA-X {s['yara_x_version']}, needs Mantha Ray >= {s['min_app_version']}"
          + (" (same as installed: nothing to update)" if s["same_as_installed"] else ""))
    for p in s["packs"]:
        print(f"  {p['id']} v{p['version']}: {p['rules']} rule{'' if p['rules'] == 1 else 's'}"
              + (f", {p['without_severity']} without a severity (treated as info)" if p["without_severity"] else ""))


def cmd_validate(cfg, args):
    from .contract import ContractError, validate_bundle, validate_pack
    d = Path(args.dir)
    try:
        if (d / "manifest.json").is_file():
            s = validate_bundle(d, compile_rules=not args.no_compile)
            print(f"OK: bundle {s['bundle_version']}, {len(s['packs'])} packs")
        else:
            s = validate_pack(d, compile_rules=not args.no_compile, allow_state=True)
            print(f"OK: pack {s['id']} v{s['version']}, {s['rules']} rules")
    except ContractError as exc:
        raise SystemExit(f"INVALID: {exc}")


def cmd_keygen(cfg, args):
    from .bundle import BundleSettings
    from .signing import SignatureError, generate_keypair, generate_protected_keypair
    s = BundleSettings(cfg)
    try:
        if args.no_password:
            line = generate_keypair(s.public_key, s.secret_key, force=args.force)
        else:
            line = generate_protected_keypair(s.public_key, s.secret_key, force=args.force)
    except SignatureError as exc:
        raise SystemExit(str(exc))
    log(f"Secret key: {s.secret_key} (owner-only permissions; never commit it; back it up offline)")
    log(f"Public key: {s.public_key}  ->  copy this file into Mantha Ray's repo")
    log(f"  {line}")
    if args.no_password:
        log("This key has no password: use it for demos and testing only. A release key can push rules "
            "to every install; run `hermit keygen` without --no-password for that.")


def cmd_serve(cfg, args):
    from .server import serve
    mode = "none" if args.no_browser else "browser" if args.browser else "window"
    serve(cfg, args.port, mode, log)


def cmd_desktop_entry(cfg, args):
    """Add Mantha Hermit to the desktop's app menu (opens in its own window)."""
    import shutil
    exe = Path(sys.executable).with_name("hermit")
    if not exe.is_file():
        exe = Path(shutil.which("hermit") or "hermit")
    apps = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "applications"
    entry = apps / "mantha-hermit.desktop"
    if args.remove:
        entry.unlink(missing_ok=True)
        log(f"Removed {entry}")
        return

    def q(s) -> str:  # desktop-entry quoting
        return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`").replace("$", "\\$") + '"'
    apps.mkdir(parents=True, exist_ok=True)
    entry.write_text("\n".join([
        "[Desktop Entry]", "Type=Application", "Name=Mantha Hermit",
        "Comment=Curate YARA rule packs for Mantha Ray",
        f"Exec={q(exe)} --config-dir {q(cfg.dir)} serve",
        f"Path={cfg.root}", "Terminal=false",
        "Categories=Development;Security;", "StartupNotify=true", ""]))
    log(f"Added Mantha Hermit to your app menu ({entry}).")
    log("It opens in its own window; requests keep running until they finish even if you close it.")


def cmd_status(cfg, args):
    store = Store(cfg.state_db)
    c = store.counts()
    last = store.last_run()
    print(f"config:   {cfg.dir}")
    print(f"sources:  {cfg.sources_dir} ({', '.join(sorted(p.name for p in cfg.sources_dir.iterdir() if p.is_dir())) if cfg.sources_dir.is_dir() else 'none fetched'})")
    print(f"state:    {cfg.state_db}: {c['runs']} runs, {c['rules_known']} rules known, "
          f"{c['llm_answers_cached']} model answers cached")
    print(f"last run: {last[1] if last else 'never'}")
    print(f"model:    {cfg.ollama_model} at {cfg.ollama_endpoint} ({'enabled' if cfg.llm_enabled else 'disabled'})")
    print(f"packs:    {', '.join(cfg.categories)}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="hermit", description=__doc__)
    ap.add_argument("--config-dir", type=Path, default=None)
    ap.add_argument("--version", action="version", version=f"hermit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--rules", action="append", default=[], metavar="DIR",
                       help="read rules from DIR instead of the fetched sources (repeatable)")

    def run_opts(p):
        common(p)
        p.add_argument("--new-only", action="store_true", help="only rules new or changed since the last run")
        p.add_argument("--no-llm", action="store_true", help="don't ask the local model; borderline rules go to review.csv")
        p.add_argument("--llm-limit", type=int, default=None, help="ask the model about at most N borderline rules")
        p.add_argument("--out", help="output folder (default out/<timestamp>-<label>)")
        p.add_argument("--dry-run", action="store_true", help="don't record this run (rules stay 'new')")

    p = sub.add_parser("fetch", help="download the rule sources in sources.toml")
    p.add_argument("--only", nargs="+", help="fetch only these source names")
    p.set_defaults(fn=cmd_fetch)

    p = sub.add_parser("sort", help="sort rules into the packs in categories.toml")
    p.add_argument("-c", "--category", action="append", help="only this pack (repeatable)")
    run_opts(p)
    p.set_defaults(fn=cmd_sort)

    p = sub.add_parser("find", help="ad-hoc: find rules matching a question")
    p.add_argument("query", help='e.g. "rules for stealers spread through fake game cheats"')
    p.add_argument("--terms", nargs="+", help="search terms for names/tags/descriptions (skips the model's plan)")
    p.add_argument("--strings", nargs="+", help="literal strings to look for inside rules")
    p.add_argument("--exclude", nargs="+", help="terms that mark rules to leave out")
    run_opts(p)
    p.set_defaults(fn=cmd_find)

    p = sub.add_parser("test", help="run a pack against clean files and suggest demotions")
    p.add_argument("pack", help="a pack folder from a sort/find run")
    p.add_argument("--clean", action="append", required=True, metavar="DIR")
    p.add_argument("--timeout", type=int, default=30, help="per-file scan timeout in seconds")
    p.set_defaults(fn=cmd_test)

    p = sub.add_parser("explain", help="show why a rule scores as it does in each pack")
    p.add_argument("rule")
    common(p)
    p.set_defaults(fn=cmd_explain)

    p = sub.add_parser("ask", help='carry out a request, e.g. "add all new rules related to video games"')
    p.add_argument("request")
    common(p)
    p.add_argument("--yes", "-y", action="store_true", help="apply even if a safety gate trips")
    p.add_argument("--no-input", action="store_true", help="never prompt; hold the proposal if a gate trips")
    p.add_argument("--dry-run", action="store_true", help="show what would change, apply nothing")
    p.add_argument("--plan-only", action="store_true", help="only show how the request was understood")
    p.add_argument("--no-fetch", action="store_true", help="don't fetch sources first")
    p.add_argument("--no-llm", action="store_true", help="don't use the model (rules-only understanding)")
    p.add_argument("--llm-limit", type=int, default=None, help="ask the model about at most N borderline rules")
    p.set_defaults(fn=cmd_ask)

    p = sub.add_parser("auto", help="scheduled run: add new rules to every pack (never prompts)")
    p.add_argument("pack", nargs="*", help="only these packs (default: all in categories.toml)")
    common(p)
    p.add_argument("--yes", "-y", action="store_true", help="apply even if a safety gate trips")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-fetch", action="store_true")
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--llm-limit", type=int, default=None)
    p.set_defaults(fn=cmd_auto, plan_only=False)

    p = sub.add_parser("apply", help="apply a held proposal from `ask`")
    p.add_argument("proposal")
    p.set_defaults(fn=cmd_apply)

    p = sub.add_parser("promote", help="end probation for rules whose time is up (clean-set checked)")
    p.add_argument("pack", nargs="*")
    p.add_argument("--now", action="store_true", help="end probation early for every rule (clean-set tested first)")
    p.add_argument("--yes", "-y", action="store_true", help="don't ask before --now")
    p.add_argument("--no-llm", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(fn=cmd_promote)

    p = sub.add_parser("packs", help="list the live packs")
    p.add_argument("--history", type=int, default=0, metavar="N", help="also show the last N versions")
    p.set_defaults(fn=cmd_packs)

    p = sub.add_parser("rollback", help="restore a pack's previous version (as a new version)")
    p.add_argument("pack")
    p.add_argument("--to", type=int, help="version to restore (default: the one before the current)")
    p.set_defaults(fn=cmd_rollback)

    p = sub.add_parser("export-bundle", help="write the live packs as an unsigned bundle folder (contract v1)")
    p.add_argument("dir")
    p.add_argument("--unsigned", action="store_true", help="required: this folder carries no signature")
    p.add_argument("--pack", action="append", help="only this pack (repeatable)")
    p.add_argument("--force", action="store_true", help="replace an existing bundle folder")
    p.set_defaults(fn=cmd_export_bundle)

    p = sub.add_parser("publish", help="build, sign and (with release_repo set) push a bundle")
    p.add_argument("--pack", action="append", help="only this pack (repeatable)")
    p.add_argument("--no-push", action="store_true", help="build and sign only")
    p.add_argument("--allow-version-mismatch", action="store_true",
                   help="publish even if yara-x differs from the pin (pack.yarx is left out)")
    p.set_defaults(fn=cmd_publish)

    p = sub.add_parser("verify", help="check a bundle the way Mantha Ray will: signature, unpack, contract")
    p.add_argument("bundle")
    p.add_argument("--pubkey", help="public key file (default: [bundle] public_key)")
    p.add_argument("--no-compile", action="store_true", help="skip compiling the rules")
    p.add_argument("--installed", metavar="VERSION",
                   help="the installed bundle_version: refuse an older bundle, as the updater does")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("validate", help="strict contract check of a bundle folder or a pack folder")
    p.add_argument("dir")
    p.add_argument("--no-compile", action="store_true")
    p.set_defaults(fn=cmd_validate)

    p = sub.add_parser("keygen", help="create the minisign key pair for signing bundles")
    p.add_argument("--force", action="store_true")
    p.add_argument("--no-password", action="store_true",
                   help="no password (demos and testing only; needs no minisign tool)")
    p.set_defaults(fn=cmd_keygen)

    p = sub.add_parser("serve", help="open the app in its own window (127.0.0.1 only)")
    p.add_argument("--port", type=int, default=None,
                   help="port to use (default: a free one for the window, 8765 for --browser)")
    p.add_argument("--browser", action="store_true", help="open it in your web browser instead of its own window")
    p.add_argument("--no-browser", action="store_true", help="just run the server; open the address yourself")
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("desktop-entry", help="add Mantha Hermit to your desktop's app menu")
    p.add_argument("--remove", action="store_true", help="remove it from the menu again")
    p.set_defaults(fn=cmd_desktop_entry)

    p = sub.add_parser("status", help="show configuration and state")
    p.set_defaults(fn=cmd_status)

    args = ap.parse_args(argv)
    cfg = Config(args.config_dir or default_config_dir())
    args.fn(cfg, args)


if __name__ == "__main__":
    main()