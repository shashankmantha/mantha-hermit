"""`hermit ask "<request>"`: carry out a plain-English request against the live packs.

The model only (a) turns the request into a validated command and (b) judges borderline
rules. Everything it can trigger is a fixed step below; it never runs anything else.
"""
from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

from . import intent as intent_mod
from . import llm as llm_mod
from . import pipeline
from .classify import Category, Signal, propose_severity, score
from .cleantest import scan_dirs
from .features import extract, upstream
from .livepacks import LivePack, compile_entries, effective_severity, entry_rule, list_packs, make_entry, namespace

EXIT_HELD = 3


def source_info(src) -> dict:
    if src is None:
        return {}
    return {"name": src.name, "url": src.origin, "revision": src.commit, "licence": src.license}


class Ask:
    def __init__(self, cfg, args, log, on_step=None):
        self.cfg, self.args, self.log = cfg, args, log
        self.auto = cfg.main.get("automation", {})
        self.today = datetime.now(timezone.utc).date()
        self.on_step = on_step          # GUI hook: called with each step as it happens
        self.steps: list[dict] = []
        self.result: dict = {}
        self.clean_stats: dict = {}

    def step(self, key: str, label: str, detail: str = "", state: str = "done") -> None:
        s = {"key": key, "label": label, "detail": detail, "state": state}
        self.steps = [x for x in self.steps if x["key"] != key] + [s]
        if self.on_step:
            self.on_step(s)

    # ------------------------------------------------------------ helpers

    def pack_catalogue(self) -> dict[str, str]:
        packs = {n: c.description for n, c in self.cfg.categories.items()}
        for p in list_packs(self.cfg.packs_dir):
            packs.setdefault(p.name, p.data.get("description") or "custom pack")
        return packs

    def client(self):
        if self.args.no_llm or not self.cfg.llm_enabled:
            return None
        c = llm_mod.Ollama(self.cfg.ollama_endpoint, self.cfg.ollama_model, self.cfg.ollama_timeout,
                            think=self.cfg.ollama_think)
        try:
            c.check()
            return c
        except llm_mod.LLMError as exc:
            self.log(f"Model unavailable ({exc}); continuing without it")
            return None

    def understand(self, request: str, client) -> dict:
        packs = self.pack_catalogue()
        aliases = {n: c.aliases for n, c in self.cfg.categories.items()}
        aliases.update({n: [] for n in packs if n not in aliases})
        errors = []
        if client:
            try:
                it = llm_mod.interpret(client, request, packs, self.today.isoformat())
                it["understood_by"] = "model"
                return it
            except (llm_mod.LLMError, llm_mod.IntentError) as exc:
                errors.append(f"model: {exc}")
        if errors:
            self.log(f"Model's reading was rejected ({errors[0][7:]}); using the built-in parser")
        try:
            it = intent_mod.parse(request, packs, aliases, self.today)
            it["understood_by"] = "rules"
            return it
        except llm_mod.IntentError as exc:
            errors.append(f"rules: {exc}")
        raise SystemExit("Couldn't understand the request:\n  " + "\n  ".join(errors))

    def describe(self, it: dict, pack: LivePack) -> list[str]:
        sel = {"new": f"rules not yet considered for {it['target_pack']}"
                      + (f" (last updated {pack.data['updated_at'][:10]})" if pack.data.get("updated_at") else " (first update)"),
               "all": "all rules", "since": f"rules first seen since {it['since']}"}[it["selection"]]
        topic = (f"matching the {it['topic_pack']} pack definition" if it["topic_pack"]
                 else f"about \"{it['topic_text']}\"" if it["topic_text"] else "")
        if it["rule_names"]:
            topic = (topic + " plus " if topic else "") + "named: " + ", ".join(it["rule_names"][:8])
        if it["action"] == "report":
            return [f"Report on {it['target_pack']}" + (f" since {it['since']}" if it["since"] else ""),
                    f"(understood by {it['understood_by']})"]
        verb = {"add": f"Add to {it['target_pack']}", "remove": f"Remove from {it['target_pack']}"}[it["action"]]
        lines = [f"{verb}: {sel} {topic}".rstrip()]
        if it["action"] == "add":
            fetching = (not self.args.rules and not getattr(self.args, "no_fetch", False)
                        and self.auto.get("fetch_before_ask", True))
            steps = (["fetch sources"] if fetching else []) + [
                "promote rules past probation", "score",
                "ask the model about borderline rules" if not self.args.no_llm and self.cfg.llm_enabled
                else "defer borderline rules (no model)", "clean-set test", "apply as a new pack version"]
            lines.append("Steps: " + ", ".join(steps))
        lines.append(f"(understood by {it['understood_by']})")
        return lines

    def topic_category(self, it: dict, client) -> Category:
        if it["topic_pack"]:
            return self.cfg.categories[it["topic_pack"]]
        text = it["topic_text"] or ""
        if client and text:
            plan = llm_mod.plan_query(client, text)
        else:
            words = [w for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]{2,}", text) if w.lower() not in
                     {"the", "and", "rules", "rule", "about", "related", "with", "for", "all", "new"}]
            plan = {"description": text, "name_terms": words, "string_terms": [], "exclude_terms": [],
                    "targets_allow": [], "targets_deny": []}
        self.log(f"Search terms: {plan['name_terms'][:20]}" + (f", strings {plan['string_terms'][:8]}" if plan["string_terms"] else ""))
        base = self.cfg.categories.get("core-threats")
        sigs = []
        if plan["name_terms"]:
            sigs += [Signal(4, ["name", "tags"], plan["name_terms"], "topic in name/tags"),
                     Signal(2, ["description"], plan["name_terms"], "topic in description")]
        if plan["string_terms"]:
            sigs.append(Signal(2, ["strings"], plan["string_terms"], "topic strings"))
        if plan["exclude_terms"]:
            sigs.append(Signal(-4, ["name", "tags", "description"], plan["exclude_terms"], "excluded"))
        deny = plan["targets_deny"] or (base.targets_deny if base else [])
        return Category(name=f"topic:{it['target_pack']}", description=plan["description"] or text,
                        kind="query", targets_allow=plan["targets_allow"],
                        targets_deny=[t for t in deny if t not in plan["targets_allow"]], signals=sigs)

    def severity_category(self, it: dict, topic: Category) -> Category:
        return self.cfg.categories.get(it["target_pack"]) or topic

    # ------------------------------------------------------------ clean set

    def clean_check(self, entries: list[dict]) -> dict[str, list[str]]:
        """key -> clean files it fired on (only for entries whose effective severity isn't already info...
        all entries are checked: an info rule that fires everywhere is still noise)."""
        dirs = [Path(d).expanduser() for d in self.auto.get("clean_dirs", [])]
        if not dirs or not entries:
            self.clean_stats = {"tested": False, "rules": len(entries)}
            return {}
        self.step("clean", "Clean-set test", f"scanning {len(entries)} rules", state="running")
        rules, errors = compile_entries(entries)
        if errors:
            raise SystemExit(f"proposed rules don't compile together: {errors[:2]}")
        self.log(f"Clean-set test: {len(entries)} rules against {', '.join(map(str, dirs))}")
        raw, stats = scan_dirs(rules, dirs, self.log, int(self.auto.get("clean_scan_timeout_seconds", 30)))
        by_ns = {(namespace(e["source"], e["relpath"]), e["name"]): e["key"] for e in entries}
        out = {}
        for k, files in raw.items():
            if k in by_ns:
                out[by_ns[k]] = files
        self.log(f"  {stats['files']} files scanned, {len(out)} of the rules fired")
        self.clean_stats = {"tested": True, "rules": len(entries), "files": stats["files"],
                            "fired": len(out), "dirs": [str(d) for d in dirs]}
        self.step("clean", "Clean-set test", f"{plural(stats['files'], 'clean file')}, {len(out)} fired")
        return out

    def apply_clean_results(self, entries: list[dict], hits: dict[str, list[str]],
                            drops: list[dict]) -> list[dict]:
        limit = int(self.auto.get("drop_after_clean_hits", 3))
        kept = []
        for e in entries:
            files = hits.get(e["key"])
            if not files:
                kept.append(e)
                continue
            why = f"fired on {len(files)} clean file(s), e.g. {Path(files[0]).name}"
            if len(files) >= limit:
                drops.append({"key": e["key"], "name": e["name"], "reason": why})
                continue
            e["demoted"] = why
            e["severity"] = effective_severity(e)
            kept.append(e)
        return kept

    # ------------------------------------------------------------ probation

    def promote_due(self, pack: LivePack, now: bool = False) -> list[str]:
        """End probation for rules whose time is up (or all of them with now=True). Every rule is
        scanned against the clean set first; hits keep it at info or drop it."""
        due = [e for e in pack.entries.values() if e.get("status") == "probation"
               and (now or (e.get("probation_until") and e["probation_until"] <= self.today.isoformat()))]
        if not due:
            return []
        hits = self.clean_check(due)
        drops: list[dict] = []
        details = []
        limit = int(self.auto.get("drop_after_clean_hits", 3))
        for e in due:
            files = hits.get(e["key"])
            if files and len(files) >= limit:
                pack.entries.pop(e["key"])
                pack.data.setdefault("excluded", {})[e["key"]] = f"dropped after probation: fired on {len(files)} clean files"
                details.append(f"dropped {e['name']}: fired on {len(files)} clean files")
                continue
            e["status"] = "active"
            if files:
                e["demoted"] = f"fired on {len(files)} clean file(s) during probation"
            e["severity"] = effective_severity(e)
            details.append(f"{'promoted' if not files else 'kept at info'} {e['name']} -> {e['severity']}")
        if not self.auto.get("clean_dirs"):
            self.log("Note: no clean_dirs configured, so these rules were promoted without a clean-set test")
        errors = pack.commit(f"Probation ended for {len(due)} rules" + (" (early, on request)." if now else "."),
                             details, {})
        if errors:
            raise SystemExit(f"{pack.name}: promotion broke compilation: {errors[:2]}")
        return details

    # ------------------------------------------------------------ gates

    def gates(self, pack: LivePack, n_changes: int, it: dict, new_pack: bool) -> list[str]:
        g = []
        size = len(pack.entries)
        limit = max(int(self.auto.get("max_change_rules", 25)),
                    int(size * float(self.auto.get("max_change_fraction", 0.15))))
        if n_changes > limit and size == 0:
            g.append(f"{n_changes} rules would fill a new pack at once (the limit is {limit})")
        elif n_changes > limit:
            g.append(f"{n_changes} changes is more than the limit of {limit} for a pack of {size} rules")
        if new_pack:
            g.append(f"creates a new pack '{it['target_pack']}' that isn't defined in categories.toml")
        if it["action"] == "remove" and n_changes:
            g.append("removes rules")
        return g

    def confirm_or_hold(self, gates: list[str], proposal_path: Path) -> bool:
        if not gates or self.args.yes:
            return True
        self.log("\nNeeds your OK before applying:")
        for x in gates:
            self.log(f"  - {x}")
        if sys.stdin.isatty() and not self.args.no_input:
            ans = input("Apply? [y/N] ").strip().lower()
            return ans in ("y", "yes")
        self.log(f"\nHeld. Proposal saved: {proposal_path}\nApply it later with: hermit apply {proposal_path}")
        return False

    # ------------------------------------------------------------ main

    def run(self, request: str, preset: dict | None = None) -> int:
        self.step("understand", "Understand the request", "", state="running")
        client = self.client()
        it = preset or self.understand(request, client)
        self.result = {"intent": it, "pack": it["target_pack"], "outcome": "planned"}
        self.step("understand", "Understand the request",
                  f"{ {'add': 'add to', 'remove': 'remove from', 'report': 'report on'}[it['action']]} {it['target_pack']}, "
                  f"read by {'the model' if it['understood_by'] == 'model' else 'the built-in parser' if it['understood_by'] == 'rules' else it['understood_by']}")
        target_cat = self.cfg.categories.get(it["target_pack"])
        pack = LivePack.open(self.cfg.packs_dir, it["target_pack"],
                             kind=target_cat.kind if target_cat else "detection",
                             description=target_cat.description if target_cat else (it["topic_text"] or ""),
                             editions=target_cat.editions if target_cat else None)
        self.log("Plan:\n  " + "\n  ".join(self.describe(it, pack)))
        if self.args.plan_only:
            print(json.dumps(it, indent=2))
            return 0
        if it["action"] == "report":
            return self.report(pack, it)

        if not self.args.rules and self.auto.get("fetch_before_ask", True) and not self.args.no_fetch:
            from .fetch import FetchError, fetch_all
            self.log("\nFetching sources")
            self.step("fetch", "Fetch rule sources", "", state="running")
            try:
                fetch_all(self.cfg.sources, self.cfg.sources_dir, self.log)
                self.step("fetch", "Fetch rule sources", "up to date")
            except FetchError as exc:
                self.log(f"  {exc}; continuing with the copies already here")
                self.step("fetch", "Fetch rule sources", "failed; used the copies already here", state="warn")

        if pack.exists and it["action"] == "add":
            if promoted := self.promote_due(pack):
                self.log(f"\nProbation: {len(promoted)} rules reviewed (v{pack.version})")
                self.step("probation", "End probation for rules whose time is up", plural(len(promoted), "rule"))

        from .cli import gather_sources
        sources = gather_sources(self.cfg, self.args.rules)
        self.step("load", "Read and compile-check rules", "", state="running")
        ev = pipeline.load(self.cfg, sources, self.log)
        self.step("load", "Read and compile-check rules",
                  f"{plural(len(ev.all_rules), 'rule')} from {plural(len(sources), 'source')}")
        if it["action"] == "remove":
            return self.remove(pack, it, ev, client)
        return self.add(pack, it, ev, client, target_cat is None and not pack.exists)

    def selector(self, pack: LivePack, it: dict, ev):
        excluded = pack.data.get("excluded", {})
        names = set(it["rule_names"])
        first_seen = dict(ev.store.db.execute("SELECT key, first_seen_at FROM rules")) if it["selection"] == "since" else {}

        def select(r) -> bool:
            if r.name in names:
                return True
            if r.key in excluded:
                return False
            if it["selection"] == "new":
                return pack.is_new_to_pack(r)
            if it["selection"] == "since":
                seen = first_seen.get(r.key)
                return seen is None or seen[:10] >= it["since"]
            return True
        return select

    def add(self, pack: LivePack, it: dict, ev, client, new_pack: bool) -> int:
        topic = self.topic_category(it, client) if (it["topic_pack"] or it["topic_text"]) else None
        cats = [topic] if topic else []
        select = self.selector(pack, it, ev)
        if topic:
            pipeline.score_all(ev, self.cfg, cats, select, self.log)
            bands = Counter(per[topic.name].band for per in ev.decisions.values() if topic.name in per)
            self.step("score", "Score against the pack",
                      f"{plural(len(ev.candidates), 'new rule')}: {bands.get('include', 0)} clear, "
                      f"{bands.get('review', 0)} borderline")
            if bands.get("review"):
                self.step("judge", "Ask the model about borderline rules",
                          f"{bands['review']} to judge, two passes each" if client else "no model: deferred",
                          state="running" if client else "warn")
            pipeline.judge_borderline(ev, self.cfg, cats, use_llm=client is not None,
                                      limit=self.args.llm_limit, two_pass=bool(self.auto.get("two_pass", True)),
                                      log=self.log)
            if bands.get("review") and client:
                after = Counter(per[topic.name].band for per in ev.decisions.values() if topic.name in per)
                self.step("judge", "Ask the model about borderline rules",
                          f"{after.get('include', 0) - bands.get('include', 0)} in, "
                          f"{after.get('uncertain', 0)} unsure, {after.get('review', 0)} left for later")
            if client:
                self.log(f"Model: {ev.llm_status if ev.llm_status != 'off' else 'not needed (no borderline rules)'}")
        else:
            ev.candidates = [r for r in ev.all_rules if select(r) and not r.is_private and not r.is_global]
            for r in ev.candidates:
                ev.feats[r.key] = extract(r)
        names = set(it["rule_names"])
        sev_cat = self.severity_category(it, topic) if topic else (self.cfg.categories.get(it["target_pack"])
                                                                   or Category(it["target_pack"], ""))
        probation = int(self.auto.get("probation_days", 14))
        policy = self.auto.get("uncertain_policy", "info")
        files_by_key = ev.files_by_key
        version = pack.version + 1
        additions, updates, skipped, deferred = [], [], Counter(), set()
        missing_names = names - {r.name for r in ev.candidates}
        for r in ev.candidates:
            if not r.compile_ok:
                skipped["don't compile"] += 1
                continue
            if r.duplicate_of:
                skipped["duplicate"] += 1
                continue
            d = ev.decisions.get(r.key, {}).get(topic.name) if topic else None
            if r.name in names:
                band, decided_by, reasons, llm_reason = "include", "request", ["named in the request"], None
            elif d is None:
                continue
            else:
                band, decided_by, reasons, llm_reason = d.band, d.decided_by, d.reasons, d.llm_reason
            if band == "review":  # the model never judged it: try again next run
                deferred.add(r.key)
                skipped["deferred until the model judges them"] += 1
                continue
            if band == "uncertain":
                if policy != "info":
                    skipped["model unsure (excluded by policy)"] += 1
                    continue
            elif band != "include":
                continue
            current = pack.entries.get(r.key)
            if current and current["sha256"] == r.sha256:
                skipped["already in pack"] += 1
                continue
            sev, why = propose_severity(r, sev_cat)
            for dm in self.cfg.demotions:
                if dm.applies(r, it["target_pack"]) and dm.action == "info":
                    sev, why = "info", f"demoted: {dm.reason}"
            e = make_entry(r, files_by_key[(r.source, r.relpath)], proposed_severity=sev, severity_reason=why,
                           decided_by=decided_by, reasons=reasons, llm_reason=llm_reason,
                           uncertain=band == "uncertain", probation_days=probation, version=version,
                           upstream=upstream(r), source_info=source_info(ev.sources.get(r.source)))
            if current:
                e["added_version"], e["added_at"] = current["added_version"], current["added_at"]
                updates.append(e)
            else:
                additions.append(e)

        drops: list[dict] = []
        hits = self.clean_check(additions + updates)
        additions = self.apply_clean_results(additions, hits, drops)
        updates = self.apply_clean_results(updates, hits, drops)

        # Only a request that uses the pack's own definition marks everything it looked at as
        # considered; a topic request ("everything about Lumma") only marks what it added.
        own_definition = it["topic_pack"] == it["target_pack"]
        seen = ({r.key: r.sha256 for r in ev.candidates if r.key not in deferred} if own_definition
                else {e["key"]: e["sha256"] for e in additions + updates})
        proposal = {
            "hermit_proposal": 1, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "request": self.args.request, "intent": it, "target_pack": it["target_pack"],
            "base_version": pack.version, "pack_kind": pack.data["kind"], "pack_description": pack.data["description"],
            "additions": additions, "updates": updates, "removals": [], "drops": drops, "seen": seen,
            "considered": len(ev.candidates), "skipped": dict(skipped), "llm": ev.llm_status,
            "missing_rule_names": sorted(missing_names),
        }
        return self.finish(pack, proposal, new_pack)

    def remove(self, pack: LivePack, it: dict, ev, client) -> int:
        if not pack.exists or not pack.entries:
            self.log(f"{pack.name} has no rules to remove")
            return 0
        names = set(it["rule_names"])
        topic = self.topic_category(it, client) if (it["topic_text"] or it["topic_pack"]) else None
        removals = []
        for e in pack.entries.values():
            if e["name"] in names:
                removals.append({"key": e["key"], "name": e["name"], "reason": "named in the request"})
            elif topic:
                r = entry_rule(e)
                d = score(r, extract(r), topic)
                if d.band == "include":
                    removals.append({"key": e["key"], "name": e["name"], "reason": "; ".join(d.reasons)[:200]})
        missing = names - {x["name"] for x in removals}
        proposal = {
            "hermit_proposal": 1, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "request": self.args.request, "intent": it, "target_pack": pack.name, "base_version": pack.version,
            "pack_kind": pack.data["kind"], "pack_description": pack.data["description"],
            "additions": [], "updates": [], "removals": removals, "drops": [], "seen": {},
            "considered": len(pack.entries), "skipped": {}, "llm": "n/a",
            "missing_rule_names": sorted(missing),
        }
        return self.finish(pack, proposal, False)

    def finish(self, pack: LivePack, proposal: dict, new_pack: bool) -> int:
        n = len(proposal["additions"]) + len(proposal["updates"]) + len(proposal["removals"])
        out = self.cfg.out_dir / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-ask-{pack.name}"
        out.mkdir(parents=True, exist_ok=True)
        ppath = out / "proposal.json"
        ppath.write_text(json.dumps(proposal, indent=1, ensure_ascii=False))
        self.log("")
        self.log(summarise(proposal))
        gates = self.gates(pack, n, proposal["intent"], new_pack)
        self.result.update(proposal_result(proposal), proposal_path=str(ppath), gates=gates,
                           clean=self.clean_stats, from_version=pack.version)
        if n == 0 and not proposal["drops"]:
            if pack.exists and not self.args.dry_run:
                pack.remember_seen(proposal["seen"])
            self.log("Nothing to change.")
            self.result["outcome"] = "nothing"
            self.step("apply", "Apply", "nothing to change")
            return 0
        if self.args.dry_run:
            self.log(f"Dry run: nothing applied. Proposal: {ppath}")
            self.result["outcome"] = "dry-run"
            self.step("apply", "Apply", "dry run: nothing applied")
            return 0
        if not self.confirm_or_hold(gates, ppath):
            self.result["outcome"] = "held"
            self.step("apply", "Apply", "waiting for your OK", state="held")
            return EXIT_HELD
        version = apply_proposal(self.cfg, proposal, self.log)
        self.log(f"\n{pack.name}: v{proposal['base_version']} -> v{version}. "
                 f"Undo with: hermit rollback {pack.name}")
        self.result.update(outcome="applied", to_version=version)
        self.step("apply", "Apply as a new pack version", f"v{proposal['base_version']} → v{version}")
        return 0

    def report(self, pack: LivePack, it: dict) -> int:
        since = it["since"] or "0000"
        self.result.update(outcome="report", exists=pack.exists,
                           history=[h for h in pack.history() if h["at"][:10] >= since][-20:])
        self.step("report", "Read the pack history", plural(len(self.result["history"]), "version"))
        if not pack.exists:
            print(f"{pack.name}: no live pack yet")
            return 0
        print(pack_status(pack))
        since = it["since"] or "0000"
        hist = [h for h in pack.history() if h["at"][:10] >= since]
        print(f"\nChanges{' since ' + it['since'] if it['since'] else ''}: {len(hist)} versions")
        for h in hist[-20:]:
            print(f"  v{h['version']} {h['at'][:16]}  {h['summary']}")
            for d in h["details"][:8]:
                print(f"      {d}")
            if len(h["details"]) > 8:
                print(f"      … {len(h['details']) - 8} more")
        return 0


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def slim_entry(e: dict) -> dict:
    from .families import family_of
    return {"name": e["name"], "family": family_of(e["name"], e.get("rule", {}).get("meta")),
            "proposed_severity": e["proposed_severity"], "severity": e["severity"], "status": e["status"],
            "uncertain": e.get("uncertain", False), "demoted": e.get("demoted"), "decided_by": e["decided_by"],
            "source": e.get("upstream") or e["source"], "probation_until": e.get("probation_until")}


def proposal_result(p: dict) -> dict:
    """The parts of a proposal the GUI shows (no rule text)."""
    return {"additions": [slim_entry(e) for e in p["additions"]],
            "updates": [slim_entry(e) for e in p["updates"]],
            "removals": p["removals"], "drops": p["drops"], "skipped": p.get("skipped", {}),
            "considered": p["considered"], "llm": p.get("llm"), "missing": p.get("missing_rule_names", []),
            "base_version": p["base_version"], "request": p["request"]}


def summarise(p: dict) -> str:
    add, upd, rem, drops = p["additions"], p["updates"], p["removals"], p["drops"]
    lines = [f"Considered {plural(p['considered'], 'rule')} for {p['target_pack']}."]
    if add or upd:
        by = Counter(e["decided_by"] for e in add + upd)
        sev = Counter(e["severity"] for e in add + upd)
        lines.append(f"  add {len(add)}, update {len(upd)} (decided by: "
                     + ", ".join(f"{k} {v}" for k, v in by.items()) + "; effective severity: "
                     + ", ".join(f"{k} {v}" for k, v in sev.items()) + ")")
        unc = sum(1 for e in add + upd if e["uncertain"])
        prob = sum(1 for e in add + upd if e["status"] == "probation")
        dem = sum(1 for e in add + upd if e["demoted"])
        if prob:
            lines.append(f"  {prob} on probation (info until {next(e['probation_until'] for e in add + upd if e['probation_until'])})")
        if unc:
            lines.append(f"  {unc} the model wasn't sure about: added at info")
        if dem:
            lines.append(f"  {dem} demoted to info after firing on clean files")
        for e in (add + upd)[:15]:
            tag = "uncertain" if e["uncertain"] else e["decided_by"]
            lines.append(f"    + {e['name']} [{e['proposed_severity']}, {tag}]")
        if len(add + upd) > 15:
            lines.append(f"    … {len(add + upd) - 15} more")
    if rem:
        lines.append(f"  remove {len(rem)}:")
        lines += [f"    - {x['name']} ({x['reason'][:80]})" for x in rem[:15]]
    if drops:
        lines.append(f"  dropped {len(drops)} after the clean-set test:")
        lines += [f"    x {x['name']}: {x['reason']}" for x in drops[:10]]
    if p.get("skipped"):
        lines.append("  skipped: " + ", ".join(f"{v} {k}" for k, v in p["skipped"].items()))
    if p.get("missing_rule_names"):
        lines.append("  named but not found: " + ", ".join(p["missing_rule_names"]))
    if p.get("llm") and p["llm"] != "n/a":
        lines.append(f"  model: {p['llm']}")
    return "\n".join(lines)


def apply_proposal(cfg, proposal: dict, log) -> int:
    cat = cfg.categories.get(proposal["target_pack"])
    pack = LivePack.open(cfg.packs_dir, proposal["target_pack"], kind=proposal.get("pack_kind", "detection"),
                         description=proposal.get("pack_description", ""),
                         editions=cat.editions if cat else None)
    if pack.version != proposal["base_version"]:
        raise SystemExit(f"{pack.name} changed since this proposal (now v{pack.version}, proposal was made "
                         f"against v{proposal['base_version']}); run the request again")
    details = []
    for e in proposal["additions"]:
        pack.entries[e["key"]] = e
        details.append(f"added {e['name']} ({e['source']}) -> {e['severity']}"
                       + (" [uncertain]" if e["uncertain"] else "") + (f" [demoted: {e['demoted']}]" if e["demoted"] else ""))
    for e in proposal["updates"]:
        pack.entries[e["key"]] = e
        details.append(f"updated {e['name']} (rule text changed upstream; probation restarts)")
    excluded = pack.data.setdefault("excluded", {})
    for x in proposal["removals"]:
        pack.entries.pop(x["key"], None)
        excluded[x["key"]] = f"removed on request: {proposal['request'][:120]}"
        details.append(f"removed {x['name']}")
    for x in proposal["drops"]:
        excluded[x["key"]] = x["reason"]
        details.append(f"dropped {x['name']}: {x['reason']}")
    summary = (f"Request: \"{proposal['request']}\". "
               f"+{len(proposal['additions'])} ~{len(proposal['updates'])} -{len(proposal['removals'])}, "
               f"{len(proposal['drops'])} dropped by the clean-set test.")
    errors = pack.commit(summary, details, proposal["seen"])
    if errors:
        raise SystemExit(f"the new version doesn't compile, nothing applied: {errors[:2]}")
    return pack.version


def pack_status(pack: LivePack) -> str:
    es = list(pack.entries.values())
    sev = Counter(e["severity"] for e in es)
    st = Counter(e["status"] for e in es)
    return (f"{pack.name} v{pack.version} (updated {(pack.data.get('updated_at') or '-')[:16]}): {plural(len(es), 'rule')}; "
            f"severity threat {sev.get('threat', 0)} / suspicious {sev.get('suspicious', 0)} / info {sev.get('info', 0)}; "
            f"probation {st.get('probation', 0)}, uncertain {sum(1 for e in es if e.get('uncertain'))}, "
            f"excluded {len(pack.data.get('excluded', {}))}")


def run_auto(cfg, args, log) -> int:
    """Scheduled run: promote rules past probation, then add new rules to every pack in
    categories.toml using its own definition. Never prompts: a tripped gate holds that pack's
    proposal for `hermit apply`."""
    args.no_input, args.request = True, "scheduled update: add new rules to every pack"
    worst, fetched = 0, False
    names = args.pack or list(cfg.categories)
    for name in names:
        if name not in cfg.categories:
            log(f"{name}: not in categories.toml, skipped")
            continue
        log(f"\n===== {name}")
        args.no_fetch = fetched or args.no_fetch
        it = {"action": "add", "selection": "new", "since": None, "topic_pack": name, "topic_text": None,
              "target_pack": name, "rule_names": [], "understood_by": "schedule"}
        try:
            code = Ask(cfg, args, log).run(args.request, preset=it)
        except SystemExit as exc:
            log(f"{name}: failed: {exc}")
            code = 1
        fetched = True
        worst = max(worst, code or 0)
    return worst
