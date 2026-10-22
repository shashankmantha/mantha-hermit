"""Load rules, score them against categories and let the local model judge borderline ones.

Shared by `sort`, `find` and `ask`. Writing results is left to the caller.
"""
from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable

from . import llm as llm_mod
from .classify import Category, Decision, score
from .features import Features, extract
from .parse import Rule, RuleFile, Source, load_rules
from .store import Store


@dataclass
class Evaluation:
    store: Store
    sources: dict[str, Source]
    files: list[RuleFile]
    problems: list[dict]
    all_rules: list[Rule]
    novelty: dict[str, str]
    first_run: bool
    candidates: list[Rule] = field(default_factory=list)
    feats: dict[str, Features] = field(default_factory=dict)
    decisions: dict[str, dict[str, Decision]] = field(default_factory=dict)
    compile_failures: list[dict] = field(default_factory=list)
    demoted_log: list[str] = field(default_factory=list)
    not_applicable: Counter = field(default_factory=Counter)
    llm_status: str = "off"
    llm_errors: list[str] = field(default_factory=list)

    @property
    def files_by_key(self) -> dict[tuple[str, str], RuleFile]:
        return {(f.source, f.relpath): f for f in self.files}


def load(cfg, sources: dict[str, Source], log) -> Evaluation:
    store = Store(cfg.state_db)
    files, problems = load_rules(list(sources.values()), cfg.exclude_globs, store, log)
    store.commit()
    all_rules = [r for f in files for r in f.rules]
    return Evaluation(store=store, sources=sources, files=files, problems=problems,
                      all_rules=all_rules, novelty=store.novelty(all_rules),
                      first_run=store.last_run() is None)


def score_all(ev: Evaluation, cfg, cats: list[Category], select: Callable[[Rule], bool] | None, log) -> None:
    ev.candidates = [r for r in ev.all_rules
                     if not r.duplicate_of and not r.is_private and not r.is_global
                     and (select is None or select(r))]
    log(f"Scoring {len(ev.candidates)} rules against {', '.join(c.name for c in cats)}")
    for r in ev.candidates:
        f = extract(r)
        ev.feats[r.key] = f
        if not r.compile_ok:
            ev.compile_failures.append({"rule": r.key, "error": r.compile_error or ""})
            continue
        per = {}
        for c in cats:
            d = score(r, f, c)
            for dm in cfg.demotions:
                if dm.applies(r, c.name) and dm.action == "drop":
                    d = Decision(c.name, d.score, "dropped", d.reasons + [f"demoted: {dm.reason}"], "demotion")
                    ev.demoted_log.append(f"{r.name} ({c.name}): dropped, {dm.reason}")
            per[c.name] = d
        ev.decisions[r.key] = per
        if all(d.band == "not_applicable" for d in per.values()):
            for t in f.targets:
                ev.not_applicable[t] += 1


def judge_borderline(ev: Evaluation, cfg, cats: list[Category], *, use_llm: bool, limit: int | None,
                     two_pass: bool, log) -> None:
    """Ask the model about rules in the 'review' band.

    one pass:  confident yes -> include, confident no -> below, otherwise stays 'review'.
    two_pass:  both passes must agree confidently; an answered-but-unsure rule becomes
               'uncertain' (which `ask` adds at info severity, never as a verdict-raising rule).
    """
    borderline = [r for r in ev.candidates if r.key in ev.decisions
                  and any(d.band == "review" for d in ev.decisions[r.key].values())]
    if not borderline:
        return
    client = None
    if use_llm:
        client = llm_mod.Ollama(cfg.ollama_endpoint, cfg.ollama_model, cfg.ollama_timeout,
                            think=cfg.ollama_think)
        try:
            client.check()
            ev.llm_status = f"{cfg.ollama_model} at {cfg.ollama_endpoint}" + (" (two passes)" if two_pass else "")
        except llm_mod.LLMError as exc:
            ev.llm_status = f"unavailable ({exc})"
            log(f"Model: {ev.llm_status}")
            client = None
    else:
        ev.llm_status = "off"

    todo = sorted(borderline, key=lambda r: -max(d.score for d in ev.decisions[r.key].values()))
    if client and limit is not None and limit < len(todo):
        log(f"Asking the model about {limit} of {len(todo)} borderline rules (limit)")
    asked = todo[:limit] if (client and limit is not None) else (todo if client else [])
    if client:
        log(f"Asking {cfg.ollama_model} about {len(asked)} borderline rules")
    t0 = time.time()
    for i, r in enumerate(asked, 1):
        review_cats = [c for c in cats if ev.decisions[r.key][c.name].band == "review"]
        try:
            answers = [llm_mod.judge(client, ev.store, r, ev.feats[r.key], review_cats, variant=v)
                       for v in ((0, 1) if two_pass else (0,))]
        except llm_mod.LLMError as exc:
            ev.llm_errors.append(f"{r.name}: {exc}")
            if exc.kind in ("unreachable", "model_missing"):
                ev.llm_status += f"; stopped after error: {exc}"
                break
            continue
        for c in review_cats:
            d = ev.decisions[r.key][c.name]
            votes = [a["decisions"].get(c.name, (False, 0.0)) for a in answers]
            d.llm_reason = answers[0]["reason"]
            d.llm_confidence = min(conf for _, conf in votes)
            confident = all(conf >= cfg.llm_min_conf for _, conf in votes)
            if confident and all(ok for ok, _ in votes):
                d.band, d.decided_by = "include", "llm"
            elif confident and not any(ok for ok, _ in votes):
                d.band, d.decided_by = "below", "llm"
            elif two_pass:
                d.band, d.decided_by = "uncertain", "llm"
                if len(votes) > 1 and votes[0][0] != votes[1][0]:
                    d.llm_reason = f"passes disagreed; {d.llm_reason}"
        if i % 10 == 0 or i == len(asked):
            log(f"  {i}/{len(asked)} ({(time.time() - t0) / i:.1f}s per rule)")
    # Rules the model never answered (no model, --llm-limit, errors) stay in 'review':
    # `sort` lists them in review.csv and `ask` defers them to the next run.
