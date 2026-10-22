"""`hermit serve`: the local web app.

Standard library only. Binds to 127.0.0.1 and is a thin layer over the same functions the CLI
uses. Rule names and rule text come from the internet, so they're treated as untrusted:

- the Host header must be this machine (blocks DNS-rebinding attacks from web pages);
- every /api call needs the per-start token from the page (a cross-site page can't read it);
- a strict Content-Security-Policy (no inline script, nothing loaded from elsewhere);
- the frontend only ever inserts text, never HTML built from data.

Long work (ask, apply, promote, export, publish) runs as one background job at a time;
the page polls /api/jobs/<id> for its steps, log and result.
"""
from __future__ import annotations

import json
import mimetypes
import re
import secrets
import threading
import time
import traceback
import urllib.request
from argparse import Namespace
from collections import Counter
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .families import family_of
from .livepacks import LivePack, entry_licence, list_packs, namespace

WEB = Path(__file__).resolve().parent / "web"
MAX_BODY = 64 * 1024
MAX_LOG = 3000
PACK_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------ jobs

class Job:
    def __init__(self, kind: str, label: str, chat_id: str | None = None, pack: str | None = None):
        self.id = secrets.token_hex(6)
        self.kind, self.label, self.chat_id, self.pack = kind, label, chat_id, pack
        self.state = "running"
        self.log: list[str] = []
        self.steps: list[dict] = []
        self.result: dict = {}
        self.error: str | None = None
        self.started = time.time()
        self.finished: float | None = None

    def add_log(self, msg: str) -> None:
        for line in str(msg).splitlines() or [""]:
            if len(self.log) < MAX_LOG:
                self.log.append(line)

    def add_step(self, s: dict) -> None:
        self.steps = [x for x in self.steps if x["key"] != s["key"]] + [s]

    def view(self, since: int = 0) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label, "state": self.state,
                "steps": self.steps, "log": self.log[since:], "log_total": len(self.log),
                "result": self.result, "error": self.error, "pack": self.pack, "chat_id": self.chat_id,
                "elapsed": round((self.finished or time.time()) - self.started, 1)}


# ------------------------------------------------------------------ app

class App:
    def __init__(self, cfg):
        self.cfg = cfg
        self.token = secrets.token_urlsafe(24)
        self.jobs: dict[str, Job] = {}
        self.busy: Job | None = None
        self.lock = threading.Lock()
        self.state_dir = cfg.state_db.parent
        self.chats_file = self.state_dir / "chats.json"
        self.held_file = self.state_dir / "held.json"
        self._check_cache: dict[tuple[str, int], dict] = {}

    # ---------------------------------------------------------- storage

    def _read(self, path: Path, default):
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return default

    def _write(self, path: Path, obj) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(obj, indent=1, ensure_ascii=False))
        tmp.replace(path)

    def chats(self) -> list[dict]:
        return self._read(self.chats_file, {"chats": []})["chats"]

    def save_chats(self, chats: list[dict]) -> None:
        self._write(self.chats_file, {"chats": chats[-200:]})

    def chat(self, chat_id: str) -> dict:
        for c in self.chats():
            if c["id"] == chat_id:
                return c
        raise ApiError(404, "no such chat")

    def add_message(self, chat_id: str | None, msg: dict, title: str | None = None) -> str:
        with self.lock:
            chats = self.chats()
            c = next((c for c in chats if c["id"] == chat_id), None) if chat_id else None
            if c is None:
                c = {"id": secrets.token_hex(6), "title": (title or "New chat")[:80], "created": now_iso(),
                     "messages": []}
                chats.append(c)
            c["messages"].append(msg)
            c["updated"] = now_iso()
            if title and c["title"] == "New chat":
                c["title"] = title[:80]
            self.save_chats(chats)
            return c["id"]

    # ---------------------------------------------------------- status

    def ollama_models(self) -> tuple[bool, list[str]]:
        try:
            with urllib.request.urlopen(self.cfg.ollama_endpoint.rstrip("/") + "/api/tags", timeout=1.5) as r:
                data = json.loads(r.read().decode())
            return True, sorted(m.get("name", "") for m in data.get("models", []) if m.get("name"))
        except Exception:
            return False, []

    def status(self) -> dict:
        from .bundle import BundleSettings
        ok, models = self.ollama_models() if self.cfg.llm_enabled else (False, [])
        b = BundleSettings(self.cfg)
        sources = []
        if self.cfg.sources_dir.is_dir():
            for d in sorted(self.cfg.sources_dir.iterdir()):
                if d.is_dir() and not d.name.endswith(".new"):
                    rev = None
                    marker = d / ".hermit-source.json"
                    if not marker.is_file():
                        marker = d / ".rulesort-source.json"  # sources fetched before the rename
                    if marker.is_file():
                        info = self._read(marker, {})
                        rev = (info.get("sha256") or info.get("commit") or "")[:12]
                        fetched = info.get("fetched_at")
                    else:
                        fetched = None
                    sources.append({"name": d.name, "revision": rev, "fetched_at": fetched})
        auto = self.cfg.main.get("automation", {})
        return {"version": __version__, "model": self.cfg.ollama_model, "endpoint": self.cfg.ollama_endpoint,
                "llm_enabled": self.cfg.llm_enabled, "ollama_ok": ok, "models": models,
                "sources": sources, "clean_dirs": auto.get("clean_dirs", []),
                "release_repo": b.release_repo, "has_secret_key": b.secret_key.is_file(),
                "has_public_key": b.public_key.is_file(),
                "busy": self.busy.view(10**9) if self.busy else None}

    # ---------------------------------------------------------- packs

    def held(self) -> dict:
        held = self._read(self.held_file, {})
        live = {p.name: p.version for p in list_packs(self.cfg.packs_dir)}
        fresh = {k: v for k, v in held.items()
                 if Path(v["path"]).is_file() and live.get(k, 0) == v["base_version"]}
        if fresh != held:
            self._write(self.held_file, fresh)
        return fresh

    def pack_summary(self, p: LivePack, held: dict) -> dict:
        es = list(p.entries.values())
        sev = Counter(e["severity"] for e in es)
        size = sum(f.stat().st_size for f in (p.dir / "rules").glob("*.yar")) if (p.dir / "rules").is_dir() else 0
        return {"id": p.name, "version": p.version, "updated_at": p.data.get("updated_at"),
                "kind": p.data.get("kind"), "description": p.data.get("description", ""),
                "editions": p.editions, "rules": len(es),
                "severity": {k: sev.get(k, 0) for k in ("threat", "suspicious", "info")},
                "probation": sum(1 for e in es if e.get("status") == "probation"),
                "uncertain": sum(1 for e in es if e.get("uncertain")),
                "families": len({family_of(e["name"], e.get("rule", {}).get("meta")) for e in es}),
                "excluded": len(p.data.get("excluded", {})), "size_bytes": size,
                "held": held.get(p.name)}

    def packs(self) -> list[dict]:
        held = self.held()
        return [self.pack_summary(p, held) for p in list_packs(self.cfg.packs_dir)]

    def open_pack(self, pack_id: str) -> LivePack:
        if not PACK_ID.match(pack_id):
            raise ApiError(400, "bad pack id")
        p = LivePack.open(self.cfg.packs_dir, pack_id)
        if not p.exists:
            raise ApiError(404, f"no live pack named {pack_id}")
        return p

    def compile_check(self, p: LivePack) -> dict:
        key = (p.name, p.version)
        if key not in self._check_cache:
            from .contract import ContractError, validate_pack
            files = len(list((p.dir / "rules").glob("*.yar"))) if (p.dir / "rules").is_dir() else 0
            try:
                s = validate_pack(p.dir, compile_rules=True, allow_state=True)
                self._check_cache[key] = {"ok": True, "files": files, "rules": s["rules"],
                                          "message": f"{files} rule file{'s compile' if files != 1 else ' compiles'} with YARA-X"}
            except ContractError as exc:
                self._check_cache[key] = {"ok": False, "files": files, "message": str(exc)}
        return self._check_cache[key]

    def pack_detail(self, pack_id: str) -> dict:
        p = self.open_pack(pack_id)
        rules, sources = [], {}
        for key, e in sorted(p.entries.items(), key=lambda kv: kv[1]["name"].lower()):
            meta = e.get("rule", {}).get("meta", {})
            rules.append({
                "key": key, "name": e["name"], "family": family_of(e["name"], meta),
                "severity": e["severity"], "proposed_severity": e["proposed_severity"],
                "severity_reason": e.get("severity_reason"), "status": e["status"],
                "probation_until": e.get("probation_until"), "uncertain": e.get("uncertain", False),
                "demoted": e.get("demoted"), "decided_by": e["decided_by"], "reasons": e.get("reasons", []),
                "llm_reason": e.get("llm_reason"), "source": e.get("upstream") or e["source"],
                "licence": entry_licence(e), "description": str(meta.get("description", ""))[:300],
                "added_at": e.get("added_at"), "namespace": namespace(e["source"], e["relpath"])})
            si = e.get("source_info") or {}
            name = si.get("name") or e["source"]
            sources.setdefault(name, {"name": name, "url": si.get("url"), "revision": si.get("revision"),
                                      "licence": si.get("licence"), "rules": 0})
            sources[name]["rules"] += 1
        return {**self.pack_summary(p, self.held()), "rules_list": rules,
                "sources": sorted(sources.values(), key=lambda s: -s["rules"]),
                "history": list(reversed(p.history()[-30:])), "check": self.compile_check(p)}

    def rule_text(self, pack_id: str, key: str) -> dict:
        p = self.open_pack(pack_id)
        e = p.entries.get(key)
        if e is None:
            raise ApiError(404, "no such rule in this pack")
        return {"name": e["name"], "text": e["rule"]["text"],
                "support": [s["name"] for s in e.get("support", [])], "imports": e.get("imports", [])}

    def manifest(self, pack_id: str) -> dict:
        p = self.open_pack(pack_id)
        return {"pack_json": self._read(p.dir / "pack.json", {}),
                "severities_json": self._read(p.dir / "severities.json", {})}

    # ---------------------------------------------------------- jobs

    def start_job(self, job: Job, fn) -> Job:
        with self.lock:
            if self.busy is not None and self.busy.state == "running":
                raise ApiError(409, f"Hermit is busy with: {self.busy.label}. Try again when it finishes.")
            self.busy = job
            self.jobs[job.id] = job
            for old in sorted(self.jobs.values(), key=lambda j: j.started)[:-30]:
                self.jobs.pop(old.id, None)

        def run():
            try:
                fn(job)
                if job.state == "running":
                    job.state = "done"
            except SystemExit as exc:
                job.state, job.error = "error", str(exc) or "stopped"
            except Exception as exc:  # report, don't kill the server
                job.state, job.error = "error", f"{type(exc).__name__}: {exc}"
                job.add_log(traceback.format_exc())
            finally:
                job.finished = time.time()
                if job.kind in ("ask", "apply") and job.chat_id:
                    self.add_message(job.chat_id, {
                        "role": "hermit", "at": now_iso(), "job": job.kind, "state": job.state,
                        "steps": job.steps, "result": job.result, "error": job.error,
                        "elapsed": round(job.finished - job.started, 1), "log": job.log[-400:]})
        threading.Thread(target=run, daemon=True, name=f"hermit-{job.kind}").start()
        return job

    def ask(self, body: dict) -> dict:
        from .ask import Ask
        text = str(body.get("text", "")).strip()
        if not text or len(text) > 2000:
            raise ApiError(400, "write a request of up to 2000 characters")
        opts = body.get("options") or {}
        chat_id = self.add_message(body.get("chat_id"), {"role": "user", "text": text, "at": now_iso()}, title=text)
        args = Namespace(request=text, rules=[], yes=False, no_input=True, plan_only=False,
                         dry_run=bool(opts.get("dry_run")), no_fetch=not bool(opts.get("fetch", False)),
                         no_llm=not bool(opts.get("use_model", True)), llm_limit=_int(opts.get("llm_limit")))
        job = Job("ask", text[:60], chat_id=chat_id)

        def work(j: Job):
            a = Ask(self.cfg, args, j.add_log, on_step=j.add_step)
            try:
                code = a.run(text)
            finally:
                j.result = a.result
                j.pack = a.result.get("pack")
            if a.result.get("outcome") == "held":
                held = self._read(self.held_file, {})
                held[a.result["pack"]] = {"path": a.result["proposal_path"], "created": now_iso(),
                                          "base_version": a.result.get("from_version", 0),
                                          "gates": a.result.get("gates", []), "chat_id": chat_id,
                                          "changes": len(a.result.get("additions", [])) + len(a.result.get("updates", []))
                                          + len(a.result.get("removals", []))}
                self._write(self.held_file, held)
            j.result["exit_code"] = code
        self.start_job(job, work)
        return {"job": job.id, "chat_id": chat_id}

    def apply(self, body: dict) -> dict:
        from .ask import apply_proposal, proposal_result
        pack_id = str(body.get("pack", ""))
        held = self.held().get(pack_id)
        if not held:
            raise ApiError(404, "nothing is waiting for approval in that pack (it may have changed since)")
        proposal = self._read(Path(held["path"]), None)
        if not proposal or proposal.get("hermit_proposal") != 1:
            raise ApiError(400, "the saved proposal can't be read")
        chat_id = held.get("chat_id")
        self.add_message(chat_id, {"role": "user", "text": f"Apply the held changes to {pack_id}.", "at": now_iso()})
        job = Job("apply", f"apply to {pack_id}", chat_id=chat_id, pack=pack_id)

        def work(j: Job):
            j.add_step({"key": "apply", "label": "Apply as a new pack version", "detail": "", "state": "running"})
            v = apply_proposal(self.cfg, proposal, j.add_log)
            j.result = {**proposal_result(proposal), "outcome": "applied", "pack": pack_id,
                        "from_version": proposal["base_version"], "to_version": v, "intent": proposal["intent"]}
            j.add_step({"key": "apply", "label": "Apply as a new pack version",
                        "detail": f"v{proposal['base_version']} → v{v}", "state": "done"})
            h = self._read(self.held_file, {})
            h.pop(pack_id, None)
            self._write(self.held_file, h)
        self.start_job(job, work)
        return {"job": job.id, "chat_id": chat_id}

    def promote(self, pack_id: str, body: dict) -> dict:
        from .ask import Ask
        p = self.open_pack(pack_id)
        job = Job("promote", f"end probation in {pack_id}", pack=pack_id)

        def work(j: Job):
            a = Ask(self.cfg, Namespace(no_llm=True, rules=[]), j.add_log, on_step=j.add_step)
            done = a.promote_due(p, now=bool(body.get("now")))
            j.result = {"pack": pack_id, "promoted": done, "clean": a.clean_stats}
        self.start_job(job, work)
        return {"job": job.id}

    def rollback(self, pack_id: str) -> dict:
        p = self.open_pack(pack_id)
        job = Job("rollback", f"undo the last change to {pack_id}", pack=pack_id)

        def work(j: Job):
            before = p.version
            v = p.rollback(None)
            j.result = {"pack": pack_id, "restored": before - 1, "version": v}
            j.add_log(f"{pack_id}: restored the contents of v{before - 1}, saved as v{v}")
        self.start_job(job, work)
        return {"job": job.id}

    def export(self) -> dict:
        from .bundle import build_tree, check_yara_x_pin, BundleSettings
        dest = self.cfg.out_dir / f"export-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
        job = Job("export", "export an unsigned bundle")

        def work(j: Job):
            mismatch = check_yara_x_pin(BundleSettings(self.cfg))
            built = build_tree(self.cfg, dest, j.add_log, include_compiled=False if mismatch else None)
            j.result = {"dir": str(dest), "manifest": built["manifest"], "packs": built["packs"]}
        self.start_job(job, work)
        return {"job": job.id}

    def publish(self, body: dict) -> dict:
        from .bundle import publish
        job = Job("publish", "sign and publish a bundle")

        def work(j: Job):
            res = publish(self.cfg, j.add_log, only=None, push=bool(body.get("push")),
                          allow_version_mismatch=False)
            j.result = {"version": res["version"], "tarball": str(res["tarball"]), "sha256": res["sha256"],
                        "url": res["url"], "changes": res["manifest"]["changes"], "packs": res["packs"]}
        self.start_job(job, work)
        return {"job": job.id}

    def set_model(self, body: dict) -> dict:
        model = str(body.get("model", ""))
        ok, models = self.ollama_models()
        if model not in models:
            raise ApiError(400, "that model isn't installed in Ollama")
        self.cfg.ollama_model = model
        return {"model": model}


def _int(v) -> int | None:
    try:
        return max(1, int(v)) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ HTTP

def make_handler(app: App, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "hermit"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def _headers(self, status: int, ctype: str, length: int, cache: bool = False):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Cache-Control", "max-age=300" if cache else "no-store")
            self.end_headers()

        def _json(self, status: int, obj) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode()
            self._headers(status, "application/json; charset=utf-8", len(body))
            self.wfile.write(body)

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ApiError(413, "request too large")
            if n and "application/json" not in self.headers.get("Content-Type", ""):
                raise ApiError(415, "send JSON")
            raw = self.rfile.read(n) if n else b"{}"
            try:
                obj = json.loads(raw or b"{}")
            except ValueError as exc:
                raise ApiError(400, "invalid JSON") from exc
            if not isinstance(obj, dict):
                raise ApiError(400, "send a JSON object")
            return obj

        def _dispatch(self, method: str) -> None:
            if not self._host_ok():
                self._json(403, {"error": "this server only answers on 127.0.0.1"})
                return
            url = urlparse(self.path)
            path = url.path
            if method == "GET" and not path.startswith("/api/"):
                return self._static(path)
            if not secrets.compare_digest(self.headers.get("X-Hermit-Token", ""), app.token):
                self._json(403, {"error": "missing or wrong token; reload the page"})
                return
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            try:
                self._json(200, self._route(method, path, q))
            except ApiError as exc:
                self._json(exc.status, {"error": str(exc)})
            except SystemExit as exc:
                self._json(400, {"error": str(exc)})
            except Exception as exc:
                self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

        def _route(self, method: str, path: str, q: dict):
            parts = [x for x in path.split("/") if x][1:]  # drop "api"
            if method == "GET":
                if parts == ["status"]:
                    return app.status()
                if parts == ["packs"]:
                    return {"packs": app.packs(), "held": app.held()}
                if len(parts) == 2 and parts[0] == "packs":
                    return app.pack_detail(parts[1])
                if len(parts) == 3 and parts[0] == "packs" and parts[2] == "rule":
                    return app.rule_text(parts[1], q.get("key", ""))
                if len(parts) == 3 and parts[0] == "packs" and parts[2] == "manifest":
                    return app.manifest(parts[1])
                if parts == ["chats"]:
                    return {"chats": [{k: c.get(k) for k in ("id", "title", "created", "updated")}
                                      | {"messages": len(c["messages"])} for c in reversed(app.chats())]}
                if len(parts) == 2 and parts[0] == "chats":
                    return app.chat(parts[1])
                if len(parts) == 2 and parts[0] == "jobs":
                    job = app.jobs.get(parts[1])
                    if not job:
                        raise ApiError(404, "no such job")
                    return job.view(_int(q.get("since")) or 0)
            if method == "POST":
                body = self._body()
                if parts == ["ask"]:
                    return app.ask(body)
                if parts == ["apply"]:
                    return app.apply(body)
                if parts == ["export"]:
                    return app.export()
                if parts == ["publish"]:
                    return app.publish(body)
                if parts == ["model"]:
                    return app.set_model(body)
                if len(parts) == 3 and parts[0] == "packs" and parts[2] == "promote":
                    return app.promote(parts[1], body)
                if len(parts) == 3 and parts[0] == "packs" and parts[2] == "rollback":
                    return app.rollback(parts[1])
            raise ApiError(404, "unknown endpoint")

        def _static(self, path: str) -> None:
            if path in ("/", "/index.html"):
                html = (WEB / "index.html").read_text().replace("{{TOKEN}}", app.token)
                body = html.encode()
                self._headers(200, "text/html; charset=utf-8", len(body))
                self.wfile.write(body)
                return
            name = path.lstrip("/")
            target = (WEB / name).resolve()
            if WEB.resolve() not in target.parents or not target.is_file():
                self._json(404, {"error": "not found"})
                return
            body = target.read_bytes()
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            self._headers(200, ctype, len(body), cache=False)
            self.wfile.write(body)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

    return Handler


def serve(cfg, port: int | None, mode: str, log) -> None:
    """mode: "window" (own desktop window, like Mantha Ray), "browser", or "none" (just serve)."""
    webview = None
    if mode == "window":
        try:
            import webview  # pywebview, from the "desktop" extra
        except ModuleNotFoundError:
            log("The desktop window needs the desktop extra: pip install -e '.[desktop]'\n"
                "Opening it in your browser instead.")
            mode = "browser"
    want = port if port is not None else (0 if mode == "window" else 8765)
    app = App(cfg)
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", want), make_handler(app, want))
    except OSError as exc:
        raise SystemExit(f"Couldn't use port {want} ({exc.strerror}). Try --port with another number.")
    httpd.daemon_threads = True
    real_port = httpd.server_address[1]
    if real_port != want:  # port 0 → a free one was picked
        httpd.RequestHandlerClass = make_handler(app, real_port)
    url = f"http://127.0.0.1:{real_port}/"

    if mode == "window":
        threading.Thread(target=httpd.serve_forever, name="hermit-server", daemon=True).start()
        log(f"Mantha Hermit is running in its own window ({url}, this machine only).")
        # Same hardening as Mantha Ray's window.
        webview.settings["ALLOW_DOWNLOADS"] = False
        webview.settings["ALLOW_FILE_URLS"] = False
        webview.settings["REMOTE_DEBUGGING_PORT"] = None
        webview.create_window("Mantha Hermit", url, width=1440, height=900, min_size=(960, 640),
                              resizable=True, background_color="#000000", text_select=True, zoomable=True)
        try:
            webview.start(gui="qt", debug=False, private_mode=True)
        finally:
            _finish_running_job(app, log)
            httpd.shutdown()
            httpd.server_close()
        return

    log(f"Mantha Hermit is running at {url}  (this machine only; Ctrl+C to stop)")
    if mode == "browser":
        import webbrowser
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("\nStopped.")
    finally:
        _finish_running_job(app, log)
        httpd.server_close()


def _finish_running_job(app: App, log) -> None:
    """Don't exit in the middle of writing a pack: let a running request finish first."""
    job = app.busy
    if job is None or job.state != "running":
        return
    log(f"Finishing the current request before exiting: {job.label} (Ctrl+C again to stop now)")
    try:
        while job.state == "running":
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("Stopped without finishing; the pack may need `hermit rollback` if it was being saved.")
