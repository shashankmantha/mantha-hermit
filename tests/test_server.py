"""The local web app: security checks and an end-to-end request through the API."""
import json
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from hermit import server
from hermit.cli import Config

ROOT = Path(__file__).resolve().parent.parent


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        shutil.copytree(ROOT / "config", cls.tmp / "config")
        shutil.copytree(ROOT / "examples" / "rules", cls.tmp / "sources" / "examples")
        t = (cls.tmp / "config" / "hermit.toml").read_text()
        t = t.replace("enabled = true", "enabled = false", 1)
        (cls.tmp / "config" / "hermit.toml").write_text(t)
        (cls.tmp / "config" / "sources.toml").write_text("")  # use every folder in sources/
        cls.cfg = Config(cls.tmp / "config")
        cls.app = server.App(cls.cfg)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(cls.app, 0))
        cls.port = cls.httpd.server_address[1]
        cls.httpd.RequestHandlerClass = server.make_handler(cls.app, cls.port)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def call(self, path, body=None, token=True, host=None, ctype="application/json"):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     data=json.dumps(body).encode() if body is not None else None,
                                     method="POST" if body is not None else "GET")
        if token:
            req.add_header("X-Hermit-Token", self.app.token)
        if host:
            req.add_header("Host", host)
        if body is not None:
            req.add_header("Content-Type", ctype)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def test_page_has_token_and_csp(self):
        status, headers, body = self.call("/", token=False)
        self.assertEqual(status, 200)
        self.assertIn(self.app.token.encode(), body)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])

    def test_rejects_missing_token_and_foreign_host(self):
        self.assertEqual(self.call("/api/status", token=False)[0], 403)
        self.assertEqual(self.call("/api/status", host="evil.example")[0], 403)
        self.assertEqual(self.call("/", token=False, host=f"attacker.test:{self.port}")[0], 403)

    def test_rejects_bad_input(self):
        self.assertEqual(self.call("/api/packs/BAD_ID")[0], 400)
        self.assertEqual(self.call("/api/ask", {"text": "x"}, ctype="text/plain")[0], 415)
        self.assertEqual(self.call("/api/ask", {"text": ""})[0], 400)
        self.assertEqual(self.call("/app.js/../../hermit.toml", token=False)[0], 404)

    def test_request_end_to_end(self):
        status, _, body = self.call("/api/ask", {"text": "add new video game rules",
                                                 "options": {"use_model": False}})
        self.assertEqual(status, 200, body)
        started = json.loads(body)
        for _ in range(200):
            job = json.loads(self.call(f"/api/jobs/{started['job']}")[2])
            if job["state"] != "running":
                break
            time.sleep(0.1)
        self.assertEqual(job["state"], "done", job.get("error"))
        self.assertEqual(job["result"]["outcome"], "applied")
        self.assertIn("understand", [s["key"] for s in job["steps"]])
        packs = json.loads(self.call("/api/packs")[2])["packs"]
        self.assertIn("games", [p["id"] for p in packs])
        detail = json.loads(self.call("/api/packs/games")[2])
        self.assertTrue(detail["check"]["ok"])
        self.assertTrue(all(r["family"] for r in detail["rules_list"]))
        rule = detail["rules_list"][0]
        text = json.loads(self.call(f"/api/packs/games/rule?key={urllib.request.quote(rule['key'])}")[2])
        self.assertIn("rule ", text["text"])
        time.sleep(0.2)
        chat = json.loads(self.call(f"/api/chats/{started['chat_id']}")[2])
        self.assertEqual([m["role"] for m in chat["messages"]], ["user", "hermit"])


if __name__ == "__main__":
    unittest.main()
