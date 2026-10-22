"""Local state: parse cache, LLM answer cache, and which rules each run has seen."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT, finished_at TEXT, command TEXT);
CREATE TABLE IF NOT EXISTS rules (
  key TEXT PRIMARY KEY, sha256 TEXT, first_seen_run INTEGER, last_seen_run INTEGER,
  last_changed_run INTEGER, first_seen_at TEXT);
CREATE TABLE IF NOT EXISTS parse_cache (file_sha256 TEXT PRIMARY KEY, parser TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS llm_cache (key TEXT PRIMARY KEY, model TEXT, data TEXT, created_at TEXT);
"""
PARSER_VERSION = "5"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.executescript(SCHEMA)

    # parse cache
    def get_parse(self, file_sha: str):
        row = self.db.execute("SELECT data FROM parse_cache WHERE file_sha256=? AND parser=?",
                              (file_sha, PARSER_VERSION)).fetchone()
        return json.loads(row[0]) if row else None

    def put_parse(self, file_sha: str, data) -> None:
        self.db.execute("INSERT OR REPLACE INTO parse_cache VALUES (?,?,?)",
                        (file_sha, PARSER_VERSION, json.dumps(data)))

    # llm cache
    def get_llm(self, key: str):
        row = self.db.execute("SELECT data FROM llm_cache WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put_llm(self, key: str, model: str, data) -> None:
        self.db.execute("INSERT OR REPLACE INTO llm_cache VALUES (?,?,?,?)",
                        (key, model, json.dumps(data), _now()))
        self.db.commit()

    # runs and novelty
    def last_run(self):
        return self.db.execute(
            "SELECT id, finished_at FROM runs WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()

    def novelty(self, rules) -> dict[str, str]:
        """'new', 'changed' or 'seen' for each rule key, against finished runs only."""
        known = dict(self.db.execute("SELECT key, sha256 FROM rules"))
        out = {}
        for r in rules:
            old = known.get(r.key)
            out[r.key] = "new" if old is None else ("changed" if old != r.sha256 else "seen")
        return out

    def record_run(self, command: str, rules) -> int:
        """Called only after a run finishes, so a failed run never uses up 'new'."""
        cur = self.db.execute("INSERT INTO runs (started_at, finished_at, command) VALUES (?,?,?)",
                              (_now(), _now(), command))
        run = cur.lastrowid
        now = _now()
        for r in rules:
            row = self.db.execute("SELECT sha256 FROM rules WHERE key=?", (r.key,)).fetchone()
            if row is None:
                self.db.execute("INSERT INTO rules VALUES (?,?,?,?,?,?)",
                                (r.key, r.sha256, run, run, run, now))
            elif row[0] != r.sha256:
                self.db.execute("UPDATE rules SET sha256=?, last_seen_run=?, last_changed_run=? WHERE key=?",
                                (r.sha256, run, run, r.key))
            else:
                self.db.execute("UPDATE rules SET last_seen_run=? WHERE key=?", (run, r.key))
        self.db.commit()
        return run

    def counts(self):
        return {
            "runs": self.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0],
            "rules_known": self.db.execute("SELECT COUNT(*) FROM rules").fetchone()[0],
            "llm_answers_cached": self.db.execute("SELECT COUNT(*) FROM llm_cache").fetchone()[0],
            "files_parsed_cached": self.db.execute("SELECT COUNT(*) FROM parse_cache").fetchone()[0],
        }

    def commit(self):
        self.db.commit()
