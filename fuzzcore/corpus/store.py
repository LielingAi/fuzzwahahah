"""SQLite 语料库 + 种子队列（见 ARCHITECTURE.md §5.1、Fuzzillai generated_program_queue 模式）。"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS inputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT UNIQUE NOT NULL,
    data BLOB NOT NULL,
    provenance TEXT NOT NULL DEFAULT '{}',
    coverage_sig TEXT,
    source TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inputs_created ON inputs(created_at);
CREATE INDEX IF NOT EXISTS idx_inputs_source ON inputs(source);

CREATE TABLE IF NOT EXISTS seed_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    data BLOB NOT NULL,
    provenance TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    consumed_at REAL,
    UNIQUE(target_id, sha256)
);
CREATE INDEX IF NOT EXISTS idx_seed_queue_target ON seed_queue(target_id, consumed_at);

CREATE TABLE IF NOT EXISTS grammars (
    name TEXT PRIMARY KEY,
    kind TEXT NOT NULL DEFAULT 'binary_file',
    spec TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS learning_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file TEXT NOT NULL UNIQUE,
    protocol TEXT,
    kind TEXT NOT NULL DEFAULT 'session',
    payload TEXT NOT NULL,
    imported_at REAL NOT NULL
);
"""


class SqliteCorpus:
    def __init__(self, path: str = "corpus.db"):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ---- inputs ----
    def add(self, data: bytes, provenance: Optional[dict] = None,
            coverage_sig: Optional[str] = None, source: Optional[str] = None) -> int:
        sha = hashlib.sha256(data).hexdigest()
        now = time.time()
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO inputs(sha256,data,provenance,coverage_sig,source,created_at)"
                " VALUES(?,?,?,?,?,?)",
                (sha, data, json.dumps(provenance or {}), coverage_sig, source, now),
            )
            row = self.conn.execute(
                "SELECT id FROM inputs WHERE sha256=?", (sha,)
            ).fetchone()
        return row["id"] if row else -1

    def query(self, source: Optional[str] = None, limit: int = 100) -> list[dict]:
        sql = ("SELECT id,sha256,data,provenance,coverage_sig,source,created_at"
               " FROM inputs")
        args: list = []
        if source is not None:
            sql += " WHERE source=?"
            args.append(source)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        rows = self.conn.execute(sql, args).fetchall()
        return [
            {
                "id": r["id"],
                "sha256": r["sha256"],
                "data": bytes(r["data"]),
                "provenance": json.loads(r["provenance"] or "{}"),
                "coverage_sig": r["coverage_sig"],
                "source": r["source"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) c FROM inputs").fetchone()["c"]

    # ---- seed queue (generated_program_queue) ----
    def enqueue_seed(self, target_id: str, data: bytes,
                     provenance: Optional[dict] = None) -> int:
        sha = hashlib.sha256(data).hexdigest()
        now = time.time()
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO seed_queue(target_id,sha256,data,provenance,created_at)"
                " VALUES(?,?,?,?,?)",
                (target_id, sha, data, json.dumps(provenance or {}), now),
            )
            row = self.conn.execute(
                "SELECT id FROM seed_queue WHERE target_id=? AND sha256=?",
                (target_id, sha),
            ).fetchone()
        return row["id"] if row else -1

    def pull_seed(self, target_id: str, limit: int = 100) -> list[dict]:
        """取出未消费种子并标记为已消费。"""
        with self.conn:
            rows = self.conn.execute(
                "SELECT id,sha256,data,provenance,created_at FROM seed_queue"
                " WHERE target_id=? AND consumed_at IS NULL"
                " ORDER BY created_at ASC LIMIT ?",
                (target_id, limit),
            ).fetchall()
            ids = [r["id"] for r in rows]
            if ids:
                now = time.time()
                self.conn.executemany(
                    "UPDATE seed_queue SET consumed_at=? WHERE id=?",
                    [(now, i) for i in ids],
                )
        return [
            {
                "id": r["id"],
                "sha256": r["sha256"],
                "data": bytes(r["data"]),
                "provenance": json.loads(r["provenance"] or "{}"),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    # ---- grammars (LLM 综合产物的落点) ----

    def register_grammar(self, grammar) -> None:
        """注册 Grammar（INSERT OR REPLACE 幂等）。"""
        spec = json.dumps(grammar.to_dict(), ensure_ascii=False)
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO grammars(name,kind,spec,created_at)"
                " VALUES(?,?,?,?)",
                (grammar.name, grammar.kind, spec, time.time()),
            )

    def get_grammar(self, name: str):
        """按名取 Grammar；不存在返回 None。"""
        row = self.conn.execute(
            "SELECT spec FROM grammars WHERE name=?", (name,)
        ).fetchone()
        if not row:
            return None
        from ..grammar import Grammar  # 延迟 import, 避免包级依赖
        return Grammar.from_dict(json.loads(row["spec"]))

    def list_grammars(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT name FROM grammars ORDER BY name"
        ).fetchall()
        return [r["name"] for r in rows]

    def queue_pending(self, target_id: str) -> int:
        """目标引擎尚未消费的种子数。"""
        row = self.conn.execute(
            "SELECT COUNT(*) c FROM seed_queue WHERE target_id=? AND consumed_at IS NULL",
            (target_id,),
        ).fetchone()
        return row["c"]

    # ---- learning events (学习数据归一化: vendored 侧的 JSON → DB) ----

    def add_learning_event(self, source_file: str, protocol: str,
                           kind: str, payload: dict) -> bool:
        """写入一条学习事件。source_file 幂等（已导入返回 False）。"""
        with self.conn:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO learning_events"
                "(source_file,protocol,kind,payload,imported_at) VALUES(?,?,?,?,?)",
                (source_file, protocol, kind,
                 json.dumps(payload, ensure_ascii=False), time.time()),
            )
            return cur.rowcount > 0

    def query_learning_events(self, protocol: str = None,
                              limit: int = 100) -> list[dict]:
        sql = ("SELECT source_file,protocol,kind,payload,imported_at"
               " FROM learning_events")
        args: list = []
        if protocol:
            sql += " WHERE protocol=?"
            args.append(protocol)
        sql += " ORDER BY imported_at DESC LIMIT ?"
        args.append(limit)
        rows = self.conn.execute(sql, args).fetchall()
        return [
            {
                "source_file": r["source_file"],
                "protocol": r["protocol"],
                "kind": r["kind"],
                "payload": json.loads(r["payload"]),
                "imported_at": r["imported_at"],
            }
            for r in rows
        ]
