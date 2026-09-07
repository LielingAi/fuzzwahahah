"""学习数据归一化：ai_learning_data/*.json → SQLite Corpus。

vendored 侧（boofuzz Session AI / enhanced engine）保持写 JSON 文件 ——
vendored 库不该反向依赖平台。平台侧通过本模块批量导入 DB，
Agent / LLM 编排只需查 learning_events 表。
source_file 幂等：重复导入同一文件不产生重复记录。

文件名约定：
  {protocol}_learning_data.json            → enhanced engine（协议级）
  global_learning_data.json                → enhanced engine（全局）
  {protocol}_session_data_{run_id}.json    → Session AI（协议级）
  session_data_{run_id}.json               → Session AI（全局）
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .store import SqliteCorpus

_RE_ENGINE_PROTO = re.compile(r"^(.+)_learning_data\.json$")
_RE_SESSION_PROTO = re.compile(r"^(.+)_session_data_.+\.json$")
_RE_SESSION_GLOBAL = re.compile(r"^session_data_.+\.json$")


def _classify(filename: str) -> tuple[str | None, str] | None:
    """文件名 → (protocol, kind)；不匹配的文件返回 None。"""
    m = _RE_SESSION_PROTO.match(filename)
    if m:
        return m.group(1), "session"
    if _RE_SESSION_GLOBAL.match(filename):
        return None, "session"
    if filename == "global_learning_data.json":
        return None, "engine"
    m = _RE_ENGINE_PROTO.match(filename)
    if m:
        return m.group(1), "engine"
    return None


def import_ai_learning_data(corpus: SqliteCorpus,
                            data_dir: str = "ai_learning_data") -> dict:
    """把目录下的学习数据 JSON 导入 Corpus，返回导入统计。"""
    base = Path(data_dir)
    stats = {"imported": 0, "skipped": 0, "invalid": 0, "files": []}
    if not base.exists():
        return stats
    for f in sorted(base.glob("*.json")):
        cls = _classify(f.name)
        if cls is None:
            stats["skipped"] += 1
            continue
        protocol, kind = cls
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            stats["invalid"] += 1
            continue
        if corpus.add_learning_event(f.name, protocol, kind, payload):
            stats["imported"] += 1
            stats["files"].append(f.name)
        else:
            stats["skipped"] += 1  # 已导入过
    return stats
