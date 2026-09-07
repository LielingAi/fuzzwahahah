"""FuzzLoopAgent 工具集（ARCHITECTURE.md §6 Phase 4 首批工具）。

- generate_seeds：由 Grammar 合成定向种子（结构化内容 + 重算校验和）。
- set_strategy：调整引擎策略参数（占位，参数由 engine.start 的 cfg 透传）。
- triage_crash：崩溃根因（委托 CdbMonitor，需 cdb）。
"""
from __future__ import annotations

from ..engine.base import Input
from ..grammar import Grammar, SeedSynthesis
from ..monitor import CdbMonitor


def make_seed_generator(grammar: Grammar):
    """返回 generate_seeds 工具：count 个种子，content 作为 blob 字段的定向内容。"""
    synthesis = SeedSynthesis(grammar)
    blob_field = next((f for f in grammar.fields if f.type == "blob"), None)

    def generate_seeds(count: int = 1, content: bytes | None = None) -> list[Input]:
        seeds = []
        for _ in range(count):
            overrides = None
            if content is not None and blob_field is not None:
                overrides = {blob_field.name: content}
            data = synthesis.generate(overrides)
            seeds.append(Input(data=data, provenance={"src": "agent", "grammar": grammar.name}))
        return seeds

    return generate_seeds


def make_seed_puller(corpus, target_id: str):
    """返回 pull_seeds 工具：从种子队列取出未消费种子并转为 Input 列表。

    对应 Fuzzillai generated_program_queue 模式: 外部生成器 (如启发式/AI 种子
    合成器) 把种子 enqueue 进 SQLite 队列, Agent 在调度时 pull 出来注入引擎。
    """
    def pull_seeds(limit: int = 100) -> list[Input]:
        rows = corpus.pull_seed(target_id, limit)
        return [
            Input(data=r["data"],
                  provenance={**(r["provenance"] or {}), "src": "queue"})
            for r in rows
        ]

    return pull_seeds


def make_set_strategy():
    """返回 set_strategy 工具：记录要调整的策略参数。"""
    def set_strategy(**params):
        return {"strategy": params}

    return set_strategy


def make_triage_crash(cdb_path: str = "cdb.exe"):
    """返回 triage_crash 工具：分析崩溃 dump（需 cdb，否则报告不可用）。

    dump_file 未显式提供时, 自动从 out_dir 找最新的 crash 文件
    (AFL++ 布局 <out_dir>/**/crashes/id:* 或 libFuzzer 的 crash-*)。
    """
    from pathlib import Path

    monitor = CdbMonitor(cdb_path)

    def _find_latest_crash(out_dir: str) -> str | None:
        base = Path(out_dir)
        if not base.exists():
            return None
        candidates = [
            p for p in base.rglob("*")
            if p.is_file() and (p.name.startswith("id:") or p.name.startswith("crash-"))
        ]
        if not candidates:
            return None
        return str(max(candidates, key=lambda p: p.stat().st_mtime))

    def triage_crash(dump_file: str | None = None, log_file: str | None = None,
                     out_dir: str | None = None):
        if not dump_file and out_dir:
            dump_file = _find_latest_crash(out_dir)
        if not dump_file:
            return {"available": monitor.available(),
                    "note": "no dump file provided and no crash found in out_dir"}
        if not log_file:
            log_file = str(Path(dump_file).with_suffix(".triage.log"))
        report = monitor.analyze_dump(dump_file, log_file)
        if report is None:
            return {"available": False, "note": "cdb not installed"}
        return {"report": report, "dump_file": dump_file, "log_file": log_file}

    return triage_crash
