#!/usr/bin/env python3
"""jobrunner_demo.py - 完整闭环端到端验证（真实引擎 + MockLLM）。

目标：7z harness（fuzz_crc_lzma.exe）—— CRC32 校验和门 + 门后 LZMA 解码。
  - 反射弧（generate_seeds, content=None）只保证结构合法（重算 CRC），blob 是
    占位垃圾 → 过 CRC 门但 LZMA 解码失败 → 浅覆盖平台期。
  - LLM（Mock）提供"有语义"的 blob（合法 LZMA 流）→ 穿过 LZMA 解码 → 深覆盖回升。

这正是反射弧的局限（懂结构不懂语义）与 LLM 的价值（提供语义内容）——
闭环验证"反射弧自救 → 连续无效升级 LLM → LLM 语义种子 → 覆盖回升"。

MockLLM 模拟 LLMOrchestrator.on_plateau 的产出（把语义种子 enqueue 进队列），
不调用真实 Kimi Code；真实 LLM 编排的接口与之一致（llm_agent/orchestrator.py）。
"""
from __future__ import annotations

import lzma
import shutil
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fuzzcore.agent import FuzzJobRunner
from fuzzcore.corpus import SqliteCorpus
from fuzzcore.engine.file_engine import LibFuzzerFileEngine
from fuzzcore.engine.base import Target, TargetKind
from fuzzcore.grammar import Field, Grammar

HARNESS = PROJECT_ROOT / "harness" / "fuzz_crc_lzma.exe"

# 与 phase2 一致的 CRC32+LZMA 信封 grammar
GRAMMAR = Grammar(
    name="crc32_lzma", kind="binary_file",
    fields=[
        Field("crc", "checksum", offset=0, size=4, endian="little",
              algorithm="crc32", over=["props", "lzma_data"]),
        Field("props", "raw", offset=4, size=5, default="5d00008000"),
        Field("lzma_data", "blob", offset=9),
    ],
)


class MockLLM:
    """模拟 LLMOrchestrator：on_plateau 时把"有语义"的种子（合法 LZMA 流）入队。"""

    def __init__(self, corpus, target_id):
        self.corpus = corpus
        self.target_id = target_id
        self.calls = 0

    def on_plateau(self, target_id, grammar_name, coverage, context=""):
        self.calls += 1
        # LLM 的"语义综合"：生成合法 LZMA 流作为 blob（反射弧不会做这个）
        payload = lzma.compress(b"agent-directed deep fuzzing " * 30,
                                format=lzma.FORMAT_ALONE)
        content = payload[:5] + payload[13:]  # 去 LZMA 头, 留 props(5B) + 流
        # 直接构造结构合法种子: 让反射弧的 generate_seeds 用此 content 重算 CRC
        from fuzzcore.agent.tools import make_corpus_seed_generator
        gen = make_corpus_seed_generator(self.corpus, grammar_name)
        for inp in gen(count=3, content=content):
            self.corpus.enqueue_seed(self.target_id, inp.data,
                                     {"src": "llm", "grammar": grammar_name})


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="jobrunner_"))
    corpus = SqliteCorpus(str(work / "corpus.db"))
    engine = LibFuzzerFileEngine(str(HARNESS), timeout_s=5, max_len=512)
    llm = MockLLM(corpus, GRAMMAR.name)

    # 从裸随机种子起步（无 grammar 指导的裸 fuzz）：覆盖会卡在 CRC 门 → 平台期,
    # 反射弧 generate_seeds 穿门 → 穿门后 blob 垃圾过不了 LZMA → 新平台期,
    # 反射弧再试仍无效 → 升级 LLM → LLM 语义种子(合法 LZMA 流) → 覆盖回升。
    seed_dir = work / "in"
    seed_dir.mkdir(parents=True, exist_ok=True)
    import os
    (seed_dir / "seed0").write_bytes(os.urandom(32))

    runner = FuzzJobRunner(engine, GRAMMAR, corpus, orchestrator=llm,
                           plateau_threshold=1, escalate_after=1,
                           digest_delay=1.5)
    target = Target(TargetKind.BINARY, "harness")

    events = []
    report = runner.run(target, str(seed_dir), str(work / "out"),
                        budget_s=40.0, observe_interval=2.0, init_seed_count=0,
                        on_event=lambda ev, d: events.append((ev, d)))

    print("=== TaskReport（loop agent 自主工作流）===")
    print(f"  rounds={report.rounds}  final_coverage={report.final_coverage}")
    print(f"  coverage_curve={report.coverage_curve}")
    print(f"  crashes={report.crashes}  终止={report.stop_reason}  耗时={report.elapsed_s:.1f}s")
    print(f"  反射弧: {report.reflex_rescues} 次(回升{report.reflex_recovered})  "
          f"LLM: {report.llm_escalations} 次(回升{report.llm_recovered}, 调用{report.llm_calls_used})")
    print(f"  策略成功率: 反射弧={report.reflex_success_rate:.0%}  LLM={report.llm_success_rate:.0%}")
    print(f"  MockLLM.on_plateau calls={llm.calls}")
    print("=== 关键事件 ===")
    for ev, d in events:
        print(f"  {ev}: {d}")

    shutil.rmtree(work, ignore_errors=True)
    # 闭环判据: 自主工作流收敛或预算内, 且有覆盖进展
    ok = report.stop_reason in ("converged", "budget") and report.final_coverage > 0
    print(f"[{'PASS' if ok else 'CHECK'}] loop agent: 终止={report.stop_reason}, "
          f"覆盖={report.final_coverage}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
