#!/usr/bin/env python3
"""phase4_demo.py - Phase 4 演示：FuzzLoopAgent 平台期 → 定向种子 → 覆盖回升。

用 MockEngine 模拟 CRC32 门（裸种子卡在门=覆盖 20，结构化种子穿过门=覆盖 223），
演示 Agent 的外层调度闭环：观察 → 检测平台期 → 生成定向种子 → 注入 → 覆盖回升。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fuzzcore.agent import FuzzLoopAgent, make_seed_generator
from fuzzcore.engine import CoverageReport, Engine, EngineHandle, EngineStatus
from fuzzcore.grammar import Field, Grammar, VerificationGate

GRAMMAR = Grammar(
    name="crc32_lzma",
    kind="binary_file",
    fields=[
        Field("crc", "checksum", offset=0, size=4, endian="little",
              algorithm="crc32", over=["props", "lzma_data"]),
        Field("props", "raw", offset=4, size=5, default="5d00008000"),
        Field("lzma_data", "blob", offset=9),
    ],
)


class MockEngine(Engine):
    """模拟校验和门：语料里任一合法（CRC 通过）种子 → 覆盖 223，否则 20。"""

    id = "mock"

    def __init__(self):
        self.gate = VerificationGate(GRAMMAR)
        self.corpus: list[bytes] = []
        self.handle = EngineHandle(self.id)

    def start(self, target, seed_dir, out_dir, **cfg):
        return self.handle

    def stop(self, handle):
        pass

    def status(self, handle):
        return EngineStatus(running=False, coverage=self.export_coverage(handle))

    def inject_seeds(self, handle, seeds):
        for s in seeds:
            self.corpus.append(s.data)

    def export_coverage(self, handle):
        deep = any(self.gate.validate(s) for s in self.corpus)
        return CoverageReport(total_paths=223 if deep else 20)


def main() -> int:
    engine = MockEngine()
    engine.corpus.append(os.urandom(56))  # 裸随机种子，卡在 CRC 门

    agent = FuzzLoopAgent(engine, plateau_threshold=3)
    agent.register_tool("generate_seeds", make_seed_generator(GRAMMAR))
    agent.on_event(lambda ev, data: print(f"  [event] {ev} {data}"))

    # 定向内容：合法 LZMA 流（穿过 CRC 门直达解码器）
    import lzma
    c = lzma.compress(b"hello agent-directed fuzzing " * 20, format=lzma.FORMAT_ALONE)
    content = c[:5] + c[13:]

    print(f"[init] coverage={engine.export_coverage(engine.handle).total_paths}")
    final = agent.run(engine.handle, rounds=8, count=1, content=content)
    print(f"[done] final coverage={final.total_paths} (应从 20 回升到 223)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
