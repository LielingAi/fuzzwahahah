#!/usr/bin/env python3
"""phase2_demo.py - Phase 2 演示：Grammar IR + 种子合成 + 验证门。

用 Phase 1 验证过的 CRC32+LZMA 格式：
  [4-byte CRC32(覆盖 props+lzma_data)][5-byte LZMA props][LZMA stream]

演示：
  1. 从 Grammar 合成合法种子
  2. 保结构变异（改内容、重算 CRC）→ 全部通过验证门
  3. 破坏 CRC → 验证门拦截
  4. 不保结构变异（改内容、不重算 CRC）→ 验证门拦截
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fuzzcore.grammar import Grammar, Field, SeedSynthesis, VerificationGate

CRC_LZMA_GRAMMAR = Grammar(
    name="crc32_lzma",
    kind="binary_file",
    fields=[
        Field(name="crc", type="checksum", offset=0, size=4, endian="little",
              algorithm="crc32", over=["props", "lzma_data"]),
        Field(name="props", type="raw", offset=4, size=5, default="5d00008000"),
        Field(name="lzma_data", type="blob", offset=9),
    ],
)


def main() -> int:
    syn = SeedSynthesis(CRC_LZMA_GRAMMAR)
    gate = VerificationGate(CRC_LZMA_GRAMMAR)

    # 1. 合成合法种子（用真实 LZMA 流，props 与压缩数据分别落到对应字段）
    import lzma
    data = b"hello structured fuzzing world " * 20
    c = lzma.compress(data, format=lzma.FORMAT_ALONE)
    props = c[:5]           # LZMA 属性头（5 字节）
    compressed = c[13:]     # 压缩数据（去 8 字节 size 字段）
    seed = syn.generate({"props": props, "lzma_data": compressed})
    print(f"[1] generate: {len(seed)}B, gate={gate.validate(seed)} (应 True)")

    # 2. 保结构变异
    ok = sum(1 for _ in range(100) if gate.validate(syn.mutate(seed, keep_structure=True)))
    print(f"[2] 100 次保结构变异通过验证门: {ok}/100 (应 100)")

    # 3. 破坏 CRC
    bad = bytearray(seed)
    bad[0] ^= 0xFF
    print(f"[3] 破坏 CRC: gate={gate.validate(bytes(bad))} (应 False)")

    # 4. 不保结构变异（改内容不重算 CRC）
    bad2 = sum(1 for _ in range(100) if gate.validate(syn.mutate(seed, keep_structure=False)))
    print(f"[4] 100 次不保结构变异通过验证门: {bad2}/100 (应 0)")

    print("[done] Phase 2 演示完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
