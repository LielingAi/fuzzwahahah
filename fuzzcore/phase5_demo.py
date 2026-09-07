#!/usr/bin/env python3
"""phase5_demo.py - Phase 5 演示：读二进制 → 恢复 magic → Grammar → 种子合成。

流程：
  1. 在 7z.dll（真实解析器二进制）里定位 .7z 签名常量（读汇编/读字节）
  2. 提取字符串作为格式提示
  3. 从恢复的 magic 构建 Grammar（信封：magic + CRC + payload）
  4. 喂给 Phase 2 的 SeedSynthesis + VerificationGate，合成合法种子
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fuzzcore.recovery import StructureRecovery
from fuzzcore.grammar import Field, SeedSynthesis, VerificationGate

DLL = r"D:\7-Zip\7z.dll"
MAGIC_HEX = "377abcaf271c"  # .7z signature（真实场景应由字符串提示 + LLM 给出候选）


def main() -> int:
    rec = StructureRecovery()

    # 1. 恢复 magic（在解析器二进制里定位字节常量）
    magic = rec.recover_magic(DLL, MAGIC_HEX)
    offs = [hex(o) for o in magic["offsets"]]
    print(f"[1] magic 恢复: {magic['hex']} found={magic['found']} 偏移={offs}")

    # 2. 字符串（格式提示，辅助 LLM 判断这是 7z 格式）
    strings = rec.strings(DLL, min_len=3)
    hints = [s for s in strings if "7z" in s.lower()][:3]
    print(f"[2] 字符串提示: 共 {len(strings)} 个，含 '7z' 前 3 个: {hints}")

    # 3. 从恢复的 magic 构建 Grammar（信封）
    grammar = rec.build_grammar("seven_z", MAGIC_HEX, [
        Field("crc", "checksum", offset=6, size=4, endian="little",
              algorithm="crc32", over=["payload"]),
        Field("payload", "blob", offset=10),
    ])
    print(f"[3] Grammar: {grammar.name} fields={[f.name for f in grammar.fields]}")

    # 4. 喂给 Phase 2 的种子合成 + 验证门
    syn = SeedSynthesis(grammar)
    gate = VerificationGate(grammar)
    seed = syn.generate({"payload": b"recovered-structure-seed"})
    print(f"[4] 合成种子 {len(seed)}B magic前缀={seed[:6].hex()} gate={gate.validate(seed)}")

    print("[done] Phase 5 演示完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
