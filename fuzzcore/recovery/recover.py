"""StructureRecovery - 从二进制恢复输入格式结构 → Grammar IR。

本阶段落地"信封恢复"的最小可用切片：在二进制（解析器）里定位 magic 常量，
并结合字符串（格式提示）构建 Grammar。完整的 length/CRC/container 自动恢复
需要 LLM 综合器 + 数据流分析，属后续增强。
"""
from __future__ import annotations

from pathlib import Path

from ..grammar import Field, Grammar
from .rizin_frontend import RizinFrontend


class StructureRecovery:
    def __init__(self, frontend: RizinFrontend | None = None):
        self.frontend = frontend or RizinFrontend()

    # ---- 字节搜索 ----

    def search_bytes(self, binary: str, hex_pattern: str) -> list[int]:
        """在二进制文件里搜索字节序列，返回偏移列表。"""
        pattern = bytes.fromhex(hex_pattern)
        data = Path(binary).read_bytes()
        offsets = []
        start = 0
        while True:
            i = data.find(pattern, start)
            if i == -1:
                break
            offsets.append(i)
            start = i + 1
        return offsets

    def recover_magic(self, binary: str, hex_pattern: str) -> dict:
        """恢复 magic：确认字节序列在二进制中存在，返回 magic 信息。"""
        offsets = self.search_bytes(binary, hex_pattern)
        return {
            "hex": hex_pattern,
            "size": len(bytes.fromhex(hex_pattern)),
            "offsets": offsets,
            "found": len(offsets) > 0,
        }

    # ---- Grammar 构建 ----

    def build_grammar(self, name: str, magic_hex: str,
                      extra_fields: list[Field] | None = None) -> Grammar:
        """从恢复的 magic 构建 Grammar（magic 字段 + 可选额外字段）。"""
        fields = [Field("magic", "magic", offset=0,
                        size=len(bytes.fromhex(magic_hex)), value=magic_hex)]
        fields += extra_fields or []
        return Grammar(name, "binary_file", fields)

    # ---- 字符串（格式提示）----

    def strings(self, binary: str, min_len: int = 3) -> list[str]:
        return self.frontend.strings(binary, min_len)
