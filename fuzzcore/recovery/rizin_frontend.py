"""RizinFrontend - rizin（Cutter）反汇编前端：字符串提取 + 基础分析。

Ghidra/IDA 的替代（本机有 Cutter/Rizin）。自动化走 rizin CLI（headless），
比 rzpipe 更稳（rzpipe 在大文件上会挂）。
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

RIZIN_CANDIDATES = [
    r"D:\Cutter-v2.4.1-Windows-x86_64\rizin.exe",
    "rizin",
]


class RizinFrontend:
    def __init__(self, rizin_path: str | None = None):
        self.rizin_path = rizin_path or self._find_rizin()

    @staticmethod
    def _find_rizin() -> str:
        for c in RIZIN_CANDIDATES:
            if shutil.which(c) or Path(c).exists():
                return c
        return "rizin"

    def run(self, binary: str, command: str, timeout: int = 120) -> str:
        cmd = [self.rizin_path, "-q", "-c", command, binary]
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        # 二进制捕获 + errors=replace：izz 输出含非 UTF-8 字节，text=True 会解码失败
        return (r.stdout or b"").decode("utf-8", errors="replace")

    def strings(self, binary: str, min_len: int = 3) -> list[str]:
        """提取所有字符串（izz）。返回字符串内容列表。"""
        out = self.run(binary, "izz", timeout=180)
        strings = []
        for line in out.splitlines():
            parts = line.split(maxsplit=7)
            # izz 列：idx vaddr paddr len slen section type string
            if len(parts) >= 8:
                s = parts[7]
                if len(s) >= min_len:
                    strings.append(s)
        return strings

    def info(self, binary: str) -> str:
        return self.run(binary, "iI", timeout=60)
