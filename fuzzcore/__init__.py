"""FuzzWahahah 平台核心（架构改造后的新核心，见 ARCHITECTURE.md）。

包初始化时把 vendor 目录注入 sys.path，使 fuzzcore 内部模块可以直接
`from boofuzz import ...` 使用 vendored 副本（fuzzcore/vendor/boofuzz）。
项目根裸脚本（boofuzz_*_fuzzer.py 等）由 sitecustomize.py 覆盖同一路径。
"""

import sys
from pathlib import Path

_VENDOR = str(Path(__file__).resolve().parent / "vendor")
if _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)

__version__ = "0.1.0"
