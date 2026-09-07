"""FuzzWahahah vendor 路径引导：import 本模块即把 fuzzcore/vendor 注入 sys.path。

boofuzz 是 vendored 库（fuzzcore/vendor/boofuzz），不通过 pip 安装。
项目根脚本的第一行写 `import fw_vendor`（必须在 from boofuzz import 之前）。
fuzzcore 包内模块不需要——fuzzcore/__init__.py 已处理。
"""
import sys
from pathlib import Path

_VENDOR = str(Path(__file__).resolve().parent / "fuzzcore" / "vendor")
if _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)
