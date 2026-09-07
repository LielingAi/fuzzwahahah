#!/usr/bin/env python3
"""phase6_demo.py - Phase 6 演示：FuzzilliEngine 驱动 fuzzillai + QuickJS（真实端到端）。

浏览器/JS 引擎的模糊测试复用了 fuzzillai（Fuzzilli 覆盖引导 fuzzer），
本 Engine 把它包进 FuzzWahahah 的统一接口，外层调度交给 FuzzLoopAgent。

依赖均 vendored 于主目录：
  - vendor/fuzzillai/.build/debug/FuzzilliCli.exe（swift build 产物）
  - vendor/quickjs/qjs_fuzzilli.exe（REPRL Windows 移植）
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fuzzcore.engine import FuzzilliEngine, Target, TargetKind

FUZZILLI_CLI = PROJECT_ROOT / "vendor" / "fuzzillai" / ".build" / "debug" / "FuzzilliCli.exe"
QJS = PROJECT_ROOT / "vendor" / "quickjs" / "qjs_fuzzilli.exe"


def main() -> int:
    if not FUZZILLI_CLI.exists() or not QJS.exists():
        print("[skip] FuzzilliCli/qjs_fuzzilli 未构建，先跑 scripts/setup_windows.ps1")
        return 0

    eng = FuzzilliEngine(fuzzilli_cli=str(FUZZILLI_CLI), js_engine=str(QJS),
                         profile="qjs", engine="mutation")
    target = Target(TargetKind.BROWSER, "qjs")

    # 展示包装后的命令行
    cmd = eng._build_command(target, seed_dir="", out_dir="out")
    print("[fuzzilli cmd] " + " ".join(cmd))

    # 真实端到端：启动 fuzzilli fuzz qjs，观察产出后停止
    work = Path(tempfile.mkdtemp(prefix="phase6_"))
    handle = eng.start(target, str(work / "in"), str(work / "out"))
    print(f"[engine] started, pid={handle.process.pid}, fuzzing 20s ...")
    time.sleep(20)
    cov = eng.export_coverage(handle)
    eng.stop(handle)
    out_entries = sorted(p.name for p in (work / "out").iterdir())
    print(f"[done] coverage crashes={cov.unique_crashes}, out={out_entries}")
    shutil.rmtree(work, ignore_errors=True)
    print("[done] Phase 6 演示完成（真实端到端）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
