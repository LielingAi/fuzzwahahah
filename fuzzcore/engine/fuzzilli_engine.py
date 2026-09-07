"""FuzzilliEngine - 包装 fuzzillai/Fuzzilli 作为 JS 引擎模糊测试引擎。

Fuzzilli 是覆盖引导的 JS 引擎 fuzzer（FuzzIL 中间语言 → JS），是浏览器
RCE（JIT/GC/bytecode 漏洞）的标准答案。fuzzillai 是在其上加 Dumpling 差分
oracle + FoG/EBG agent 的分叉，vendored 于 vendor/fuzzillai（主目录自包含）。

本 Engine 只包装 fuzzillai 的 FuzzilliCli（内层覆盖引导 fuzzer），外层调度
复用 FuzzWahahah 的 FuzzLoopAgent（避免与 fuzzillai 的 FoG/EBG 重复建设）。

Windows 端到端已就绪（ARCHITECTURE.md §6b）：FuzzilliCli.exe 驱动
vendor/quickjs/qjs_fuzzilli.exe（REPRL Windows 移植），fuzzcore 端到端抓 crash。
依赖（后续大工程）：v8/d8（depot_tools + gclient sync）。
"""
from __future__ import annotations

import glob
import os
from pathlib import Path

from .base import CoverageReport, Target
from .base_process import BaseProcessEngine


class FuzzilliEngine(BaseProcessEngine):
    def __init__(self, fuzzilli_cli: str = "FuzzilliCli",
                 js_engine: str = "qjs_fuzzilli.exe", profile: str = "qjs",
                 engine: str = "mutation", timeout_ms: int = 1500):
        super().__init__(id="fuzzilli")
        self.fuzzilli_cli = fuzzilli_cli
        self.js_engine = js_engine
        self.profile = profile
        self.engine = engine
        self.timeout_ms = timeout_ms

    def _build_command(self, target: Target, seed_dir: str, out_dir: str, **cfg) -> list[str]:
        # fuzzillai 的 FuzzilliCli 约定（--key=value 形式）：
        #   FuzzilliCli --profile=qjs --engine=mutation --storagePath=<dir> --timeout=<ms> <js_engine>
        # --overwrite: BaseProcessEngine 会先在 out_dir 写 engine.log, 导致 storagePath
        # 非空, fuzzilli 默认拒绝 — 必须 --overwrite 才接受。
        js = cfg.get("js_engine", self.js_engine)
        return [self.fuzzilli_cli,
                f"--profile={self.profile}",
                f"--engine={self.engine}",
                f"--storagePath={out_dir}",
                "--overwrite",
                f"--timeout={self.timeout_ms}",
                js]

    def _coverage_from_dir(self, out_dir: str) -> CoverageReport:
        cov = CoverageReport()
        # fuzzillai 崩溃样本落在 storagePath/crashes 下
        base = Path(out_dir)
        for pat in ("crashes/*", "*/crashes/*"):
            cov.unique_crashes = len(glob.glob(os.path.join(str(base), pat)))
            if cov.unique_crashes:
                break
        return cov
