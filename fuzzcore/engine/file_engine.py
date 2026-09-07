"""FileEngine：文件格式 fuzz 的两个 driver（见 ARCHITECTURE.md §6 Phase 1）。

- WinAFLFileEngine：黑盒，DynamoRIO 动态插桩，覆盖来自 AFL fuzzer_stats。
- LibFuzzerFileEngine：源码 harness，进程内覆盖，覆盖来自 libFuzzer 日志。

两个 driver 共用 BaseProcessEngine 的生命周期，只差命令行与反馈解析。
CLI 细节（-target_offset / -nargs / -fuzz_iterations / libFuzzer 参数）在二进制落地后做最终校准。
"""
from __future__ import annotations

import glob
import os
import re
from pathlib import Path
from typing import Optional

from .base import CoverageReport, Target, TargetKind
from .base_process import BaseProcessEngine
from ..feedback import coverage_from_fuzzer_stats


class WinAFLFileEngine(BaseProcessEngine):
    """WinAFL 黑盒文件 fuzz，支持两种插桩后端。

    mode="tinyinst"（默认，推荐）：TinyInst 调试器插桩，afl-fuzz -y。
        Windows 25H2 (build 26200) 下 DynamoRIO 对 kernel32 系统调用路径的
        翻译有 execute-fault 兼容问题（所有 DR 版本均受影响），TinyInst 不依赖
        DynamoRIO，是 25H2 上的可用路径。
    mode="dynamorio"：DynamoRIO 代码缓存插桩（旧 Windows 版本可用）。
    """

    def __init__(self, afl_fuzz: str, coverage_modules: list[str],
                 target_module: str,
                 mode: str = "tinyinst",
                 dynamorio_dir: str = "",
                 target_offset: Optional[str] = None,
                 target_method: Optional[str] = None,
                 nargs: int = 2, timeout_ms: int = 5000,
                 iterations: int = 5000):
        super().__init__(id="winafl_file")
        assert mode in ("tinyinst", "dynamorio"), f"unknown mode: {mode}"
        self.afl_fuzz = afl_fuzz
        self.mode = mode
        self.dynamorio_dir = dynamorio_dir
        self.coverage_modules = coverage_modules
        self.target_module = target_module
        self.target_offset = target_offset
        self.target_method = target_method
        self.nargs = nargs
        self.timeout_ms = timeout_ms
        self.iterations = iterations

    def _build_command(self, target: Target, seed_dir: str, out_dir: str, **cfg) -> list[str]:
        assert target.kind == TargetKind.BINARY
        cmd = [self.afl_fuzz]
        if self.mode == "tinyinst":
            cmd += ["-y"]  # TinyInst 模式
        cmd += ["-i", seed_dir, "-o", out_dir, "-t", f"{self.timeout_ms}+",
                "-m", "none"]  # none: Windows job 内存限制与调试器插桩不兼容
        if self.mode == "dynamorio":
            cmd += ["-D", self.dynamorio_dir]
        cmd += ["--"]

        # 插桩目标模块（TinyInst: -instrument_module / DynamoRIO: -coverage_module）
        module_flag = "-instrument_module" if self.mode == "tinyinst" else "-coverage_module"
        for m in self.coverage_modules:
            cmd += [module_flag, m]

        if self.target_offset or self.target_method:
            # 持久模式：指定目标函数
            cmd += ["-target_module", self.target_module]
            if self.target_offset:
                cmd += ["-target_offset", self.target_offset]
            else:
                cmd += ["-target_method", self.target_method]
            cmd += ["-nargs", str(self.nargs)]
            if self.mode == "tinyinst":
                cmd += ["-persist", "-loop", "-iterations", str(self.iterations)]
            else:
                cmd += ["-fuzz_iterations", str(self.iterations)]
        else:
            # 整程序模式（非持久化，较慢但无需逆向入口）
            if self.mode == "dynamorio":
                cmd += ["-fuzz_iterations", "1"]
        cmd += ["--"]
        cmd += target.command.split()  # @@ 由 WinAFL 替换为输入文件路径
        return cmd

    def _coverage_from_dir(self, out_dir: str) -> CoverageReport:
        base = Path(out_dir)
        # 单 fuzzer 布局: <out_dir>/fuzzer_stats; 多 fuzzer: <out_dir>/<name>/fuzzer_stats
        candidates = [base / "fuzzer_stats", base / "default" / "fuzzer_stats"]
        candidates += sorted(base.glob("*/fuzzer_stats"))
        for stats in candidates:
            if stats.exists():
                return coverage_from_fuzzer_stats(str(stats))
        return CoverageReport()


class LibFuzzerFileEngine(BaseProcessEngine):
    """libFuzzer harness（源码 + clang-cl `-fsanitize=fuzzer`）文件 fuzz。"""

    def __init__(self, fuzz_target: str, timeout_s: int = 5, max_len: int = 4096):
        super().__init__(id="libfuzzer_file")
        self.fuzz_target = fuzz_target
        self.timeout_s = timeout_s
        self.max_len = max_len

    def _build_command(self, target: Target, seed_dir: str, out_dir: str, **cfg) -> list[str]:
        # libFuzzer 目标直接读 corpus 目录，不使用 @@ 占位符
        return [self.fuzz_target, seed_dir,
                f"-max_len={self.max_len}",
                f"-timeout={self.timeout_s}",
                f"-artifact_prefix={out_dir}/",
                "-print_final_stats=1"]

    def _coverage_from_dir(self, out_dir: str) -> CoverageReport:
        cov = CoverageReport()
        # cov 值来自 stderr 日志里的 "cov: N"（libFuzzer 周期性统计）
        log = Path(out_dir) / "engine.log"
        if log.exists():
            last_cov = 0
            for line in log.read_text(errors="ignore").splitlines():
                m = re.search(r"cov:\s*(\d+)", line)
                if m:
                    last_cov = int(m.group(1))
            cov.total_paths = last_cov
        # 崩溃 artifact 由 -artifact_prefix 落到 out_dir 下
        cov.unique_crashes = len(glob.glob(os.path.join(out_dir, "crash-*")))
        return cov
