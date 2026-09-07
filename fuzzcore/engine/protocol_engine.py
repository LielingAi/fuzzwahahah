"""ProtocolEngine - 把 boofuzz 包成统一 Engine（监督式黑盒，ARCHITECTURE.md §2.2）。

boofuzz 的 Session 是封闭循环，这里不重写它：ProtocolEngine 把 profile
（一个 boofuzz fuzzer 脚本）作为子进程启动，观察其输出（engine.log 里的
"CASE n" 进度与 "CRASH" 崩溃标记）作为反馈。

profile 约定：`python <profile> <host> <port> [--timeout N] [--max-cases N]`
"""
from __future__ import annotations

from pathlib import Path

from .base import CoverageReport, Target, TargetKind, FeedbackKind
from .base_process import BaseProcessEngine


class ProtocolEngine(BaseProcessEngine):
    # boofuzz 的反馈是代理指标（engine.log 的用例数/崩溃计数）, 不是真覆盖
    feedback_kind = FeedbackKind.PROXY_METRICS

    def __init__(self, profile_script: str, python: str = "python"):
        super().__init__(id="protocol")
        self.profile_script = profile_script
        self.python = python

    def _build_command(self, target: Target, seed_dir: str, out_dir: str, **cfg) -> list[str]:
        assert target.kind == TargetKind.SERVICE, "ProtocolEngine needs a SERVICE target"
        # target.command 形如 "host port"（专用 profile）或 "protocol host port"（通用 profile）
        cmd = [self.python, self.profile_script] + target.command.split()
        if "timeout" in cfg:
            cmd += ["--timeout", str(cfg["timeout"])]
        if "max_cases" in cfg and cfg["max_cases"]:
            cmd += ["--max-cases", str(cfg["max_cases"])]
        return cmd

    def _coverage_from_dir(self, out_dir: str) -> CoverageReport:
        cov = CoverageReport()
        log = Path(out_dir) / "engine.log"
        if not log.exists():
            return cov
        text = log.read_text(errors="ignore")
        cov.total_paths = text.count("CASE ")
        cov.unique_crashes = text.count("CRASH")
        return cov
