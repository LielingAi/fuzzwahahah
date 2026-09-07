"""FuzzLoopAgent - 外层调度内核（ARCHITECTURE.md §2.2 / §6 Phase 4）。

Agent 只在外层循环（秒级、高杠杆），不进入内层变异。状态机：
  observe(读覆盖) -> decide(平台期? 崩溃? 健康?) -> act(调用工具) -> 循环

工具通过 register_tool 注册，事件通过 emit 派发。
"""
from __future__ import annotations

from typing import Callable, Optional

from ..engine.base import CoverageReport, Engine, Input


class FuzzLoopAgent:
    def __init__(self, engine: Engine, plateau_threshold: int = 3,
                 restart_on_inject: bool = True):
        self.engine = engine
        self.plateau_threshold = plateau_threshold
        # 真实引擎运行中不读语料目录 —— 注入种子后需要重启消化（SeedDigestCycle）。
        # MockEngine 等注入即生效的引擎没有 restart 方法, 自动跳过。
        self.restart_on_inject = restart_on_inject
        self.tools: dict[str, Callable] = {}
        self.listeners: list[Callable[[str, dict], None]] = []
        self.coverage_history: list[int] = []
        self._last_coverage = 0

    # ---- 工具注册 ----

    def register_tool(self, name: str, fn: Callable) -> None:
        self.tools[name] = fn

    def call_tool(self, name: str, **kwargs):
        if name not in self.tools:
            raise KeyError(f"tool not registered: {name}")
        return self.tools[name](**kwargs)

    # ---- 事件 ----

    def on_event(self, fn: Callable[[str, dict], None]) -> None:
        self.listeners.append(fn)

    def emit(self, event: str, **data) -> None:
        for fn in self.listeners:
            fn(event, data)

    # ---- 观察 / 决策 ----

    def observe(self, handle) -> CoverageReport:
        cov = self.engine.export_coverage(handle)
        self.coverage_history.append(cov.total_paths)
        # 只保留 detect_plateau 需要的窗口, 防止长期运行内存无界增长
        if len(self.coverage_history) > self.plateau_threshold + 1:
            self.coverage_history = self.coverage_history[-(self.plateau_threshold + 1):]
        self._last_coverage = cov.total_paths
        return cov

    def detect_plateau(self) -> bool:
        """覆盖在最近 plateau_threshold+1 次观察里没有增长。"""
        if len(self.coverage_history) < self.plateau_threshold + 1:
            return False
        recent = self.coverage_history[-(self.plateau_threshold + 1):]
        return len(set(recent)) == 1 and recent[0] > 0

    # ---- 主循环 ----

    def step(self, handle, **tool_kwargs) -> CoverageReport:
        """单步：观察 -> 若平台期则生成种子并注入（真实引擎会重启消化）。返回观察到的覆盖。"""
        cov = self.observe(handle)
        if self.detect_plateau():
            self.emit("plateau", coverage=cov.total_paths)
            # 未注册 generate_seeds 工具时无法自救, 保持观察模式
            if "generate_seeds" not in self.tools:
                self.emit("plateau_unhandled", coverage=cov.total_paths)
                return cov
            seeds = self.call_tool("generate_seeds", **tool_kwargs)
            if seeds:
                self.engine.inject_seeds(handle, seeds)
                self.emit("seeds_injected", count=len(seeds))
                # SeedDigestCycle: 注入 → 重启消化 → 再观察
                if self.restart_on_inject and hasattr(self.engine, "restart"):
                    self.engine.restart(handle)
                    self.emit("engine_restarted", engine=self.engine.id)
                after = self.observe(handle)
                if after.total_paths > cov.total_paths:
                    self.emit("recovered",
                              before=cov.total_paths, after=after.total_paths)
                else:
                    self.emit("still_plateau", coverage=after.total_paths)
                return after
        return cov

    def run(self, handle, rounds: int, **tool_kwargs) -> CoverageReport:
        """跑 rounds 步调度循环，返回最终覆盖。"""
        final = CoverageReport()
        for _ in range(rounds):
            final = self.step(handle, **tool_kwargs)
        return final
