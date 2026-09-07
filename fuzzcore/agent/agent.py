"""FuzzLoopAgent - 外层调度内核（ARCHITECTURE.md §2.2 / §6 Phase 4）。

Agent 只在外层循环（秒级、高杠杆），不进入内层变异。状态机：
  observe(读覆盖) -> decide(平台期? 崩溃? 健康?) -> act(调用工具) -> 循环

工具通过 register_tool 注册，事件通过 emit 派发。
"""
from __future__ import annotations

import time
from typing import Callable, Optional

from ..engine.base import CoverageReport, Engine, Input


class FuzzLoopAgent:
    def __init__(self, engine: Engine, plateau_threshold: int = 3,
                 restart_on_inject: bool = True, escalate_after: int = 2,
                 on_escalate: Optional[Callable] = None,
                 digest_delay: float = 0.0):
        self.engine = engine
        self.plateau_threshold = plateau_threshold
        # 真实引擎运行中不读语料目录 —— 注入种子后需要重启消化（SeedDigestCycle）。
        # MockEngine 等注入即生效的引擎没有 restart 方法, 自动跳过。
        self.restart_on_inject = restart_on_inject
        # 重启后等待引擎消化新种子再观察, 否则 recovered 判定早于消化（误报 still_plateau）。
        self.digest_delay = digest_delay
        # 升级钩子: 连续 escalate_after 次自救无效 (still_plateau) 后调用 on_escalate,
        # 用于升级到 LLM 编排 (LLMOrchestrator.on_plateau)。
        self.escalate_after = escalate_after
        self.on_escalate = on_escalate
        self._still_plateau_count = 0
        # SeedDigestCycle 延迟判定基线: inject+restart 后引擎需时间消化新种子,
        # recovered/still_plateau 不在注入当轮判定, 而是下一轮 observe 与此基线对比。
        self._digest_baseline: Optional[int] = None
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
        """单步：观察 -> 平台期则先消费 LLM 队列种子(pull)再反射弧合成(generate)
        兜底 -> 注入+重启消化 -> 下一轮对比基线判 recovered/still_plateau ->
        连续自救无效则经 on_escalate 升级 LLM。"""
        cov = self.observe(handle)

        # 0. 上一轮 inject+restart 后的消化判定（延迟一轮, 等引擎消化新种子）
        if self._digest_baseline is not None:
            baseline = self._digest_baseline
            self._digest_baseline = None
            if cov.total_paths > baseline:
                self._still_plateau_count = 0
                self.emit("recovered", before=baseline, after=cov.total_paths)
            else:
                self._still_plateau_count += 1
                self.emit("still_plateau", coverage=cov.total_paths,
                          count=self._still_plateau_count)
                if (self.on_escalate is not None
                        and self._still_plateau_count >= self.escalate_after):
                    self.emit("escalate", count=self._still_plateau_count)
                    self.on_escalate(cov, cov)
                    self._still_plateau_count = 0

        if self.detect_plateau():
            self.emit("plateau", coverage=cov.total_paths)
            # 1. 优先消费 LLM 编排进队列的种子（生成的、有语义的定向种子）
            seeds: list = []
            if "pull_seeds" in self.tools:
                seeds = self.call_tool("pull_seeds") or []
            # 2. 队列空则用反射弧 generate_seeds 兜底（确定性合成）
            if not seeds:
                if "generate_seeds" not in self.tools:
                    self.emit("plateau_unhandled", coverage=cov.total_paths)
                    return cov
                seeds = self.call_tool("generate_seeds", **tool_kwargs)
            if seeds:
                self.engine.inject_seeds(handle, seeds)
                self.emit("seeds_injected", count=len(seeds))
                # SeedDigestCycle: 注入 → 重启消化 → 记录基线, 下一轮判 recovered
                if self.restart_on_inject and hasattr(self.engine, "restart"):
                    self.engine.restart(handle)
                    self.emit("engine_restarted", engine=self.engine.id)
                self._digest_baseline = cov.total_paths
        return cov

    def run(self, handle, rounds: int, **tool_kwargs) -> CoverageReport:
        """跑 rounds 步调度循环，返回最终覆盖。"""
        final = CoverageReport()
        for _ in range(rounds):
            final = self.step(handle, **tool_kwargs)
        return final
