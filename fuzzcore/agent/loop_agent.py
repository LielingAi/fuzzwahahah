"""LoopAgent - 自主工作的 loop agent（工具形态的 fuzzing 工作流核心）。

与 FuzzLoopAgent（外部 for 循环跑 N 轮）不同，LoopAgent 是循环的主人：
agent 在任务内自主控制循环（观察→决策→行动→学习→判断终止），直到出 bug
或收敛或预算耗尽，产出任务报告。

五要素（ARCHITECTURE.md §10.3b 闭环的工作流化）：
  自主循环   loop_until_done（agent 控制, 非外部 rounds）
  记忆/学习  短期内存(策略有效性) + Corpus learning_events(跨任务)
  决策层次   decide: CONTINUE/REFLEX_RESCUE/ESCALATE_LLM/TRIAGE_CRASH/STOP_*
  自主终止   should_stop: 预算/收敛(长期无进展)/出 bug
  产出       TaskReport(覆盖曲线+崩溃根因+策略统计+学习结论+资源消耗)

设计决策（WREN 审定）：
  - 隐式状态机: decide 直接返回动作, current_phase 字段用于日志/调试
  - 学习数据: 内存(当前任务) + Corpus(跨任务) 双层
  - LLM 配额: llm_budget 限制预算内 LLM 调用次数, 超出回退反射弧
  - 收敛判定: converge_rounds 轮无覆盖增长+无新崩溃 → 收敛(保守: 宁多跑勿误停)
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..corpus import SqliteCorpus
from ..engine.base import CoverageReport, Engine, EngineHandle


class AgentAction(enum.Enum):
    """decide 的策略选择输出。"""
    CONTINUE = "continue"            # 继续 fuzz（覆盖在涨, 不动）
    REFLEX_RESCUE = "reflex"         # 反射弧自救（确定性种子, 零 LLM 成本）
    ESCALATE_LLM = "escalate_llm"    # 升级 LLM（语义种子, 有成本有配额）
    TRIAGE_CRASH = "triage"          # 崩溃分诊
    STOP_CONVERGED = "stop_conv"     # 收敛（长期无进展）
    STOP_BUDGET = "stop_budget"      # 预算耗尽


@dataclass
class Observation:
    """一次观察的快照。"""
    coverage: int
    crashes: int
    queue_pending: int
    elapsed: float
    phase: str


@dataclass
class TaskReport:
    """loop agent 任务报告（产出）。"""
    target_id: str = ""
    coverage_curve: list[int] = field(default_factory=list)
    final_coverage: int = 0
    crashes: int = 0
    rounds: int = 0
    elapsed_s: float = 0.0
    # 策略统计
    reflex_rescues: int = 0
    reflex_recovered: int = 0
    llm_escalations: int = 0
    llm_recovered: int = 0
    llm_calls_used: int = 0
    # 终止
    stop_reason: str = ""
    # 学习结论（跨任务）
    reflex_success_rate: float = 0.0
    llm_success_rate: float = 0.0


class LoopAgent:
    """自主工作的 loop agent。"""

    def __init__(self, engine: Engine, corpus: SqliteCorpus, target_id: str,
                 orchestrator=None,
                 plateau_threshold: int = 3, escalate_after: int = 2,
                 llm_budget: int = 5, converge_rounds: int = 5,
                 digest_delay: float = 2.0,
                 on_event: Optional[Callable] = None):
        self.engine = engine
        self.corpus = corpus
        self.target_id = target_id
        self.orchestrator = orchestrator
        self.plateau_threshold = plateau_threshold
        self.escalate_after = escalate_after
        self.llm_budget = llm_budget
        self.converge_rounds = converge_rounds
        self.digest_delay = digest_delay
        self.on_event = on_event

        # 工具（register_tool 注册）
        self.tools: dict[str, Callable] = {}

        # 短期记忆（当前任务）
        self.coverage_history: list[int] = []
        self._last_coverage = 0
        self._digest_baseline: Optional[int] = None
        self._digest_strategy: Optional[str] = None  # 上轮注入用的策略
        self.still_plateau_count = 0
        self.no_progress_rounds = 0
        self.crash_count = 0

        # 策略有效性（当前任务 + 跨任务从 Corpus 读）
        self.reflex_success = 0
        self.reflex_fail = 0
        self.llm_success = 0
        self.llm_fail = 0
        self.llm_calls_used = 0

        # 状态
        self.phase = "warmup"
        self._start_time: Optional[float] = None
        self._budget_s = 0.0
        self._stop_reason = ""

        # 报告
        self._report = TaskReport(target_id=target_id)

    # ---- 工具注册 ----

    def register_tool(self, name: str, fn: Callable) -> None:
        self.tools[name] = fn

    def _call_tool(self, name: str, **kwargs):
        if name not in self.tools:
            return None
        return self.tools[name](**kwargs)

    def _emit(self, event: str, **data) -> None:
        if self.on_event:
            self.on_event(event, data)

    # ---- 主循环（agent 自主控制）----

    def loop_until_done(self, handle: EngineHandle, budget_s: float,
                        observe_interval: float = 2.0) -> TaskReport:
        """自主工作流：观察→决策→行动→学习→判断终止，直到收敛/预算/出 bug。"""
        self._start_time = time.time()
        self._budget_s = budget_s
        self.phase = "fuzzing"

        while True:
            if self.should_stop():
                break
            obs = self.observe(handle)
            action = self.decide(obs)
            self._emit("decide", action=action.value, coverage=obs.coverage,
                       phase=self.phase)
            if action in (AgentAction.STOP_CONVERGED, AgentAction.STOP_BUDGET):
                break
            self.act(handle, action)
            self.learn(obs, action)
            if observe_interval > 0:
                time.sleep(observe_interval)

        self._report.stop_reason = self._stop_reason
        self._report.elapsed_s = time.time() - self._start_time
        return self.report()

    # ---- 观察 ----

    def observe(self, handle: EngineHandle) -> Observation:
        cov = self.engine.export_coverage(handle)
        self.coverage_history.append(cov.total_paths)
        # 只保留判定需要的窗口（platform + converge）
        keep = max(self.plateau_threshold, self.converge_rounds) + 2
        if len(self.coverage_history) > keep:
            self.coverage_history = self.coverage_history[-keep:]
        self._last_coverage = cov.total_paths

        # 上一轮 inject 的消化判定（延迟一轮, 等引擎消化）
        self._judge_digest(cov.total_paths)

        # 无进展计数
        if len(self.coverage_history) >= 2 \
                and self.coverage_history[-1] == self.coverage_history[-2]:
            self.no_progress_rounds += 1
        else:
            self.no_progress_rounds = 0

        # 崩溃数追踪
        self._report.crashes = max(self._report.crashes, cov.unique_crashes)
        self._report.coverage_curve.append(cov.total_paths)
        self._report.rounds += 1
        self._report.final_coverage = cov.total_paths

        return Observation(
            coverage=cov.total_paths,
            crashes=cov.unique_crashes,
            queue_pending=self.corpus.queue_pending(self.target_id),
            elapsed=time.time() - self._start_time if self._start_time else 0.0,
            phase=self.phase,
        )

    # ---- 决策（策略选择）----

    def decide(self, obs: Observation) -> AgentAction:
        """基于观察 + 记忆的策略选择。"""
        # 崩溃优先
        if obs.crashes > self.crash_count:
            self.phase = "triaging"
            return AgentAction.TRIAGE_CRASH
        # 覆盖在涨 → 继续
        if self._coverage_rising():
            self.phase = "fuzzing"
            return AgentAction.CONTINUE
        # 平台期
        if self._is_plateau():
            self.phase = "plateau"
            # 反射弧历史有效或没试过 → 先试反射弧（零成本）
            if self.still_plateau_count < self.escalate_after:
                return AgentAction.REFLEX_RESCUE
            # 反射弧连续无效 → LLM（配额内）
            if self.orchestrator is not None and self.llm_calls_used < self.llm_budget:
                return AgentAction.ESCALATE_LLM
            # 反射弧+LLM 都无效/配额尽 → 收敛
            return AgentAction.STOP_CONVERGED
        # 默认继续
        self.phase = "fuzzing"
        return AgentAction.CONTINUE

    def _coverage_rising(self) -> bool:
        if len(self.coverage_history) < 2:
            return False
        return self.coverage_history[-1] > self.coverage_history[-2]

    def _is_plateau(self) -> bool:
        if len(self.coverage_history) < self.plateau_threshold + 1:
            return False
        recent = self.coverage_history[-(self.plateau_threshold + 1):]
        return len(set(recent)) == 1 and recent[0] > 0

    # ---- 行动 ----

    def act(self, handle: EngineHandle, action: AgentAction) -> None:
        if action == AgentAction.CONTINUE:
            return  # 引擎自己跑
        if action == AgentAction.REFLEX_RESCUE:
            self._reflex_rescue(handle)
        elif action == AgentAction.ESCALATE_LLM:
            self._llm_escalate()
            seeds = self._call_tool("pull_seeds") or []
            if seeds:
                self._inject_and_digest(handle, seeds, strategy="llm")
        elif action == AgentAction.TRIAGE_CRASH:
            self._triage_crash(handle)

    def _reflex_rescue(self, handle: EngineHandle) -> None:
        """反射弧自救：先消费 LLM 队列种子，空则确定性合成兜底。"""
        seeds = self._call_tool("pull_seeds") or []
        if not seeds:
            seeds = self._call_tool("generate_seeds") or []
        if seeds:
            self._inject_and_digest(handle, seeds, strategy="reflex")

    def _inject_and_digest(self, handle: EngineHandle, seeds: list,
                           strategy: str) -> None:
        """注入 + 重启消化 + 记录基线（下一轮观察判 recovered/still_plateau）。"""
        self.engine.inject_seeds(handle, seeds)
        self._emit("seeds_injected", count=len(seeds), strategy=strategy)
        if hasattr(self.engine, "restart"):
            self.engine.restart(handle)
            self._emit("engine_restarted", engine=self.engine.id)
        self._digest_baseline = self._last_coverage
        self._digest_strategy = strategy
        if self.digest_delay > 0:
            time.sleep(self.digest_delay)

    def _llm_escalate(self) -> None:
        """升级 LLM 编排：LLM 生成语义种子进队列（下一轮 pull 消费）。"""
        if self.orchestrator is None:
            return
        self.llm_calls_used += 1
        self._report.llm_escalations += 1
        self._report.llm_calls_used = self.llm_calls_used
        self._emit("llm_escalate", coverage=self._last_coverage,
                   llm_calls=self.llm_calls_used)
        grammar_name = self._current_grammar_name()
        self.orchestrator.on_plateau(self.target_id, grammar_name,
                                     self._last_coverage)

    def _triage_crash(self, handle: EngineHandle) -> None:
        """崩溃分诊：新崩溃产生时调用（LLM 分诊或 cdb）。"""
        self.crash_count = self._report.crashes
        self._emit("triage_crash", crashes=self.crash_count)
        if self.orchestrator is not None and self.llm_calls_used < self.llm_budget:
            self.llm_calls_used += 1
            self._report.llm_calls_used = self.llm_calls_used
            out_dir = handle.meta.get("out_dir", "")
            self.orchestrator.on_crash(self.target_id, out_dir)

    def _current_grammar_name(self) -> str:
        """当前 grammar 名（Corpus 里注册的）。"""
        grammars = self.corpus.list_grammars()
        return grammars[-1] if grammars else self.target_id

    # ---- 学习（决策结果写记忆）----

    def learn(self, obs: Observation, action: AgentAction) -> None:
        """把决策结果写记忆（短期内存 + Corpus learning_events 跨任务）。"""
        # 策略有效性统计在 _judge_digest 里更新（消化判定后）
        # 这里持久化策略结果到 Corpus（跨任务学习）
        if action in (AgentAction.REFLEX_RESCUE, AgentAction.ESCALATE_LLM):
            self.corpus.add_learning_event(
                source_file=f"{self.target_id}_round{self._report.rounds}",
                protocol=self.target_id, kind="strategy",
                payload={
                    "action": action.value,
                    "coverage": obs.coverage,
                    "still_plateau_count": self.still_plateau_count,
                    "reflex_rate": self._reflex_rate(),
                    "llm_rate": self._llm_rate(),
                    "timestamp": time.time(),
                })

    def _judge_digest(self, coverage: int) -> None:
        """上一轮 inject 的消化判定（延迟一轮）。"""
        if self._digest_baseline is None:
            return
        baseline = self._digest_baseline
        strategy = self._digest_strategy
        self._digest_baseline = None
        self._digest_strategy = None
        if coverage > baseline:
            self.still_plateau_count = 0
            self._emit("recovered", before=baseline, after=coverage,
                       strategy=strategy)
            if strategy == "reflex":
                self.reflex_success += 1
                self._report.reflex_recovered += 1
            elif strategy == "llm":
                self.llm_success += 1
                self._report.llm_recovered += 1
        else:
            self.still_plateau_count += 1
            self._emit("still_plateau", coverage=coverage,
                       count=self.still_plateau_count, strategy=strategy)
            if strategy == "reflex":
                self.reflex_fail += 1
            elif strategy == "llm":
                self.llm_fail += 1

    def _reflex_rate(self) -> float:
        total = self.reflex_success + self.reflex_fail
        return self.reflex_success / total if total else 0.0

    def _llm_rate(self) -> float:
        total = self.llm_success + self.llm_fail
        return self.llm_success / total if total else 0.0

    # ---- 自主终止 ----

    def should_stop(self) -> bool:
        """预算 / 收敛（长期无进展+无新崩溃）。"""
        if self._start_time is None:
            return False
        if time.time() - self._start_time > self._budget_s:
            self._stop_reason = "budget"
            return True
        if self.no_progress_rounds >= self.converge_rounds:
            self._stop_reason = "converged"
            return True
        return False

    # ---- 产出 ----

    def report(self) -> TaskReport:
        self._report.reflex_success_rate = self._reflex_rate()
        self._report.llm_success_rate = self._llm_rate()
        return self._report
