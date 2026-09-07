"""FuzzJobRunner - 统一任务编排器（闭环：引擎生命周期 + FuzzLoopAgent + LLM 编排）。

把一次完整 fuzzing 任务串成自驱动状态机：

  新目标接入   register_grammar + 初始种子合成入队
       │
  稳态 fuzz    引擎 start → FuzzLoopAgent 周期 observe
       │
  平台期       反射弧自救: 先 pull_seeds(消费 LLM 队列) 再 generate_seeds(确定性兜底)
       │       → inject → SeedDigestCycle 重启 → 覆盖对比
       │
  自救无效     连续 escalate_after 次 still_plateau → on_escalate 升级 LLM
       │       (LLMOrchestrator.on_plateau → Kimi Code → MCP 生成定向种子进队列)
       │
  覆盖回升     下一轮 pull_seeds 消费 LLM 种子 → inject → 覆盖变化 → JobReport

LLM 作为"慢速种子合成器"嵌入反射弧循环：LLM 产出的种子经 SQLite 队列流入下一轮
pull，不直接打断内层 fuzz。所有种子强制过 VerificationGate（MCP generate_seeds）。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..corpus import SqliteCorpus
from ..engine.base import CoverageReport, Target
from ..grammar import Grammar, SeedSynthesis, VerificationGate
from .agent import FuzzLoopAgent
from .tools import make_corpus_seed_generator, make_seed_puller


@dataclass
class JobReport:
    """一次 fuzzing 任务的观测报告。"""
    target_id: str = ""
    rounds: int = 0
    coverage_curve: list[int] = field(default_factory=list)
    crashes: int = 0
    recovered_events: int = 0
    llm_escalations: int = 0
    seeds_injected: int = 0
    final_coverage: int = 0


class FuzzJobRunner:
    """统一任务编排器：引擎生命周期 + FuzzLoopAgent + 可选 LLM 编排。"""

    def __init__(self, engine, grammar: Grammar, corpus: SqliteCorpus,
                 orchestrator=None, target_id: Optional[str] = None,
                 plateau_threshold: int = 3, escalate_after: int = 2,
                 digest_delay: float = 0.0):
        self.engine = engine
        self.grammar = grammar
        self.corpus = corpus
        self.orchestrator = orchestrator  # llm_agent.LLMOrchestrator (可选)
        self.target_id = target_id or grammar.name
        self.plateau_threshold = plateau_threshold
        self.escalate_after = escalate_after
        self.digest_delay = digest_delay
        self._report = JobReport(target_id=self.target_id)

    def run(self, target: Target, seed_dir: str, out_dir: str,
            max_rounds: int = 20, round_interval: float = 1.0,
            init_seed_count: int = 10,
            on_event: Optional[Callable] = None) -> JobReport:
        """跑完整闭环，返回 JobReport。

        on_event(event, data): 订阅 agent 事件（plateau/recovered/still_plateau/
        escalate/seeds_injected/engine_restarted）。
        """
        # 1. 新目标接入：注册 grammar + 初始种子合成入队
        self.corpus.register_grammar(self.grammar)
        self._synthesize_initial_seeds(init_seed_count)

        # 2. 引擎启动
        handle = self.engine.start(target, seed_dir, out_dir)

        # 3. FuzzLoopAgent：pull_seeds(消费 LLM 队列) + generate_seeds(兜底)
        agent = FuzzLoopAgent(
            self.engine, plateau_threshold=self.plateau_threshold,
            escalate_after=self.escalate_after,
            on_escalate=self._llm_escalate,
            digest_delay=self.digest_delay,
        )
        agent.register_tool("pull_seeds", make_seed_puller(self.corpus, self.target_id))
        agent.register_tool("generate_seeds",
                            make_corpus_seed_generator(self.corpus, self.grammar.name))
        if on_event is not None:
            agent.on_event(on_event)
        agent.on_event(self._track_event)

        # 4. 主循环：观察 → 平台期自救 → 升级 LLM → 覆盖对比
        try:
            for _ in range(max_rounds):
                cov = agent.step(handle)
                self._observe(cov)
                if round_interval > 0:
                    time.sleep(round_interval)
        finally:
            self.engine.stop(handle)
        return self._report

    # ---- 内部 ----

    def _synthesize_initial_seeds(self, count: int) -> None:
        """新目标接入：用 grammar 合成初始合法种子（过验证门）入队。"""
        synthesis = SeedSynthesis(self.grammar)
        gate = VerificationGate(self.grammar)
        seed = synthesis.generate()
        for _ in range(count):
            if gate.validate(seed):
                self.corpus.enqueue_seed(
                    self.target_id, seed,
                    {"src": "runner_init", "grammar": self.grammar.name})
            seed = synthesis.mutate(seed, keep_structure=True)

    def _llm_escalate(self, cov_before: CoverageReport, cov_after: CoverageReport) -> None:
        """自救无效升级 LLM：LLM 分析学习数据 + grammar 语义, 生成定向种子进队列。
        种子经 SQLite 队列流入下一轮 pull_seeds, 不直接打断内层 fuzz。"""
        if self.orchestrator is None:
            return
        self._report.llm_escalations += 1
        self.orchestrator.on_plateau(
            self.target_id, self.grammar.name, cov_after.total_paths)

    def _observe(self, cov: CoverageReport) -> None:
        r = self._report
        r.rounds += 1
        r.coverage_curve.append(cov.total_paths)
        r.crashes = max(r.crashes, cov.unique_crashes)
        r.final_coverage = cov.total_paths

    def _track_event(self, event: str, data: dict) -> None:
        if event == "recovered":
            self._report.recovered_events += 1
        elif event == "seeds_injected":
            self._report.seeds_injected += data.get("count", 0)
