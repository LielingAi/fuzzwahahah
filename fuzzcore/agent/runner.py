"""FuzzJobRunner - 统一任务编排器（闭环：引擎生命周期 + LoopAgent + LLM 编排）。

把一次完整 fuzzing 任务串成自驱动状态机，核心是 LoopAgent 的自主工作流：

  新目标接入   register_grammar + 初始种子合成入队
       │
  loop agent   LoopAgent.loop_until_done（agent 自主控制循环）:
       │         observe(覆盖/崩溃/队列) → decide(策略选择) → act → learn
       │         平台期反射弧自救(先 pull LLM 队列, 再 generate 兜底)
       │         连续无效 → 升级 LLM(LLM 语义种子进队列回流)
       │         崩溃 → 分诊; 收敛/预算/出 bug → 自主终止
       │
  产出         TaskReport(覆盖曲线+崩溃+策略统计+学习结论+资源消耗)

LLM 作为"慢速种子合成器"嵌入 loop：LLM 产出的种子经 SQLite 队列流入下一轮
pull，不直接打断内层 fuzz。所有种子强制过 VerificationGate（MCP generate_seeds）。
"""
from __future__ import annotations

from typing import Callable, Optional

from ..corpus import SqliteCorpus
from ..engine.base import Target
from ..grammar import Grammar, SeedSynthesis, VerificationGate
from .loop_agent import LoopAgent, TaskReport
from .tools import make_corpus_seed_generator, make_seed_puller


class FuzzJobRunner:
    """统一任务编排器：引擎生命周期 + LoopAgent 自主工作流 + 可选 LLM 编排。"""

    def __init__(self, engine, grammar: Grammar, corpus: SqliteCorpus,
                 orchestrator=None, target_id: Optional[str] = None,
                 plateau_threshold: int = 3, escalate_after: int = 2,
                 digest_delay: float = 2.0, llm_budget: int = 5,
                 converge_rounds: int = 5):
        self.engine = engine
        self.grammar = grammar
        self.corpus = corpus
        self.orchestrator = orchestrator  # llm_agent 编排器 (可选)
        self.target_id = target_id or grammar.name
        self.plateau_threshold = plateau_threshold
        self.escalate_after = escalate_after
        self.digest_delay = digest_delay
        self.llm_budget = llm_budget
        self.converge_rounds = converge_rounds

    def run(self, target: Target, seed_dir: str, out_dir: str,
            budget_s: float = 60.0, observe_interval: float = 2.0,
            init_seed_count: int = 10,
            on_event: Optional[Callable] = None) -> TaskReport:
        """跑 loop agent 自主工作流，返回 TaskReport。

        on_event(event, data): 订阅 agent 事件（decide/seeds_injected/
        engine_restarted/recovered/still_plateau/llm_escalate/triage_crash）。
        """
        # 1. 新目标接入：注册 grammar + 初始种子合成入队
        self.corpus.register_grammar(self.grammar)
        self._synthesize_initial_seeds(init_seed_count)

        # 2. 引擎启动
        handle = self.engine.start(target, seed_dir, out_dir)

        # 3. LoopAgent：自主工作流（pull_seeds 消费 LLM 队列 + generate_seeds 兜底）
        agent = LoopAgent(
            self.engine, self.corpus, self.target_id,
            orchestrator=self.orchestrator,
            plateau_threshold=self.plateau_threshold,
            escalate_after=self.escalate_after,
            llm_budget=self.llm_budget,
            converge_rounds=self.converge_rounds,
            digest_delay=self.digest_delay,
            on_event=on_event,
        )
        agent.register_tool("pull_seeds", make_seed_puller(self.corpus, self.target_id))
        agent.register_tool("generate_seeds",
                            make_corpus_seed_generator(self.corpus, self.grammar.name))
        try:
            return agent.loop_until_done(handle, budget_s, observe_interval)
        finally:
            self.engine.stop(handle)

    # ---- 内部 ----

    def _synthesize_initial_seeds(self, count: int) -> None:
        """新目标接入：用 grammar 合成初始合法种子（过验证门）入队。"""
        if count <= 0:
            return
        synthesis = SeedSynthesis(self.grammar)
        gate = VerificationGate(self.grammar)
        seed = synthesis.generate()
        for _ in range(count):
            if gate.validate(seed):
                self.corpus.enqueue_seed(
                    self.target_id, seed,
                    {"src": "runner_init", "grammar": self.grammar.name})
            seed = synthesis.mutate(seed, keep_structure=True)
