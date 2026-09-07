"""LLM 编排器 — 事件驱动的 LLM 任务编排（架构 v2 §4）。

定位：把 fuzzcore 平台事件转成 LLM 任务，喂给 Kimi Code（ACP 会话）；
LLM 通过 fuzzcore 的 MCP 工具自主操作平台（编排循环由 Kimi Code agent 承担，
本类只做事件→prompt 策略与会话管理）。

四个编排触发点（对应 ARCHITECTURE.md §3 事件模型）：
  on_new_target   新目标接入 → 分析代码 → 综合 grammar → harness
  on_plateau      覆盖率平台期 → 分析变异历史 → 定向种子
  on_crash        崩溃产生 → 分诊 → 根因假设 → 新变异策略
  on_healthcheck  定时健康检查 → 全局调度建议

prompt 模板遵循"事实与推测分层"：recovery 产出的确定性事实直接注入 prompt，
LLM 只允许在事实上综合；产出强制过 fuzzcore 侧的 VerificationGate。
"""
from __future__ import annotations

import json
from typing import Callable, Optional

from .acp_client import ACPClient


class LLMOrchestrator:
    """事件→prompt 编排策略 + ACP 会话管理。"""

    def __init__(self, workdir: str, corpus_db: str = "corpus.db",
                 kimi_cmd: str = "kimi",
                 on_text: Optional[Callable[[str], None]] = None):
        self.workdir = workdir
        self.corpus_db = corpus_db
        self._kimi_cmd = kimi_cmd
        self._on_text = on_text or print
        self.client: Optional[ACPClient] = None
        self.session_id: Optional[str] = None

    # ---- 生命周期 ----

    def start(self) -> None:
        """启动 ACP 会话, 并把 fuzzcore MCP server 挂进会话。"""
        self.client = ACPClient(self._kimi_cmd, cwd=self.workdir)
        self.client.start()
        self.session_id = self.client.new_session(
            cwd=self.workdir,
            mcp_servers=[{
                "name": "fuzzcore",
                "command": "python",
                "args": ["-m", "fuzzcore.mcp.server", "--corpus", self.corpus_db],
                "env": [],
            }],
        )
        self._on_text(f"[llm_agent] ACP session started: {self.session_id} "
                      f"(agent={self.client.agent_info.get('name')})")

    def stop(self) -> None:
        if self.client:
            if self.session_id:
                try:
                    self.client.close_session(self.session_id)
                except Exception:
                    pass
            self.client.stop()
            self.client = None
            self.session_id = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    # ---- 编排触发点 ----

    def on_new_target(self, binary_path: str, magic_hex: str = "",
                      extra_context: str = "") -> dict:
        """新目标接入：恢复结构事实 → LLM 综合 grammar 候选 → 注册 → 初始种子。"""
        prompt = f"""你是 fuzz 平台的结构综合器。新目标接入：

- 二进制: {binary_path}
{f'- 已知 magic(hex): {magic_hex}' if magic_hex else ''}
{f'- 补充上下文: {extra_context}' if extra_context else ''}

任务（严格按序）：
1. 用 fuzzcore MCP 的 recover_structure 工具提取结构事实（magic 定位 + 字符串提示）。
2. 基于事实综合一个 Grammar 候选（信封结构: magic/length/checksum/blob），
   通过 register_grammar 注册（schema 由工具自检，不合法会被拒——被拒就修正再试）。
3. 用 generate_seeds 为目标合成 5 个初始种子（target_id 用 grammar 名）。
4. 最后用 get_status 确认种子已进入队列, 并用中文汇报结论（不超过 5 行）。

约束：只做事实性综合, 不要臆造 magic/校验和算法; 所有结论以工具返回为准。"""
        return self._run(prompt)

    def on_plateau(self, target_id: str, grammar_name: str,
                   coverage: int, context: str = "") -> dict:
        """覆盖率平台期：分析变异历史 → LLM 选定向内容 → 生成种子注入队列。"""
        prompt = f"""你是 fuzz 平台的策略顾问。目标 {target_id} 的覆盖率在 {coverage} 进入平台期
（长时间无新路径）。
{f'补充上下文: {context}' if context else ''}

任务（严格按序）：
1. 用 get_status 看目标 {target_id} 的当前状态（队列、语料、覆盖）。
2. 基于 grammar {grammar_name} 的结构语义, 判断哪类内容变异最可能穿过当前卡点
   （例如: 改变 blob 的语义模式, 而不是盲翻字节）。
3. 用 generate_seeds 生成 10 个定向种子（content_hex 给有语义的定向内容,
   可以是结构化数据、边界值、格式注入模式等的 hex）。
4. 用 get_status 确认种子入队, 并用中文汇报策略结论（不超过 5 行）。"""
        return self._run(prompt)

    def on_crash(self, target_id: str, out_dir: str,
                 crash_context: str = "") -> dict:
        """崩溃分诊：读崩溃上下文 → LLM 给根因假设 → 建议后续变异方向。"""
        prompt = f"""你是 fuzz 平台的崩溃分诊器。目标 {target_id} 产生了崩溃。

- 输出目录: {out_dir}
{f'- 崩溃上下文: {crash_context}' if crash_context else ''}

任务（严格按序）：
1. 读取崩溃上下文（crash 文件/报告; 可直接读文件或用 fuzzcore 工具）。
2. 给出根因假设（哪个字段/哪类变异触发的, 最可能的缺陷类型）。
3. 用 generate_seeds 生成 5 个"围绕崩溃点"的变体种子（同源变异族, 便于复现与最小化）。
4. 用中文汇报: 根因假设 + 置信度 + 建议的后续动作（不超过 8 行）。"""
        return self._run(prompt)

    def on_healthcheck(self, targets: list[str]) -> dict:
        """定时健康检查：全局观测 → 调度建议。"""
        prompt = f"""你是 fuzz 平台的调度器。做一次全局健康检查。

目标列表: {', '.join(targets)}

任务（严格按序）：
1. 对每个目标用 get_status 取快照。
2. 对比各目标的队列积压与覆盖趋势, 判断资源分配是否合理。
3. 如有必要, 为队列空虚的目标用 generate_seeds 补充种子。
4. 用中文汇报调度结论（不超过 8 行）。"""
        return self._run(prompt)

    # ---- 内部 ----

    def _run(self, prompt: str, timeout: float = 600.0) -> dict:
        assert self.client and self.session_id, "orchestrator not started"
        chunks: list[str] = []

        def on_update(update: dict):
            kind = update.get("sessionUpdate")
            if kind == "agent_message_chunk":
                chunk = update.get("content", {}).get("text", "")
                if chunk:
                    chunks.append(chunk)
                    self._on_text(chunk)

        result = self.client.prompt(self.session_id, prompt,
                                    on_update=on_update, timeout=timeout)
        return {"stop_reason": result.get("stopReason", "unknown"),
                "text": "".join(chunks)}

    def ask(self, prompt: str, timeout: float = 600.0) -> dict:
        """自由 prompt（编排之外的直接问答, 复用同一会话上下文）。"""
        return self._run(prompt, timeout)
