"""DeepSeek 编排器 — 用 DeepSeek API（OpenAI-compatible）做 LLM 编排。

与 LLMOrchestrator（Kimi Code ACP）并存的另一种 LLM 后端：
- Kimi Code ACP: spawn kimi 子进程, 经 ACP+MCP 协议, LLM 在 kimi 进程里调 MCP 工具
- DeepSeek: 进程内 OpenAI function calling, LLM 的 tool_call 由本进程直接执行
  fuzzcore 工具（复用 fuzzcore/mcp/server.py 的 MCPServer 工具实现, 无子进程）

工具产出强制过 VerificationGate / IR 严格校验（type 白名单），幻觉进不了语料库。
API key 经环境变量 OPENAI_API_KEY 提供, 不硬编码。
"""
from __future__ import annotations

import json
import os
from typing import Optional

from fuzzcore.mcp.server import MCPServer

SYSTEM_PROMPT = """你是 fuzz 平台的结构综合器与策略顾问。你通过调用工具操作 fuzz 平台。

工作原则:
- 只做事实性综合。recover_structure 返回的确定性事实优先; 工具说没找到就如实报告, 不要臆造。
- 所有 grammar 产出必须通过 register_grammar 注册 (schema + IR type 白名单校验)。
  若被拒, 读错误信息里的合法 type 与示例, 修正后重试。
- 种子生成用 generate_seeds (已过 VerificationGate)。
- 用中文汇报, 简洁 (不超过 6 行), 结论以工具返回为准。"""

MAX_ITERATIONS = 12


class DeepSeekOrchestrator:
    """DeepSeek function-calling 编排器（进程内执行 fuzzcore 工具）。"""

    def __init__(self, corpus_db: str, api_key: Optional[str] = None,
                 base_url: str = "https://api.deepseek.com/v1",
                 model: str = "deepseek-chat"):
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY", ""),
                             base_url=base_url)
        self.model = model
        self.mcp = MCPServer(corpus_db)  # 复用 MCP 工具实现（进程内）
        self.corpus = self.mcp.corpus

    # ---- 工具桥接 ----

    def _openai_tools(self) -> list[dict]:
        return [
            {"type": "function",
             "function": {"name": name,
                          "description": meta["description"],
                          "parameters": meta["inputSchema"]}}
            for name, (_, meta) in self.mcp._tools.items()
        ]

    def _execute_tool(self, name: str, arguments: dict):
        handler, _ = self.mcp._tools[name]
        try:
            return handler(arguments)
        except Exception as e:
            # 把异常(含 IR 严格校验的带提示拒绝)作为工具结果返回, 让 LLM 自我修正
            return {"error": f"{type(e).__name__}: {e}"}

    # ---- 编排循环 ----

    def _run(self, prompt: str, max_tokens: int = 4000) -> dict:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        tools = self._openai_tools()
        for _ in range(MAX_ITERATIONS):
            resp = self.client.chat.completions.create(
                model=self.model, messages=messages, tools=tools,
                max_tokens=max_tokens)
            msg = resp.choices[0].message
            messages.append(msg.model_dump(exclude_unset=True))
            if not msg.tool_calls:
                return {"stop_reason": "end_turn", "text": msg.content or ""}
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = self._execute_tool(tc.function.name, args)
                messages.append({
                    "role": "tool", "tool_call_id": tc.id,
                    "content": json.dumps(result, ensure_ascii=False),
                })
        return {"stop_reason": "max_iterations", "text": "(达到工具调用上限)"}

    # ---- 触发点（与 LLMOrchestrator 一致）----

    def on_new_target(self, binary_path: str, magic_hex: str = "",
                      extra_context: str = "") -> dict:
        prompt = f"""新目标接入：

- 二进制: {binary_path}
{f'- 已知 magic(hex): {magic_hex}' if magic_hex else ''}
{f'- 补充上下文: {extra_context}' if extra_context else ''}

任务（严格按序）：
1. 用 recover_structure 提取结构事实（magic 定位 + 字符串提示）。
2. 基于事实综合一个 Grammar 候选（信封结构: magic/length/checksum/blob），
   通过 register_grammar 注册。注意 IR 的 type 白名单:
   magic/checksum/length/blob/raw/uint —— 用这些 type, 不要自造。
   被拒就读错误信息修正再试。
3. 用 generate_seeds 为目标合成 5 个初始种子（target_id 用 grammar 名）。
4. 用 get_status 确认种子入队, 并汇报（不超过 6 行）。"""
        return self._run(prompt)

    def on_plateau(self, target_id: str, grammar_name: str,
                   coverage: int, context: str = "") -> dict:
        prompt = f"""目标 {target_id} 覆盖率在 {coverage} 进入平台期（长时间无新路径）。
{f'补充上下文: {context}' if context else ''}

任务（严格按序）：
1. 用 get_status 看目标 {target_id} 的状态（队列、语料、覆盖）。
2. 基于 grammar {grammar_name} 的结构语义, 判断哪类内容变异最可能穿过当前卡点
   （改变 blob 的语义模式, 而非盲翻字节）。
3. 用 generate_seeds 生成 10 个定向种子（content_hex 给有语义的定向内容的 hex）。
4. 用 get_status 确认入队, 并汇报策略结论（不超过 6 行）。"""
        return self._run(prompt)

    def on_crash(self, target_id: str, out_dir: str,
                 crash_context: str = "") -> dict:
        prompt = f"""目标 {target_id} 产生崩溃。
- 输出目录: {out_dir}
{f'- 崩溃上下文: {crash_context}' if crash_context else ''}

任务（严格按序）：
1. 读取崩溃上下文（crash 文件/报告）。
2. 给出根因假设（哪个字段/哪类变异触发, 最可能的缺陷类型）+ 置信度。
3. 用 generate_seeds 生成 5 个围绕崩溃点的变体种子（同源变异族）。
4. 汇报: 根因假设 + 置信度 + 建议后续动作（不超过 8 行）。"""
        return self._run(prompt)

    def on_healthcheck(self, targets: list[str]) -> dict:
        prompt = f"""做一次全局健康检查。目标列表: {', '.join(targets)}

任务（严格按序）：
1. 对每个目标用 get_status 取快照。
2. 对比各目标队列积压与覆盖趋势, 判断资源分配是否合理。
3. 如有必要, 为队列空虚的目标用 generate_seeds 补充种子。
4. 汇报调度结论（不超过 8 行）。"""
        return self._run(prompt)
