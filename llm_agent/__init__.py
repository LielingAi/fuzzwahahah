"""llm_agent — 独立的 LLM 编排包（架构 v2）。

两种 LLM 后端（可互换, 触发点一致）:
- LLMOrchestrator (acp_client): 驱动 Kimi Code（kimi acp, ACP 会话 + MCP 工具）
- DeepSeekOrchestrator: DeepSeek API（OpenAI-compatible, 进程内 function calling）

本包不依赖 fuzzcore 内部对象 —— 通过 ACP/MCP 协议面或 fuzzcore 工具接口通信。
"""
from .acp_client import ACPClient, ACPError
from .orchestrator import LLMOrchestrator
from .deepseek_orchestrator import DeepSeekOrchestrator

__all__ = ["ACPClient", "ACPError", "LLMOrchestrator", "DeepSeekOrchestrator"]
__version__ = "0.1.0"
