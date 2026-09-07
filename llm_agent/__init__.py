"""llm_agent — 独立的 LLM 编排包（架构 v2）。

定位：驱动 Kimi Code（kimi acp, Agent Client Protocol）作为 LLM 综合器/编排器，
通过 fuzzcore 的 MCP 工具操作平台。本包不依赖 fuzzcore 内部对象 ——
只通过 ACP（会话）与 MCP（工具）两个协议面通信，可以独立复用。
"""
from .acp_client import ACPClient, ACPError
from .orchestrator import LLMOrchestrator

__all__ = ["ACPClient", "ACPError", "LLMOrchestrator"]
__version__ = "0.1.0"
