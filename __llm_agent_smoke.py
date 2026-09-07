"""临时冒烟: llm_agent ACP 全链路（真实 Kimi Code 会话 + fuzzcore MCP 工具调用）。

验证点:
1. ACP initialize + session/new 携带 fuzzcore MCP server（stdio 传输）
2. LLM 自主发现并调用 get_status 工具（MCP 工具发现 + 调用链路）
3. 平台状态真实可读（corpus/queue 计数来自真实 SQLite）
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llm_agent import LLMOrchestrator


def main():
    corpus = "__llm_smoke.db"
    with LLMOrchestrator(workdir=str(Path(__file__).resolve().parent),
                         corpus_db=corpus,
                         on_text=lambda t: print(t, end="", flush=True)) as orch:
        result = orch.ask(
            "调用 fuzzcore MCP 的 get_status 工具（target_id 传 \"smoke_test\"），"
            "把返回的 JSON 原样贴出来, 然后用一行中文说明语料库是否为空。",
            timeout=300,
        )
        print()
        print(f"stop_reason: {result['stop_reason']}")
        # 断言: LLM 确实拿到了工具返回（content 里应有 corpus_total / queue_pending 字段）
        assert "corpus_total" in result["text"] or "queue_pending" in result["text"], \
            "LLM 没有调用 get_status 工具（响应里没有平台状态字段）"
        print("LLM AGENT SMOKE OK")

    Path(corpus).unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
