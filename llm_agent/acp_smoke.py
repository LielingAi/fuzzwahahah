"""acp_smoke.py - llm_agent 的 ACP 协议级冒烟（不消耗 LLM 额度）。

验证: kimi acp 启动 → initialize → session/new（挂 fuzzcore MCP）→ session/close。
不发送 prompt（prompt 才消耗模型额度）；完整编排链路见 llm_agent/orchestrator.py。

用法: python -m llm_agent.acp_smoke
"""
from __future__ import annotations

import sys
from pathlib import Path

from .acp_client import ACPClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    client = ACPClient(cwd=str(PROJECT_ROOT))
    try:
        client.start()
        print(f"[acp] agent: {client.agent_info.get('name')} "
              f"{client.agent_info.get('version')}")
        sid = client.new_session(
            cwd=str(PROJECT_ROOT),
            mcp_servers=[{
                "name": "fuzzcore",
                "command": sys.executable,
                "args": ["-m", "fuzzcore.mcp.server", "--corpus", "acp_smoke.db"],
                "env": [],
            }],
        )
        print(f"[acp] session created: {sid} (fuzzcore MCP attached)")
        client.close_session(sid)
        print("ACP SMOKE OK")
        return 0
    finally:
        client.stop()
        Path(PROJECT_ROOT / "acp_smoke.db").unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
