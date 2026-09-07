"""fuzzcore MCP 工具接口。

用法: `from fuzzcore.mcp.server import MCPServer` 或 `python -m fuzzcore.mcp.server`。
（__init__ 不 eager import server, 避免 `-m` 运行的 runpy 重复加载警告。）
"""
