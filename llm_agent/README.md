# llm_agent — LLM 编排包

独立的 LLM 编排包：把 fuzzcore 平台事件转成 LLM 任务，驱动 LLM 通过 fuzzcore 的工具操作平台（结构综合、定向种子、崩溃分诊、调度建议）。

## 两种可互换的 LLM 后端

| 后端 | 类 | 机制 | 依赖 |
|---|---|---|---|
| **Kimi Code** | `LLMOrchestrator` | `kimi acp` 子进程（ACP 会话）+ fuzzcore MCP 工具 | Kimi Code CLI（已登录） |
| **DeepSeek** | `DeepSeekOrchestrator` | OpenAI-compatible function calling，进程内执行 fuzzcore 工具 | `OPENAI_API_KEY` 环境变量（DeepSeek key） |

两者触发点一致，产出都强制过 fuzzcore 的 VerificationGate / IR 严格校验。

## 编排触发点

```
on_new_target(binary_path, magic_hex, extra_context)   # 新目标: 恢复事实→综合 grammar→注册→初始种子
on_plateau(target_id, grammar_name, coverage)          # 平台期: 分析→定向种子→入队
on_crash(target_id, out_dir, crash_context)            # 崩溃: 分诊→根因假设→变体种子
on_healthcheck(targets)                                # 定时: 全局观测→调度建议
```

## 用法

```python
import os
os.environ["OPENAI_API_KEY"] = "sk-..."   # DeepSeek key
from llm_agent import DeepSeekOrchestrator

llm = DeepSeekOrchestrator(corpus_db="corpus.db")
llm.on_new_target("harness.exe", magic_hex="5d00008000",
                  extra_context="CRC32+LZMA harness")
```

或经 `fuzzcore` CLI 的 `--llm deepseek|kimi|none` 选择后端（见 README 快速开始）。

## 设计

- **协议面解耦**：本包不依赖 fuzzcore 内部对象——Kimi Code 走 ACP+MCP 协议，DeepSeek 走 function calling + fuzzcore 工具接口（复用 `fuzzcore/mcp/server.py` 的 `MCPServer` 工具实现）。
- **验证门兜底**：LLM 的一切产出（grammar/种子/变体）强制过验证门与 IR 严格校验，幻觉无法进入语料库。
- **严格校验下的自我修正**：IR type 白名单拒绝不规范 type 时，错误信息带合法 type + 正确示例，LLM 读后修正重试（实测 DeepSeek 首次被拒后补 `crc32` 注册成功）。
