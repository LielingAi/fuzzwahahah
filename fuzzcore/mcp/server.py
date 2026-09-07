"""fuzzcore MCP server — 平台工具通过 stdio MCP 暴露给 LLM（Kimi Code ACP 会话）。

设计决定：
- 无状态：平台状态全部经由 SQLite Corpus 与文件系统（out_dir）共享，
  server 不持有引擎进程句柄 —— 与 fuzzcore 的"文件系统即接口"一致。
- 零依赖：手写最小 JSON-RPC 2.0（NDJSON framing），不引 mcp SDK。
- 所有 LLM 产出（grammar 候选、种子）强制过 VerificationGate / schema 校验，
  幻觉无法污染 corpus。

工具（对应 LLM 编排点）：
  register_grammar   分析代码后综合的 Grammar 候选 → 校验 → 入库
  generate_seeds     Grammar 合成 + 验证门 → 种子队列（engine 下个周期消费）
  recover_structure  二进制结构事实提取（magic 定位 + 字符串提示）
  get_status         语料 / 队列 / 覆盖快照（观测编排结果）
"""
from __future__ import annotations

import json
import sys
from typing import Any, Callable

from ..corpus import SqliteCorpus
from ..corpus.learning_import import import_ai_learning_data
from ..feedback import parse_fuzzer_stats
from ..grammar import Grammar, SeedSynthesis, VerificationGate
from ..recovery import StructureRecovery

PROTOCOL_VERSION = "2025-03-26"
MAX_STRINGS_HINTS = 50
MAX_COUNT = 1000  # 单次 generate_seeds 的批量上限


class MCPServer:
    """NDJSON stdio JSON-RPC 2.0 server（MCP 最小实现）。"""

    def __init__(self, corpus_path: str = "corpus.db"):
        self.corpus = SqliteCorpus(corpus_path)
        self._tools: dict[str, tuple[Callable, dict]] = {
            "register_grammar": (self._tool_register_grammar, {
                "description": "注册一个 Grammar 候选（LLM 综合的格式结构）。"
                               "schema 校验通过后入库, 供 generate_seeds 按名引用。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "spec": {"type": "object",
                                 "description": "Grammar.to_dict() 结构: "
                                                "{name, kind, fields:[{name,type,offset,size,"
                                                "endian,value,algorithm,over,length_of,default}]}"},
                    },
                    "required": ["spec"],
                },
            }),
            "generate_seeds": (self._tool_generate_seeds, {
                "description": "按已注册的 Grammar 合成结构化种子: content 定向覆盖 blob 字段, "
                               "length/checksum 自动重算, 全部过 VerificationGate, "
                               "通过者进入目标引擎的种子队列。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "grammar_name": {"type": "string"},
                        "target_id": {"type": "string",
                                      "description": "目标引擎 id（种子队列按此分发）"},
                        "count": {"type": "integer", "default": 5},
                        "content_hex": {"type": "string", "default": "",
                                        "description": "定向内容（hex）, 覆盖第一个 blob 字段"},
                    },
                    "required": ["grammar_name", "target_id"],
                },
            }),
            "recover_structure": (self._tool_recover_structure, {
                "description": "从二进制（解析器）提取结构事实: magic 字节定位 + 字符串格式提示。"
                               "返回确定性事实, 供 LLM 综合 Grammar 候选。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {"type": "string"},
                        "magic_hex": {"type": "string",
                                      "description": "待验证的 magic 字节序列（hex, 如 377abcaf271c）"},
                        "string_pattern": {"type": "string", "default": "",
                                           "description": "字符串过滤子串（可选）"},
                    },
                    "required": ["binary_path", "magic_hex"],
                },
            }),
            "sync_learning_data": (self._tool_sync_learning_data, {
                "description": "把 ai_learning_data/ 下的学习数据 JSON 归一化进 SQLite Corpus "
                               "（Session AI 与 enhanced engine 的运行时学习 → 平台统一查询）。"
                               "幂等: 重复导入同一文件不产生重复记录。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "data_dir": {"type": "string", "default": "ai_learning_data"},
                    },
                },
            }),
            "get_status": (self._tool_get_status, {
                "description": "平台快照: 语料计数、目标引擎待消费种子数、覆盖统计（若给 out_dir）。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_id": {"type": "string"},
                        "out_dir": {"type": "string", "default": "",
                                    "description": "引擎输出目录（含 fuzzer_stats 时解析覆盖）"},
                    },
                    "required": ["target_id"],
                },
            }),
        }

    # ---- stdio framing ----

    def run(self) -> None:
        """读 stdin 逐行 JSON-RPC，响应写 stdout。日志一律走 stderr。"""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._send(self._error(None, -32700, "parse error"))
                continue
            resp = self._dispatch(msg)
            if resp is not None:
                self._send(resp)

    def _send(self, obj: dict) -> None:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    # ---- dispatch ----

    def _dispatch(self, msg: dict) -> dict | None:
        method = msg.get("method", "")
        req_id = msg.get("id")

        if method == "initialize":
            return self._result(req_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fuzzcore-mcp", "version": "0.1.0"},
            })
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None
        if method == "ping":
            return self._result(req_id, {})
        if method == "tools/list":
            return self._result(req_id, {"tools": [
                {"name": name, "description": meta["description"],
                 "inputSchema": meta["inputSchema"]}
                for name, (_, meta) in self._tools.items()
            ]})
        if method == "tools/call":
            params = msg.get("params", {})
            return self._call_tool(req_id, params.get("name", ""),
                                   params.get("arguments", {}))
        if req_id is not None:
            return self._error(req_id, -32601, f"method not found: {method}")
        return None

    def _call_tool(self, req_id, name: str, arguments: dict) -> dict:
        entry = self._tools.get(name)
        if entry is None:
            return self._error(req_id, -32602, f"unknown tool: {name}")
        handler, _ = entry
        try:
            payload = handler(arguments)
            return self._result(req_id, {
                "content": [{"type": "text",
                             "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
                "isError": False,
            })
        except Exception as e:
            return self._result(req_id, {
                "content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}],
                "isError": True,
            })

    @staticmethod
    def _result(req_id, result: Any) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    @staticmethod
    def _error(req_id, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": req_id,
                "error": {"code": code, "message": message}}

    # ---- tools ----

    def _tool_register_grammar(self, args: dict) -> dict:
        spec = args.get("spec")
        if not isinstance(spec, dict):
            raise ValueError("spec must be a Grammar dict")
        grammar = Grammar.from_dict(spec)
        if not grammar.name.strip():
            raise ValueError("grammar.name must be non-empty")
        if not grammar.fields:
            raise ValueError("grammar must define at least one field")
        # 自检: 用 grammar 合成一个种子并验证, 不合法的 schema 在这里就被拦下
        probe = SeedSynthesis(grammar).generate()
        if not VerificationGate(grammar).validate(probe):
            raise ValueError("grammar 自检失败: 合成的探针种子未通过验证门")
        self.corpus.register_grammar(grammar)
        return {"registered": grammar.name, "kind": grammar.kind,
                "fields": len(grammar.fields),
                "grammars_total": len(self.corpus.list_grammars())}

    def _tool_generate_seeds(self, args: dict) -> dict:
        grammar = self.corpus.get_grammar(args["grammar_name"])
        if grammar is None:
            raise ValueError(f"grammar not registered: {args['grammar_name']}")
        count = max(1, min(int(args.get("count", 5)), MAX_COUNT))
        content_hex = args.get("content_hex", "")
        content = bytes.fromhex(content_hex) if content_hex else None
        target_id = args["target_id"]

        synthesis = SeedSynthesis(grammar)
        gate = VerificationGate(grammar)
        blob_field = next((f for f in grammar.fields if f.type == "blob"), None)
        overrides = ({blob_field.name: content}
                     if content is not None and blob_field is not None else None)

        accepted, rejected, shas = 0, 0, []
        seed = synthesis.generate(overrides)
        for _ in range(count):
            if gate.validate(seed):
                row_id = self.corpus.enqueue_seed(
                    target_id, seed,
                    {"src": "mcp", "grammar": grammar.name},
                )
                if row_id != -1:
                    accepted += 1  # UNIQUE 冲突时返回已有行 id（队列去重, 仍算入队成功）
                    import hashlib
                    shas.append(hashlib.sha256(seed).hexdigest()[:12])
                else:
                    rejected += 1
            else:
                rejected += 1
            seed = synthesis.mutate(seed, keep_structure=True)  # 保结构变异出新样本

        return {"accepted": accepted, "rejected": rejected,
                "shas": shas[:20], "queue_pending": self.corpus.queue_pending(target_id)}

    def _tool_recover_structure(self, args: dict) -> dict:
        recovery = StructureRecovery()
        facts = recovery.recover_magic(args["binary_path"], args["magic_hex"])
        pattern = args.get("string_pattern", "")
        strings = recovery.strings(args["binary_path"])
        if pattern:
            strings = [s for s in strings if pattern in s]
        facts["string_hints"] = strings[:MAX_STRINGS_HINTS]
        facts["string_hints_truncated"] = len(strings) > MAX_STRINGS_HINTS
        return facts

    def _tool_sync_learning_data(self, args: dict) -> dict:
        stats = import_ai_learning_data(self.corpus, args.get("data_dir", "ai_learning_data"))
        stats["learning_events_total"] = len(self.corpus.query_learning_events(limit=100000))
        return stats

    def _tool_get_status(self, args: dict) -> dict:
        target_id = args["target_id"]
        status = {
            "corpus_total": self.corpus.count(),
            "queue_pending": self.corpus.queue_pending(target_id),
            "grammars": self.corpus.list_grammars(),
        }
        out_dir = args.get("out_dir", "")
        if out_dir:
            import os
            stats_path = os.path.join(out_dir, "fuzzer_stats")
            if os.path.exists(stats_path):
                status["fuzzer_stats"] = parse_fuzzer_stats(stats_path)
        return status


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="fuzzcore MCP server (stdio)")
    parser.add_argument("--corpus", default="corpus.db", help="SQLite corpus 路径")
    args = parser.parse_args()
    MCPServer(args.corpus).run()


if __name__ == "__main__":
    main()
