"""mcp_demo.py - fuzzcore MCP server 端到端验证（spawn + 5 工具全链路）。

用法: python fuzzcore/mcp_demo.py
验证: initialize → tools/list → register_grammar → generate_seeds →
      recover_structure → sync_learning_data → get_status
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

CORPUS = PROJECT_ROOT / "mcp_demo.db"
MAGIC = "377abcaf271c"  # 7z 签名（Phase 5 验证目标）


def _rpc(proc, method, params=None, _id=[0]):
    _id[0] += 1
    msg = {"jsonrpc": "2.0", "id": _id[0], "method": method}
    if params is not None:
        msg["params"] = params
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def _call(proc, name, arguments):
    resp = _rpc(proc, "tools/call", {"name": name, "arguments": arguments})
    result = resp.get("result", {})
    text = result.get("content", [{}])[0].get("text", "")
    if result.get("isError"):
        raise RuntimeError(f"tool {name} failed: {text}")
    return json.loads(text)


def main() -> int:
    proc = subprocess.Popen(
        [sys.executable, "-m", "fuzzcore.mcp.server", "--corpus", str(CORPUS)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8", cwd=str(PROJECT_ROOT),
    )
    try:
        r = _rpc(proc, "initialize", {"protocolVersion": "2025-03-26",
                                      "capabilities": {},
                                      "clientInfo": {"name": "mcp_demo", "version": "0"}})
        print(f"[init] {r['result']['serverInfo']}")

        tools = [t["name"] for t in _rpc(proc, "tools/list")["result"]["tools"]]
        print(f"[tools] {tools}")

        out = _call(proc, "register_grammar", {"spec": {
            "name": "demo_crc32", "kind": "binary_file",
            "fields": [
                {"name": "crc", "type": "checksum", "offset": 0, "size": 4,
                 "endian": "little", "algorithm": "crc32", "over": ["props", "payload"]},
                {"name": "props", "type": "raw", "offset": 4, "size": 5,
                 "default": "5d00008000"},
                {"name": "payload", "type": "blob", "offset": 9},
            ]}})
        print(f"[register_grammar] {out}")

        out = _call(proc, "generate_seeds", {
            "grammar_name": "demo_crc32", "target_id": "demo", "count": 5,
            "content_hex": "4142434445464748"})
        print(f"[generate_seeds] accepted={out['accepted']} rejected={out['rejected']} "
              f"queue={out['queue_pending']}")
        assert out["accepted"] == 5

        seven_z = Path(r"D:\7-Zip\7z.dll")
        if seven_z.exists():
            out = _call(proc, "recover_structure", {
                "binary_path": str(seven_z), "magic_hex": MAGIC,
                "string_pattern": "7z"})
            print(f"[recover_structure] magic found={out['found']} "
                  f"offsets={len(out['offsets'])} hints={len(out['string_hints'])}")
            assert out["found"]
        else:
            print("[recover_structure] 7z.dll not present, skipped")

        out = _call(proc, "sync_learning_data", {})
        print(f"[sync_learning_data] imported={out['imported']} skipped={out['skipped']}")

        out = _call(proc, "get_status", {"target_id": "demo"})
        print(f"[get_status] {out}")
        assert "demo_crc32" in out["grammars"]

        print("MCP DEMO OK")
        return 0
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        CORPUS.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
