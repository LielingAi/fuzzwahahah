"""ACP client — 驱动 Kimi Code 的 agent 会话（JSON-RPC over stdio, NDJSON framing）。

协议要点（kimi acp 子进程）：
- 每行一个 JSON 对象（NDJSON），请求带 id，响应按 id 路由
- agent → client 通知：session/update（agent_message_chunk / tool_call* / plan）
- agent → client 反向请求：session/request_permission、fs/*、terminal/*
- 本 client 对 request_permission 自动批准（编排场景是无人值守的自动化）；
  fs/terminal 反向请求回 methodNotFound（工具调用由 agent 自己的进程内工具执行）

线程模型：一个 reader 线程持续读 stdout 分发消息；request() 同步等待响应。
"""
from __future__ import annotations

import json
import subprocess
import threading
from typing import Callable, Optional


class ACPError(Exception):
    pass


class ACPClient:
    """kimi acp 的最小同步客户端。"""

    def __init__(self, kimi_cmd: str = "kimi", cwd: Optional[str] = None):
        self._kimi_cmd = kimi_cmd
        self._cwd = cwd
        self._proc: Optional[subprocess.Popen] = None
        self._next_id = 0
        self._pending: dict[int, dict] = {}
        self._pending_cv = threading.Condition()
        self._update_listeners: list[Callable] = []
        self._reader: Optional[threading.Thread] = None
        self.agent_info: dict = {}

    # ---- 生命周期 ----

    def start(self) -> None:
        self._proc = subprocess.Popen(
            [self._kimi_cmd, "acp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace",
            cwd=self._cwd, bufsize=1,
        )
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        result = self._request("initialize", {
            "protocolVersion": 1,
            "clientInfo": {"name": "fuzzwahahah-llm-agent", "version": "0.1.0"},
            "clientCapabilities": {"fs": {"readTextFile": True, "writeTextFile": True}},
        })
        self.agent_info = result.get("agentInfo", {})

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    # ---- 会话 ----

    def new_session(self, cwd: str, mcp_servers: Optional[dict] = None) -> str:
        params: dict = {"cwd": cwd, "mcpServers": []}
        if mcp_servers:
            params["mcpServers"] = mcp_servers
        result = self._request("session/new", params)
        return result["sessionId"]

    def close_session(self, session_id: str) -> None:
        self._request("session/close", {"sessionId": session_id})

    # ---- prompt ----

    def prompt(self, session_id: str, text: str,
               on_update: Optional[Callable] = None,
               timeout: float = 300.0) -> dict:
        """发一个 prompt, 流式更新经 on_update(update: dict) 回调, 返回 stop_reason。"""
        listener_id = len(self._update_listeners)
        if on_update:
            def _filter(update: dict):
                if update.get("sessionId") == session_id:
                    on_update(update.get("update", {}))
            self._update_listeners.append(_filter)
        try:
            return self._request("session/prompt", {
                "sessionId": session_id,
                "prompt": [{"type": "text", "text": text}],
            }, timeout=timeout)
        finally:
            if on_update:
                self._update_listeners.pop(listener_id)

    def cancel(self, session_id: str) -> None:
        self._notify("session/cancel", {"sessionId": session_id})

    # ---- 底层 ----

    def _request(self, method: str, params: dict, timeout: float = 60.0) -> dict:
        self._next_id += 1
        req_id = self._next_id
        with self._pending_cv:
            self._pending[req_id] = {}
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        with self._pending_cv:
            got = self._pending_cv.wait_for(
                lambda: bool(self._pending.get(req_id)), timeout=timeout)
            response = self._pending.pop(req_id, {})
        if not got:
            raise ACPError(f"timeout waiting for {method} (id={req_id})")
        if "error" in response:
            raise ACPError(f"{method} failed: {response['error']}")
        return response.get("result", {})

    def _notify(self, method: str, params: dict) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _send(self, obj: dict) -> None:
        assert self._proc and self._proc.stdin
        self._proc.stdin.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self._proc.stdin.flush()

    def _read_loop(self) -> None:
        assert self._proc and self._proc.stdout
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            self._handle(msg)

    def _handle(self, msg: dict) -> None:
        method = msg.get("method", "")
        # 响应（带 id 无 method）
        if "id" in msg and not method:
            with self._pending_cv:
                if msg["id"] in self._pending:
                    self._pending[msg["id"]] = msg
                    self._pending_cv.notify_all()
            return
        # agent → client 通知
        if method == "session/update":
            for fn in self._update_listeners:
                try:
                    fn(msg.get("params", {}))
                except Exception:
                    pass
            return
        # agent → client 反向请求：权限自动批准（无人值守编排）
        if method == "session/request_permission" and "id" in msg:
            options = msg.get("params", {}).get("options", [])
            allow = next((o for o in options
                          if o.get("kind", "").startswith("allow")), None)
            option_id = allow["optionId"] if allow else (options[0]["optionId"] if options else "")
            self._send({"jsonrpc": "2.0", "id": msg["id"],
                        "result": {"outcome": {"outcome": "selected",
                                               "optionId": option_id}}})
            return
        # 其他反向请求（fs/terminal/elicitation）：不支持
        if method and "id" in msg:
            self._send({"jsonrpc": "2.0", "id": msg["id"],
                        "error": {"code": -32601, "message": f"method not found: {method}"}})
