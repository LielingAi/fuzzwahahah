#!/usr/bin/env python3
"""phase3_demo.py - Phase 3 演示：boofuzz 通过统一 Engine 接口运行多协议 fuzz。

用一个通用 profile（generic_profile.py）+ 协议模板，跑多个协议，
证明 boofuzz 已降级为"一个 Engine 实现"，多协议走同一接口。
"""
from __future__ import annotations

import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fuzzcore.engine import ProtocolEngine, Target, TargetKind

GENERIC_PROFILE = str(PROJECT_ROOT / "fuzzcore" / "profiles" / "generic_profile.py")


class EchoServer:
    def __init__(self, port: int = 9777):
        self.port = port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def _serve(self):
        self._sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    def _echo(self, conn):
        try:
            conn.settimeout(2)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self):
        self._stop.set()
        self._sock.close()


def run_protocol(engine, proto: str, port: int) -> int:
    target = Target(TargetKind.SERVICE, f"{proto} 127.0.0.1 {port}")
    out_dir = tempfile.mkdtemp(prefix=f"{proto}_out_")
    handle = engine.start(target, seed_dir="", out_dir=out_dir, max_cases=30)
    try:
        handle.process.wait(timeout=40)
    except Exception:
        engine.stop(handle)
    status = engine.status(handle)
    engine.stop(handle)
    return status.coverage.total_paths


def main() -> int:
    server = EchoServer(9777)
    server.start()
    time.sleep(0.3)

    engine = ProtocolEngine(GENERIC_PROFILE)
    protocols = ["echo", "http", "ftp"]
    for proto in protocols:
        n = run_protocol(engine, proto, 9777)
        print(f"[{proto}] test_cases={n}")

    server.stop()
    print("[done] Phase 3 演示完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
