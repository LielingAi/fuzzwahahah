"""echo_profile.py - minimal boofuzz profile（Echo 协议）。

约定：python echo_profile.py <host> <port> [--timeout N] [--max-cases N]
作为 ProtocolEngine 的子进程运行，进度以 "CASE n" 打到 stdout，
崩溃以 "CRASH" 标记，供 Engine 解析。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# 让 profile 独立可运行：把项目根加入 sys.path 以导入 vendored boofuzz
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from boofuzz import (
    IFuzzLogger,
    Session,
    SocketConnection,
    Target,
    s_delim,
    s_get,
    s_group,
    s_initialize,
)


class ProgressLogger(IFuzzLogger):
    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        print(f"CASE {index}", flush=True)

    def open_test_step(self, description):
        pass

    def log_send(self, data):
        pass

    def log_recv(self, data):
        pass

    def log_check(self, description):
        pass

    def log_pass(self, description=""):
        pass

    def log_fail(self, description=""):
        print("CRASH", flush=True)

    def log_info(self, description):
        pass

    def log_error(self, description):
        print("CRASH", flush=True)

    def close_test_case(self):
        pass

    def close_test(self):
        pass


def build_requests():
    s_initialize("ECHO")
    s_group("msg", values=["Hello", "Test", b"A" * 100, b"\x00\x01\x02\x03", "Hello World!"])
    s_delim("\n")
    return [s_get("ECHO")]


def main():
    parser = argparse.ArgumentParser(description="boofuzz Echo profile")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--max-cases", type=int, default=0)
    args = parser.parse_args()

    requests = build_requests()
    session = Session(
        target=Target(connection=SocketConnection(args.host, args.port, proto="tcp",
                                                   send_timeout=args.timeout, recv_timeout=args.timeout)),
        fuzz_loggers=[ProgressLogger()],
        index_start=1,
        index_end=args.max_cases if args.max_cases else None,
        web_port=None,
        check_data_received_each_request=False,
        receive_data_after_each_request=False,
        receive_data_after_fuzz=False,
    )
    for r in requests:
        session.connect(r)
    session.fuzz()


if __name__ == "__main__":
    main()
