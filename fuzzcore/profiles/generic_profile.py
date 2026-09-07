"""generic_profile.py - 通用 boofuzz profile：按协议模板自动生成请求。

用法：python generic_profile.py <protocol> <host> <port> [--timeout N] [--max-cases N]
从 protocol_templates/<protocol>.json 读取数据，为每个键生成一个 s_group 请求。
一个 profile 覆盖全部协议模板（16 个）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

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

TEMPLATES_DIR = PROJECT_ROOT / "protocol_templates"


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


def _ascii_safe(s: str) -> bool:
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def build_requests(protocol: str):
    tmpl = TEMPLATES_DIR / f"{protocol}.json"
    data = json.loads(tmpl.read_text(encoding="utf-8"))
    requests = []
    for key, values in data.items():
        if not isinstance(values, list):
            continue
        # boofuzz 字符串原语当前只支持 ASCII，过滤非 ASCII 值，限值避免爆炸
        values = [v for v in values if isinstance(v, str) and _ascii_safe(v)][:20]
        if not values:
            continue
        name = f"{protocol.upper()}_{key}"
        s_initialize(name)
        s_group(key, values=values)
        s_delim("\n")
        requests.append(s_get(name))
    return requests


def main():
    parser = argparse.ArgumentParser(description="generic boofuzz profile")
    parser.add_argument("protocol")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--max-cases", type=int, default=0)
    args = parser.parse_args()

    requests = build_requests(args.protocol)
    if not requests:
        print(f"no data for protocol {args.protocol}", flush=True)
        return

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
