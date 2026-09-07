#!/usr/bin/env python3
"""
HTTP/2 Protocol Fuzzer (boofuzz)

基于boofuzz的HTTP/2协议模糊测试工具。

按照 protocol_configs/http2_config.yaml 定义六个请求:
  - HTTP2_PREFACE      : 连接前导魔法字符串
  - HTTP2_SETTINGS     : SETTINGS 帧 (type=0x04)
  - HTTP2_HEADERS      : HEADERS 帧 (type=0x01, HPACK 简化编码)
  - HTTP2_DATA         : DATA 帧 (type=0x00)
  - HTTP2_WINDOW_UPDATE: WINDOW_UPDATE 帧 (type=0x08)
  - HTTP2_MALICIOUS    : 异常帧类型 + 大随机 payload

帧结构: size(3字节, 大端) + type(1) + flags(1) + stream_id(4, 大端) + payload

使用方法:
    python boofuzz_http2_fuzzer.py <target> [port] [--timeout 5] [--dry-run] [--web-port 26011]

示例:
    python boofuzz_http2_fuzzer.py 127.0.0.1 --dry-run
    python boofuzz_http2_fuzzer.py 127.0.0.1 8443
"""

import sys
import os
import argparse

# 添加当前目录到Python路径以便导入boofuzz
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 标准boofuzz导入
import fw_vendor  # vendored boofuzz path bootstrap
from boofuzz import *


def create_http2_requests():
    """创建HTTP/2请求模板，返回请求列表。"""
    requests = []

    # 1. HTTP/2 Connection Preface
    s_initialize("HTTP2_PREFACE")
    s_static("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    requests.append(s_get("HTTP2_PREFACE"))

    # 2. HTTP/2 SETTINGS Frame
    s_initialize("HTTP2_SETTINGS")
    s_size("settings_payload", length=3, endian=">", name="frame_length")
    s_byte(0x04, name="frame_type")
    s_byte(0x00, name="flags")
    s_dword(0x00000000, endian=">", name="stream_id")
    s_block_start("settings_payload")
    s_word(0x0001, endian=">", name="header_table_size_id")
    s_dword(4096, endian=">", name="header_table_size_value")
    s_word(0x0002, endian=">", name="enable_push_id")
    s_dword(1, endian=">", name="enable_push_value")
    s_block_end("settings_payload")
    requests.append(s_get("HTTP2_SETTINGS"))

    # 3. HTTP/2 HEADERS Frame
    s_initialize("HTTP2_HEADERS")
    s_size("headers_payload", length=3, endian=">", name="frame_length")
    s_byte(0x01, name="frame_type")
    s_byte(0x05, name="flags")
    s_dword(0x00000001, endian=">", name="stream_id")
    s_block_start("headers_payload")
    s_group("method", values=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"])
    s_delim(" ")
    s_group("path", values=["/", "/index.html", "/admin", "/api/v1/users", "/../../etc/passwd"])
    s_delim(" HTTP/2\r\n")
    s_string("Host: example.com\r\n")
    s_group("user_agent", values=["Mozilla/5.0", "curl/7.68.0", "Malicious/1.0"])
    s_delim("\r\n\r\n")
    s_block_end("headers_payload")
    requests.append(s_get("HTTP2_HEADERS"))

    # 4. HTTP/2 DATA Frame
    s_initialize("HTTP2_DATA")
    s_size("data_payload", length=3, endian=">", name="frame_length")
    s_byte(0x00, name="frame_type")
    s_byte(0x01, name="flags")
    s_dword(0x00000001, endian=">", name="stream_id")
    s_block_start("data_payload")
    s_group("post_data", values=["hello world", "A" * 100, "fuzzdata\x00\x01\x02payload"])
    s_block_end("data_payload")
    requests.append(s_get("HTTP2_DATA"))

    # 5. HTTP/2 WINDOW_UPDATE Frame
    s_initialize("HTTP2_WINDOW_UPDATE")
    s_size("window_payload", length=3, endian=">", name="frame_length")
    s_byte(0x08, name="frame_type")
    s_byte(0x00, name="flags")
    s_dword(0x00000000, endian=">", name="stream_id")
    s_block_start("window_payload")
    # 4字节大端 window_size_increment 值
    s_group("window_size_increment", values=[
        b"\x00\x00\x04\x00",    # 1024
        b"\x00\x01\x00\x00",    # 65536
        b"\x7f\xff\xff\xff",    # 0x7FFFFFFF
        b"\x80\x00\x00\x00",    # 0x80000000
    ])
    s_block_end("window_payload")
    requests.append(s_get("HTTP2_WINDOW_UPDATE"))

    # 6. HTTP/2 Malicious Frame
    s_initialize("HTTP2_MALICIOUS")
    s_size("malicious_payload", length=3, endian=">", name="frame_length")
    # 异常帧类型值: 0xFF, 0x100, 0x200
    s_group("malicious_frame_type", values=[b"\xff", b"\x01\x00", b"\x02\x00"])
    s_byte(0xFF, name="flags")
    s_dword(0xFFFFFFFF, endian=">", name="stream_id")
    s_block_start("malicious_payload")
    s_random("", min_length=100, max_length=10000, num_mutations=20, name="random_data")
    s_block_end("malicious_payload")
    requests.append(s_get("HTTP2_MALICIOUS"))

    return requests


def main():
    """主函数 - 标准boofuzz模式。"""
    parser = argparse.ArgumentParser(description="boofuzz HTTP/2 Protocol Fuzzer")
    parser.add_argument("target", help="目标HTTP/2服务器IP")
    parser.add_argument("port", nargs='?', type=int, default=443,
                        help="目标端口 (默认: 443)")
    parser.add_argument("--timeout", type=int, default=5, help="连接超时时间 (默认: 5)")
    parser.add_argument("--dry-run", action="store_true",
                        help="仅渲染请求模板，不连接目标")
    parser.add_argument("--web-port", type=int, default=26011,
                        help="Web界面端口 (默认: 26011)")

    args = parser.parse_args()

    print("boofuzz HTTP/2 Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Transport: SSL/TLS")
    print(f"Timeout: {args.timeout}s")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()

    # 创建HTTP/2请求模板
    requests = create_http2_requests()
    print(f"创建了 {len(requests)} 个HTTP/2请求模板")

    if args.dry_run:
        print("\nDry run mode - testing request generation...")
        for i, req in enumerate(requests):
            print(f"\nRequest {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # HTTP/2协议是二进制的，显示十六进制
                hex_preview = rendered[:50].hex()
                print(f"   Hex Preview: {hex_preview}")
                text_preview = rendered[:50].decode('latin-1', errors='replace')
                print(f"   Text Preview: {text_preview}")
            except Exception as e:
                print(f"   Error: {e}")
        print("\nDry run completed successfully!")
        return

    # 创建会话
    try:
        session = Session(
            target=Target(
                connection=SocketConnection(
                    host=args.target,
                    port=args.port,
                    proto="ssl",
                    send_timeout=args.timeout,
                    recv_timeout=args.timeout,
                )
            ),
            web_port=args.web_port,
            check_data_received_each_request=False,
        )

        # 添加请求到会话
        for request in requests:
            session.connect(request)

        print(f"\n开始HTTP/2协议模糊测试...")
        print(f"监控界面: http://localhost:{args.web_port}")
        print("WARNING: 警告: 这将对目标HTTP/2服务器执行潜在危险的操作!")
        print("\n按 Ctrl+C 停止FUZZ")

        session.fuzz()
    except KeyboardInterrupt:
        print("\n⏹️  用户中断测试")
    except Exception as e:
        print(f"\nError: 测试过程中出现错误: {e}")
        print("请确保目标HTTP/2服务器正在运行且可访问")

    print("🏁 HTTP/2模糊测试完成")


if __name__ == "__main__":
    main()
