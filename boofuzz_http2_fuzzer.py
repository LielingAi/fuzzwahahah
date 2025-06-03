#!/usr/bin/env python3
"""
HTTP/2 Protocol Fuzzer with Advanced Frame Testing
基于boofuzz的HTTP2协议模糊测试工具，集成符号执行和智能优化
"""

import sys
import time
import argparse
import struct
import base64
from boofuzz import *
from boofuzz.utils.enhanced_symbolic_execution import generate_protocol_data, convert_to_bytes

def create_http2_requests():
    """创建增强的HTTP2请求模板"""
    
    print("🧠 生成HTTP2符号执行数据...")
    
    # 使用增强的符号执行框架生成测试数据
    symbolic_methods = generate_protocol_data('http2', 'methods', 8)
    symbolic_paths = generate_protocol_data('http2', 'paths', 15)
    symbolic_headers = generate_protocol_data('http2', 'headers', 12)
    symbolic_values = generate_protocol_data('http2', 'values', 20)
    
    
    print(f"✅ 准备了符号执行测试数据")
    
    requests = []
    
    # 1. HTTP/2 Connection Preface
    s_initialize("HTTP2_PREFACE")
    
    s_string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    
    
    requests.append(s_get("HTTP2_PREFACE"))
    
    # 2. HTTP/2 SETTINGS Frame
    s_initialize("HTTP2_SETTINGS")
    
    s_size(, name="frame_length", endian=">")
    s_byte(4, name="frame_type")
    s_byte(0, name="flags")
    s_dword(0, name="stream_id", endian=">")
    s_block_start("settings_payload")
    s_word(1, name="header_table_size_id", endian=">")
    s_dword(4096, name="header_table_size_value", endian=">")
    s_word(2, name="enable_push_id", endian=">")
    s_dword(1, name="enable_push_value", endian=">")
    s_block_end("settings_payload")
    
    
    requests.append(s_get("HTTP2_SETTINGS"))
    
    # 3. HTTP/2 HEADERS Frame
    s_initialize("HTTP2_HEADERS")
    
    s_size("headers_payload", length=3, endian=">")
    s_byte(1, name="frame_type")
    s_byte(5, name="flags")
    s_dword(1, name="stream_id", endian=">")
    s_block_start("headers_payload")
    # 使用符号执行数据
    method_bytes = [convert_to_bytes(item, 'auto') for item in symbolic_methods]
    s_group("method", values=method_bytes)
    s_delim(" ")
    # 使用符号执行数据
    path_bytes = [convert_to_bytes(item, 'auto') for item in symbolic_paths]
    s_group("path", values=path_bytes)
    s_delim(" HTTP/2\r\n")
    s_string("Host: example.com\r\n")
    # 静态数据组
    user_agent_data = <built-in method values of dict object at 0x70f33b2a0880>
    s_group("user_agent", values=user_agent_data)
    s_delim("\r\n\r\n")
    s_block_end("headers_payload")
    
    
    requests.append(s_get("HTTP2_HEADERS"))
    
    # 4. HTTP/2 DATA Frame
    s_initialize("HTTP2_DATA")
    
    s_size("data_payload", length=3, endian=">")
    s_byte(0, name="frame_type")
    s_byte(1, name="flags")
    s_dword(1, name="stream_id", endian=">")
    s_block_start("data_payload")
    # 使用符号执行数据
    post_data_bytes = [convert_to_bytes(item, 'auto') for item in symbolic_values]
    s_group("post_data", values=post_data_bytes)
    s_block_end("data_payload")
    
    
    requests.append(s_get("HTTP2_DATA"))
    
    # 5. HTTP/2 WINDOW_UPDATE Frame
    s_initialize("HTTP2_WINDOW_UPDATE")
    
    s_size(, name="frame_length", endian=">")
    s_byte(8, name="frame_type")
    s_byte(0, name="flags")
    s_dword(0, name="stream_id", endian=">")
    s_block_start("window_payload")
    # 静态数据组
    window_size_increment_data = <built-in method values of dict object at 0x70f33b2a0cc0>
    s_group("window_size_increment", values=window_size_increment_data)
    s_block_end("window_payload")
    
    
    requests.append(s_get("HTTP2_WINDOW_UPDATE"))
    
    # 6. HTTP/2 Malicious Frame
    s_initialize("HTTP2_MALICIOUS")
    
    s_size(, name="frame_length", endian=">")
    # 静态数据组
    malicious_frame_type_data = <built-in method values of dict object at 0x70f33b2a0d80>
    s_group("malicious_frame_type", values=malicious_frame_type_data)
    s_byte(255, name="flags")
    s_dword(4294967295, name="stream_id", endian=">")
    s_block_start("malicious_payload")
    s_random("random_data", min_length=100, max_length=10000)
    s_block_end("malicious_payload")
    
    
    requests.append(s_get("HTTP2_MALICIOUS"))
    
    return requests

def encode_hpack():
    """HPACK header compression encoder"""
    def encode_header(name, value):
    # 简化的HPACK编码
    return f"{len(name)}:{name}:{len(value)}:{value}".encode()


def main():
    parser = argparse.ArgumentParser(description="Enhanced HTTP2 Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 443)", nargs='?', default=443)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26011, help="Web interface port")
    parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS")
    args = parser.parse_args()
    
    print("🚀 Enhanced HTTP2 Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"SSL: {'Yes' if args.ssl else 'No'}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("🧪 Dry run mode - testing request generation...")
        requests = create_http2_requests()
        print(f"✅ Successfully created {len(requests)} HTTP2 request templates")
        
        for i, req in enumerate(requests):
            print(f"\n📋 Request {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # HTTP2协议是二进制的，显示十六进制
                hex_preview = rendered[:50].hex()
                print(f"   Hex Preview: {hex_preview}...")
                except Exception as e:
                print(f"   Error: {e}")
        
        print("\n✅ Dry run completed successfully!")
        return
    
    # 创建会话
    session = Session(
        target=Target(
            connection=SocketConnection(
                host=args.target,
                port=args.port,
                proto="ssl",
                timeout=args.timeout
            )
        ),
        web_port=args.web_port,
        check_data_received_each_request=False
    )
    
    # 创建HTTP2请求
    requests = create_http2_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(s_get("target"), request)
    
    print(f"🚀 开始HTTP2协议模糊测试...")
    print(f"📊 监控界面: http://localhost:{args.web_port}")
    print("⚠️  警告: 这将对目标HTTP2服务器执行潜在危险的操作!")
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\n⏹️  用户中断测试")
    except Exception as e:
        print(f"\n❌ 测试过程中出现错误: {e}")
    finally:
        print("🏁 HTTP2模糊测试完成")

if __name__ == "__main__":
    main()