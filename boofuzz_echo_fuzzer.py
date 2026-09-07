#!/usr/bin/env python3
"""
Simple Echo Protocol Fuzzer for Testing
基于boofuzz的Echo协议模糊测试工具，集成符号执行和智能优化
"""

import sys
import time
import argparse
import fw_vendor  # vendored boofuzz path bootstrap
from boofuzz import *
from boofuzz.utils.enhanced_symbolic_execution import (
    generate_protocol_data,
    convert_to_bytes,
    save_ai_learning_data
)

def create_echo_requests():
    """创建增强的Echo请求模板"""
    
    
    print("Using AI to generate Echo test data...")

    # 使用AI增强的协议数据生成
    try:
        test_messages = generate_protocol_data('echo', 'messages', 15, use_ai=True)
        test_data = generate_protocol_data('echo', 'data', 10, use_ai=True)
        test_patterns = generate_protocol_data('echo', 'patterns', 8, use_ai=True)

        # 合并所有测试数据
        all_test_data = test_messages + test_data + test_patterns

        print(f"AI generated {len(test_messages)} Echo message variants")
        print(f"AI generated {len(test_data)} Echo data variants")
        print(f"AI generated {len(test_patterns)} Echo pattern variants")

    except Exception as e:
        print(f"AI data generation failed, using base data: {e}")
        # 使用基础数据作为后备
        all_test_data = ["Hello", "Test", "Echo", "Hello World!", "123456", "Test Message"]
    
    requests = []
    
    # 1. Echo Simple Message
    s_initialize("ECHO_SIMPLE")
    
    # 使用AI增强的测试数据
    s_group("message", values=all_test_data)
    s_delim("\n")
    
    
    requests.append(s_get("ECHO_SIMPLE"))
    
    # 2. Echo Binary Data
    s_initialize("ECHO_BINARY")
    
    s_random("binary_data", min_length=10, max_length=100)
    s_delim("\n")
    
    
    requests.append(s_get("ECHO_BINARY"))
    
    # 3. Echo Overflow Test
    s_initialize("ECHO_OVERFLOW")
    
    # 静态数据组
    overflow_data_data = ["A", "AA", "AAA"]
    s_group("overflow_data", values=overflow_data_data)
    s_delim("\n")
    
    
    requests.append(s_get("ECHO_OVERFLOW"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description="Enhanced Echo Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 7)", nargs='?', default=7)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26012, help="Web interface port")
    args = parser.parse_args()
    
    print("Enhanced Echo Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("Dry run mode - testing request generation...")
        requests = create_echo_requests()
        print(f"Successfully created {len(requests)} Echo request templates")
        
        for i, req in enumerate(requests):
            print(f"\nRequest {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # Echo是文本协议，可以直接显示
                preview = rendered.decode('utf-8', errors='ignore')[:100]
                print(f"   Preview: {preview}...")
            except Exception as e:
                print(f"   Error: {e}")
        
        print("\nDry run completed successfully!")
        return
    
    # 创建会话
    session = Session(
        target=Target(
            connection=SocketConnection(
                host=args.target,
                port=args.port,
                proto="tcp",
                send_timeout=args.timeout, recv_timeout=args.timeout
            )
    
        ),
        web_port=args.web_port,
        check_data_received_each_request=False
    )
    
    # 启用AI自适应策略
    session.ai_strategy_enabled = True
    session.ai_decision_threshold = 0.15
    session.ai_adaptation_interval = 50
    
    print("AI adaptive strategy enabled")
    
    # 创建Echo请求
    requests = create_echo_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(request)
    
    print("Starting Echo protocol fuzzing...")
    print(f"Monitor: http://localhost:{args.web_port}")
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
    except Exception as e:
        print(f"\nError during fuzzing: {e}")
    finally:
        try:
            save_ai_learning_data("echo")
        except Exception:
            pass
        print("Echo fuzzing completed")

if __name__ == "__main__":
    main()