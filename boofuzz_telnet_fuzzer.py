#!/usr/bin/env python3
"""
Telnet Protocol Fuzzer with Authentication Testing
基于boofuzz的Telnet协议模糊测试工具，集成符号执行和智能优化
"""

import sys
import time
import argparse
import struct
import fw_vendor  # vendored boofuzz path bootstrap
from boofuzz import *
from boofuzz.utils.enhanced_symbolic_execution import (
    generate_protocol_data,
    convert_to_bytes,
    save_ai_learning_data
)

def create_telnet_requests():
    """创建增强的Telnet请求模板"""
    
    
    print("Using AI to generate Telnet test data...")

    # 使用AI增强的协议数据生成
    try:
        symbolic_commands = generate_protocol_data('telnet', 'commands', 15, use_ai=True)
        symbolic_usernames = generate_protocol_data('telnet', 'usernames', 10, use_ai=True)
        symbolic_passwords = generate_protocol_data('telnet', 'passwords', 12, use_ai=True)

        print(f"AI generated {len(symbolic_commands)} Telnet command variants")
        print(f"AI generated {len(symbolic_usernames)} Telnet username variants")
        print(f"AI generated {len(symbolic_passwords)} Telnet password variants")

    except Exception as e:
        print(f"AI data generation failed, using base data: {e}")
        # 使用基础数据作为后备
        symbolic_commands = ["ls", "pwd", "whoami", "cat /etc/passwd", "ps aux", "netstat -an"]
        symbolic_passwords = ["password", "admin", "123456", "root", "telnet"]
        symbolic_usernames = ["admin", "root", "user", "guest", "telnet"]
    
    requests = []
    
    # 1. Telnet Login Sequence
    s_initialize("TELNET_LOGIN")
    
    # 使用符号执行数据
    s_group("username", values=symbolic_usernames)
    s_delim("\r\n")
    # 使用符号执行数据
    s_group("password", values=symbolic_passwords)
    s_delim("\r\n")
    
    
    requests.append(s_get("TELNET_LOGIN"))
    
    # 2. Telnet Command Execution
    s_initialize("TELNET_COMMAND")
    
    # 使用符号执行数据
    s_group("command", values=symbolic_commands)
    s_delim("\r\n")
    
    
    requests.append(s_get("TELNET_COMMAND"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description="Enhanced Telnet Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 23)", nargs='?', default=23)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26010, help="Web interface port")
    parser.add_argument("--username", default="admin", help="Telnet username")
    parser.add_argument("--password", default="password", help="Telnet password")
    args = parser.parse_args()
    
    print("Enhanced Telnet Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Username: {args.username}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("Dry run mode - testing request generation...")
        requests = create_telnet_requests()
        print(f"Successfully created {len(requests)} Telnet request templates")
        
        for i, req in enumerate(requests):
            print(f"\nRequest {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # Telnet是文本协议，可以直接显示
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
    
    # 创建Telnet请求
    requests = create_telnet_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(request)
    
    print("Starting Telnet protocol fuzzing...")
    print(f"Monitor: http://localhost:{args.web_port}")
    print("WARNING: this will perform potentially dangerous operations against the target Telnet server!")
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
    except Exception as e:
        print(f"\nError during fuzzing: {e}")
    finally:
        try:
            save_ai_learning_data("telnet")
        except Exception:
            pass
        print("Telnet fuzzing completed")

if __name__ == "__main__":
    main()