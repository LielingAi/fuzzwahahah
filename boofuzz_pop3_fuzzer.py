#!/usr/bin/env python3
"""
Enhanced POP3 Protocol Fuzzer with Symbolic Execution
基于boofuzz的POP3协议模糊测试工具，集成符号执行和智能优化
"""

import sys
import time
import argparse
import fw_vendor  # vendored boofuzz path bootstrap
from boofuzz import *
from boofuzz.utils.enhanced_symbolic_execution import (
    generate_protocol_data, 
    learn_from_test_result,
    save_ai_learning_data
)

def create_pop3_requests():
    """创建增强的POP3请求模板"""
    
    print("Using AI to generate POP3 test data...")
    
    # 使用AI增强的协议数据生成
    try:
        symbolic_commands = generate_protocol_data('pop3', 'commands', 15, use_ai=True)
        symbolic_usernames = generate_protocol_data('pop3', 'usernames', 12, use_ai=True)
        symbolic_passwords = generate_protocol_data('pop3', 'passwords', 10, use_ai=True)

        print(f"AI generated {len(symbolic_commands)} POP3 command variants")
        print(f"AI generated {len(symbolic_usernames)} username variants")
        print(f"AI generated {len(symbolic_passwords)} password variants")
        
    except Exception as e:
        print(f"AI data generation failed, using base data: {e}")
        # 使用基础数据作为后备
        symbolic_commands = ['USER', 'PASS', 'STAT', 'LIST', 'RETR', 'DELE', 'NOOP', 'RSET', 'QUIT', 'TOP', 'UIDL', 'CAPA', 'AUTH']
        symbolic_usernames = ['test', 'admin', 'user', 'root', 'postmaster']
        symbolic_passwords = ['password', '123456', 'admin123', 'testpass']

    requests = []
    
    # POP3是基于文本的协议，使用CRLF作为行结束符
    
    # 1. POP3 USER命令
    s_initialize("POP3_USER")
    s_string("USER ")
    usernames = [
        "test",
        "admin",
        "user",
        "root",
        "postmaster",
        "test@example.com"
    ] + symbolic_usernames[:8]
    s_group("username", values=usernames)
    s_delim("\r\n")
    requests.append(s_get("POP3_USER"))
    
    # 2. POP3 PASS命令
    s_initialize("POP3_PASS")
    s_string("PASS ")
    passwords = [
        "password",
        "123456",
        "admin123",
        "testpass",
        ""
    ] + symbolic_passwords[:8]
    s_group("password", values=passwords)
    s_delim("\r\n")
    requests.append(s_get("POP3_PASS"))
    
    # 3. POP3 STAT命令
    s_initialize("POP3_STAT")
    s_string("STAT\r\n")
    requests.append(s_get("POP3_STAT"))
    
    # 4. POP3 LIST命令
    s_initialize("POP3_LIST")
    s_string("LIST")
    s_delim(" ")
    # 可选的邮件编号
    message_numbers = ["", "1", "2", "100", "0", "-1", "999999"]
    s_group("msg_num", values=message_numbers)
    s_delim("\r\n")
    requests.append(s_get("POP3_LIST"))
    
    # 5. POP3 RETR命令
    s_initialize("POP3_RETR")
    s_string("RETR ")
    # 邮件编号
    retr_numbers = ["1", "2", "100", "0", "-1", "999999"]
    s_group("retr_num", values=retr_numbers)
    s_delim("\r\n")
    requests.append(s_get("POP3_RETR"))
    
    # 6. POP3 DELE命令
    s_initialize("POP3_DELE")
    s_string("DELE ")
    # 邮件编号
    dele_numbers = ["1", "2", "100", "0", "-1", "999999"]
    s_group("dele_num", values=dele_numbers)
    s_delim("\r\n")
    requests.append(s_get("POP3_DELE"))
    
    # 7. POP3 NOOP命令
    s_initialize("POP3_NOOP")
    s_string("NOOP\r\n")
    requests.append(s_get("POP3_NOOP"))
    
    # 8. POP3 RSET命令
    s_initialize("POP3_RSET")
    s_string("RSET\r\n")
    requests.append(s_get("POP3_RSET"))
    
    # 9. POP3 QUIT命令
    s_initialize("POP3_QUIT")
    s_string("QUIT\r\n")
    requests.append(s_get("POP3_QUIT"))
    
    # 10. POP3 TOP命令
    s_initialize("POP3_TOP")
    s_string("TOP ")
    # 邮件编号
    top_numbers = ["1", "2", "100", "0", "-1"]
    s_group("top_num", values=top_numbers)
    s_delim(" ")
    # 行数
    line_counts = ["0", "10", "100", "-1", "999999"]
    s_group("line_count", values=line_counts)
    s_delim("\r\n")
    requests.append(s_get("POP3_TOP"))
    
    # 11. POP3 UIDL命令
    s_initialize("POP3_UIDL")
    s_string("UIDL")
    s_delim(" ")
    # 可选的邮件编号
    uidl_numbers = ["", "1", "2", "100", "0", "-1"]
    s_group("uidl_num", values=uidl_numbers)
    s_delim("\r\n")
    requests.append(s_get("POP3_UIDL"))
    
    # 12. POP3 CAPA命令
    s_initialize("POP3_CAPA")
    s_string("CAPA\r\n")
    requests.append(s_get("POP3_CAPA"))
    
    # 13. POP3 AUTH命令
    s_initialize("POP3_AUTH")
    s_string("AUTH")
    s_delim(" ")
    # 认证机制
    auth_mechanisms = ["PLAIN", "LOGIN", "CRAM-MD5", "DIGEST-MD5", "APOP"]
    s_group("auth_mech", values=auth_mechanisms)
    s_delim("\r\n")
    requests.append(s_get("POP3_AUTH"))
    
    # 14. 恶意POP3命令 (缓冲区溢出测试)
    s_initialize("POP3_MALICIOUS")
    # 超长命令测试
    malicious_commands = [
        "USER " + "A" * 1000,
        "PASS " + "B" * 1000,
        "LIST " + "C" * 1000,
        "RETR " + "D" * 1000,
        "TOP 1 " + "E" * 1000
    ]
    s_group("malicious_command", values=malicious_commands)
    s_delim("\r\n")
    requests.append(s_get("POP3_MALICIOUS"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description="Enhanced POP3 Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 110)", nargs='?', default=110)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26009, help="Web interface port")
    parser.add_argument("--ssl", action="store_true", help="Use POP3S (SSL/TLS)")
    
    args = parser.parse_args()
    
    print("Enhanced POP3 Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"SSL: {'Yes' if args.ssl else 'No'}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("Dry run mode - testing request generation...")
        requests = create_pop3_requests()
        print(f"Successfully created {len(requests)} POP3 request templates")
        
        for i, req in enumerate(requests):
            print(f"\nRequest {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # POP3是文本协议，可以直接显示
                preview = rendered.decode('utf-8', errors='ignore')[:100]
                preview_clean = preview.replace(chr(13), '\\r').replace(chr(10), '\\n')
                print(f"   Preview: {preview_clean}...")
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
                proto="ssl" if args.ssl else "tcp",
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
    
    # 创建POP3请求
    requests = create_pop3_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(request)
    
    print("Starting POP3 protocol fuzzing...")
    print(f"Monitor: http://localhost:{args.web_port}")
    print("WARNING: this will perform potentially dangerous operations against the target POP3 server!")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
    except Exception as e:
        print(f"\nError during fuzzing: {e}")
    finally:
        try:
            save_ai_learning_data("pop3")
        except Exception:
            pass
        print("POP3 fuzzing completed")

if __name__ == "__main__":
    main()