#!/usr/bin/env python3
"""
Enhanced SMTP Protocol Fuzzer with Symbolic Execution
基于boofuzz的SMTP协议模糊测试工具，集成符号执行和智能优化
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

def create_smtp_requests():
    """创建增强的SMTP请求模板"""
    
    
    print("Using AI to generate SMTP test data...")
    
    # 使用AI增强的协议数据生成
    try:
        symbolic_commands = generate_protocol_data('smtp', 'commands', 15, use_ai=True)
        symbolic_emails = generate_protocol_data('smtp', 'emails', 12, use_ai=True)
        symbolic_subjects = generate_protocol_data('smtp', 'subjects', 10, use_ai=True)
        symbolic_bodies = generate_protocol_data('smtp', 'bodies', 8, use_ai=True)

        print(f"AI generated {len(symbolic_commands)} SMTP command variants")
        print(f"AI generated {len(symbolic_emails)} email address variants")
        print(f"AI generated {len(symbolic_subjects)} email subject variants")
        print(f"AI generated {len(symbolic_bodies)} email body variants")
        
    except Exception as e:
        print(f"AI data generation failed, using base data: {e}")
        # 使用基础数据作为后备
        symbolic_commands = ['HELO', 'EHLO', 'MAIL FROM', 'RCPT TO', 'DATA', 'QUIT']
        symbolic_emails = ['test@example.com', 'admin@localhost', 'user@test.local']
        symbolic_subjects = ['Test Subject', 'Important Notice', 'System Alert']
        symbolic_bodies = ['Test message body', 'Hello World!', 'System notification']
    
    requests = []
    
    # SMTP是基于文本的协议，使用CRLF作为行结束符
    
    # 1. SMTP HELO/EHLO命令
    s_initialize("SMTP_HELO")
    
    # HELO/EHLO命令
    helo_commands = ["HELO", "EHLO"]
    s_group("helo_cmd", values=helo_commands)
    s_delim(" ")
    
    # 主机名
    hostnames = [
        "client.example.com",
        "localhost",
        "test.local",
        "[192.168.1.100]"  # IP地址格式
    ] + symbolic_emails[:5]  # 使用邮件地址作为主机名测试
    
    s_group("hostname", values=hostnames)
    s_delim("\r\n")
    
    requests.append(s_get("SMTP_HELO"))
    
    # 2. SMTP MAIL FROM命令
    s_initialize("SMTP_MAIL_FROM")
    
    s_string("MAIL FROM:")
    
    # 发件人地址
    sender_addresses = [
        "<test@example.com>",
        "<admin@localhost>",
        "<user@test.local>",
        "<>",  # 空发件人
        "<postmaster>"  # 无域名
    ] + [f"<{email}>" for email in symbolic_emails[:10]]
    
    s_group("sender", values=sender_addresses)
    
    # SMTP扩展参数
    mail_params = [
        "",
        " SIZE=1000",
        " BODY=8BITMIME",
        " AUTH=user@example.com",
        " RET=FULL",
        " ENVID=12345"
    ]
    s_group("mail_params", values=mail_params)
    
    s_delim("\r\n")
    
    requests.append(s_get("SMTP_MAIL_FROM"))
    
    # 3. SMTP RCPT TO命令
    s_initialize("SMTP_RCPT_TO")
    
    s_string("RCPT TO:")
    
    # 收件人地址
    recipient_addresses = [
        "<user@example.com>",
        "<admin@localhost>",
        "<test@test.local>",
        "<root>",  # 本地用户
        "<user+tag@example.com>"  # 带标签的地址
    ] + [f"<{email}>" for email in symbolic_emails[:10]]
    
    s_group("recipient", values=recipient_addresses)
    
    # RCPT TO扩展参数
    rcpt_params = [
        "",
        " NOTIFY=SUCCESS,FAILURE,DELAY",
        " ORCPT=rfc822;user@example.com"
    ]
    s_group("rcpt_params", values=rcpt_params)
    
    s_delim("\r\n")
    
    requests.append(s_get("SMTP_RCPT_TO"))
    
    # 4. SMTP DATA命令和邮件内容
    s_initialize("SMTP_DATA")
    
    s_string("DATA\r\n")
    
    # 邮件头部
    s_string("From: ")
    s_group("from_header", values=symbolic_emails[:8])
    s_delim("\r\n")
    
    s_string("To: ")
    s_group("to_header", values=symbolic_emails[:8])
    s_delim("\r\n")
    
    s_string("Subject: ")
    subjects = [
        "Test Message",
        "Important Notice",
        "System Alert",
        "=?UTF-8?B?5L2g5aW95LiA5Liq56S6?=",  # Base64编码的中文主题
        "=?ISO-2022-JP?B?GyRCJCIkbCEpJGIkNxsoQg==?="  # JIS编码的日文主题
    ] + symbolic_subjects
    s_group("subject", values=subjects)
    s_delim("\r\n")
    
    # 可选的其他头部
    s_string("Date: ")
    s_string("Mon, 01 Jan 2024 12:00:00 +0000")
    s_delim("\r\n")
    
    s_string("Message-ID: ")
    s_string("<test@example.com>")
    s_delim("\r\n")
    
    s_string("MIME-Version: ")
    s_string("1.0")
    s_delim("\r\n")
    
    s_string("Content-Type: ")
    content_types = [
        "text/plain; charset=utf-8",
        "text/html; charset=utf-8",
        "multipart/mixed; boundary=\"frontier\"",
        "multipart/alternative; boundary=\"boundary42\""
    ]
    s_group("content_type", values=content_types)
    s_delim("\r\n")
    
    # 空行分隔头部和正文
    s_delim("\r\n")
    
    # 邮件正文 (更复杂的MIME结构将在下面定义)
    message_bodies = [
        "This is a test message.",
        "Hello World!",
        "System notification message.",
        "This is a message with unicode: 你好世界 🌍",
        "Message with special chars: \x00\x01\x02\x03"
    ] + symbolic_bodies
    
    s_group("message_body", values=message_bodies)
    s_delim("\r\n")
    
    # 邮件结束标记
    s_string(".\r\n")
    
    requests.append(s_get("SMTP_DATA"))
    
    # 5. SMTP AUTH命令 (认证)
    s_initialize("SMTP_AUTH")
    
    s_string("AUTH ")
    
    # 认证机制
    auth_mechanisms = [
        "PLAIN",
        "LOGIN", 
        "CRAM-MD5",
        "DIGEST-MD5",
        "NTLM"
    ]
    s_group("auth_mechanism", values=auth_mechanisms)
    
    # 认证数据 (Base64编码的用户名:密码)
    auth_data = [
        "",  # 无数据
        "dGVzdEB0ZXN0LmNvbTpwYXNzd29yZA==",  # test@test.com:password
        "YWRtaW46YWRtaW4=",  # admin:admin
        "cm9vdDpyb290",  # root:root
        "AHVzZXIAcGFzc3dvcmQ="  # 另一种PLAIN格式 (username\0password)
    ]
    
    s_delim(" ")
    s_group("auth_data", values=auth_data)
    s_delim("\r\n")
    
    requests.append(s_get("SMTP_AUTH"))
    
    # 6. SMTP VRFY命令 (验证用户)
    s_initialize("SMTP_VRFY")
    
    s_string("VRFY ")
    
    # 要验证的用户
    verify_users = [
        "root",
        "admin",
        "postmaster",
        "test",
        "user",
        "<test@example.com>",  # 验证完整邮箱地址
        "\"Test User\" <test@example.com>"  # 验证带名字的邮箱地址
    ] + [email.split('@')[0] for email in symbolic_emails[:5]]  # 提取用户名部分
    
    s_group("verify_user", values=verify_users)
    s_delim("\r\n")
    
    requests.append(s_get("SMTP_VRFY"))
    
    # 7. SMTP EXPN命令 (展开邮件列表)
    s_initialize("SMTP_EXPN")
    
    s_string("EXPN ")
    
    # 邮件列表名
    mailing_lists = [
        "all",
        "staff",
        "users",
        "admin",
        "postmaster",
        "\"Mailing List\" <list@example.com>"  # 带名字的列表
    ]
    s_group("mailing_list", values=mailing_lists)
    s_delim("\r\n")
    
    requests.append(s_get("SMTP_EXPN"))
    
    # 8. SMTP HELP命令
    s_initialize("SMTP_HELP")
    
    s_string("HELP")
    
    # 可选的命令参数
    help_topics = [
        "",
        " MAIL",
        " RCPT", 
        " DATA",
        " AUTH",
        " VRFY",
        " EXPN"
    ]
    s_group("help_topic", values=help_topics)
    s_delim("\r\n")
    
    requests.append(s_get("SMTP_HELP"))
    
    # 9. SMTP STARTTLS命令
    s_initialize("SMTP_STARTTLS")
    
    s_string("STARTTLS\r\n")
    
    requests.append(s_get("SMTP_STARTTLS"))
    
    # 10. 恶意SMTP命令 (缓冲区溢出测试)
    s_initialize("SMTP_MALICIOUS")
    
    # 超长命令测试
    malicious_commands = [
        "HELO " + "A" * 1000,
        "MAIL FROM:<" + "x" * 500 + "@example.com>",
        "RCPT TO:<" + "y" * 500 + "@example.com>",
        "VRFY " + "z" * 1000,
        "EXPN " + "w" * 1000,
        "AUTH PLAIN " + "A" * 1000  # 超长认证数据
    ]
    
    s_group("malicious_command", values=malicious_commands)
    s_delim("\r\n")
    
    requests.append(s_get("SMTP_MALICIOUS"))
    
    # 11. SMTP RSET命令
    s_initialize("SMTP_RSET")
    
    s_string("RSET\r\n")
    
    requests.append(s_get("SMTP_RSET"))
    
    # 12. SMTP NOOP命令
    s_initialize("SMTP_NOOP")
    
    s_string("NOOP\r\n")
    
    requests.append(s_get("SMTP_NOOP"))
    
    # 13. SMTP QUIT命令
    s_initialize("SMTP_QUIT")
    
    s_string("QUIT\r\n")
    
    requests.append(s_get("SMTP_QUIT"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description="Enhanced SMTP Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 25)", nargs='?', default=25)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26008, help="Web interface port")
    parser.add_argument("--ssl", action="store_true", help="Use SMTPS (SSL/TLS)")
    
    args = parser.parse_args()
    
    print("Enhanced SMTP Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"SSL: {'Yes' if args.ssl else 'No'}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("Dry run mode - testing request generation...")
        requests = create_smtp_requests()
        print(f"Successfully created {len(requests)} SMTP request templates")
        
        for i, req in enumerate(requests):
            print(f"\nRequest {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # SMTP是文本协议，可以直接显示
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
    
    # 创建SMTP请求
    requests = create_smtp_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(request)
    
    print("Starting SMTP protocol fuzzing...")
    print(f"Monitor: http://localhost:{args.web_port}")
    print("WARNING: this will perform potentially dangerous operations against the target SMTP server!")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
    except Exception as e:
        print(f"\nError during fuzzing: {e}")
    finally:
        try:
            save_ai_learning_data("smtp")
        except Exception:
            pass
        print("SMTP fuzzing completed")

if __name__ == "__main__":
    main()
