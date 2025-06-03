#!/usr/bin/env python3
"""
Enhanced SMTP Protocol Fuzzer with Symbolic Execution
基于boofuzz的SMTP协议模糊测试工具，集成符号执行和智能优化
"""

import sys
import time
import argparse
from boofuzz import *
from boofuzz.utils.enhanced_symbolic_execution import (
    generate_protocol_data, 
    learn_from_test_result,
    save_ai_learning_data
)

def create_smtp_requests():
    """创建增强的SMTP请求模板"""
    
    
    print("🧠 使用AI增强生成SMTP测试数据...")
    
    # 使用AI增强的协议数据生成
    try:
        symbolic_commands = generate_protocol_data('smtp', 'commands', 15, use_ai=True)
        symbolic_emails = generate_protocol_data('smtp', 'emails', 12, use_ai=True)
        symbolic_subjects = generate_protocol_data('smtp', 'subjects', 10, use_ai=True)
        symbolic_bodies = generate_protocol_data('smtp', 'bodies', 8, use_ai=True)

        print(f"✅ AI生成了 {len(symbolic_commands)} 个SMTP命令变异")
        print(f"✅ AI生成了 {len(symbolic_emails)} 个邮件地址变异")
        print(f"✅ AI生成了 {len(symbolic_subjects)} 个邮件主题变异")
        print(f"✅ AI生成了 {len(symbolic_bodies)} 个邮件正文变异")
        
    except Exception as e:
        print(f"⚠️  AI数据生成失败，使用基础数据: {e}")
        # 使用基础数据作为后备
        symbolic_commands = ['HELO', 'EHLO', 'MAIL FROM', 'RCPT TO', 'DATA', 'QUIT']
        symbolic_emails = ['test@example.com', 'admin@localhost', 'user@test.local']
        symbolic_subjects = ['Test Subject', 'Important Notice', 'System Alert']
        symbolic_bodies = ['Test message body', 'Hello World!', 'System notification']
# 初始化符号执行引擎
    
    
    print("🧠 生成SMTP符号执行数据...")
    
    # SMTP命令分析
    smtp_commands = []
    
    # 邮件地址分析
    email_addresses = []
    
    # 邮件内容分析
    email_content = []
    
    print(f"✅ 生成了 {len(smtp_commands)} 个SMTP命令变异")
    print(f"✅ 生成了 {len(email_addresses)} 个邮件地址变异")
    print(f"✅ 生成了 {len(email_content)} 个邮件内容变异")
    
    # 使用基础测试数据
    # 使用AI增强的协议数据生成
    print("🧠 使用AI增强生成SMTP测试数据...")
    
    # AI增强的数据生成将在下面的代码中使用generate_protocol_data()
    # 使用AI增强的协议数据生成
    print("🧠 使用AI增强生成SMTP测试数据...")
    
    # AI增强的数据生成将在下面的代码中使用generate_protocol_data()
    # 使用AI增强的协议数据生成
    print("🧠 使用AI增强生成SMTP测试数据...")
    
    # AI增强的数据生成将在下面的代码中使用generate_protocol_data()
    
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
        " AUTH=user@example.com"
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
        "System Alert"
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
    
    # 空行分隔头部和正文
    s_delim("\r\n")
    
    # 邮件正文
    message_bodies = [
        "This is a test message.",
        "Hello World!",
        "System notification message."
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
        "cm9vdDpyb290"  # root:root
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
        "user"
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
        "postmaster"
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
        " AUTH"
    ]
    s_group("help_topic", values=help_topics)
    s_delim("\r\n")
    
    requests.append(s_get("SMTP_HELP"))
    
    # 9. 恶意SMTP命令 (缓冲区溢出测试)
    s_initialize("SMTP_MALICIOUS")
    
    # 超长命令测试
    malicious_commands = [
        "HELO " + "A" * 1000,
        "MAIL FROM:<" + "x" * 500 + "@example.com>",
        "RCPT TO:<" + "y" * 500 + "@example.com>",
        "VRFY " + "z" * 1000,
        "EXPN " + "w" * 1000
    ]
    
    s_group("malicious_command", values=malicious_commands)
    s_delim("\r\n")
    
    requests.append(s_get("SMTP_MALICIOUS"))
    
    # 10. SMTP QUIT命令
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
    
    print("📧 Enhanced SMTP Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"SSL: {'Yes' if args.ssl else 'No'}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("🧪 Dry run mode - testing request generation...")
        requests = create_smtp_requests()
        print(f"✅ Successfully created {len(requests)} SMTP request templates")
        
        for i, req in enumerate(requests):
            print(f"\n📋 Request {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # SMTP是文本协议，可以直接显示
                preview = rendered.decode('utf-8', errors='ignore')[:100]
                preview_clean = preview.replace(chr(13), '\\r').replace(chr(10), '\\n')
                print(f"   Preview: {preview_clean}...")
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
                proto="ssl" if args.ssl else "tcp",
                timeout=args.timeout
            )
    
        ),
        web_port=args.web_port,
        check_data_received_each_request=False
    )
    
    # 启用AI自适应策略
    session.ai_strategy_enabled = True
    session.ai_decision_threshold = 0.15
    session.ai_adaptation_interval = 50
    
    print("🤖 AI自适应策略已启用")
    
    # 创建SMTP请求
    requests = create_smtp_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(s_get("target"), request)
    
    print(f"🚀 开始SMTP协议模糊测试...")
    print(f"📊 监控界面: http://localhost:{args.web_port}")
    print("⚠️  警告: 这将对目标SMTP服务器执行潜在危险的操作!")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\n⏹️  用户中断测试")
    except Exception as e:
        print(f"\n❌ 测试过程中出现错误: {e}")
    finally:
        print("🏁 SMTP模糊测试完成")

if __name__ == "__main__":
    main()
