#!/usr/bin/env python3
"""
Enhanced IMAP Protocol Fuzzer with Symbolic Execution
基于boofuzz的IMAP协议模糊测试工具，集成符号执行和智能优化
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

def create_imap_requests():
    \"\"\"创建增强的IMAP请求模板\"\"\"
    
    print(\"🧠 使用AI增强生成IMAP测试数据...\")
    
    # 使用AI增强的协议数据生成
    try:
        symbolic_commands = generate_protocol_data('imap', 'commands', 20, use_ai=True)
        symbolic_usernames = generate_protocol_data('imap', 'usernames', 12, use_ai=True)
        symbolic_passwords = generate_protocol_data('imap', 'passwords', 10, use_ai=True)
        symbolic_mailboxes = generate_protocol_data('imap', 'mailboxes', 8, use_ai=True)
        symbolic_search_criteria = generate_protocol_data('imap', 'search_criteria', 10, use_ai=True)

        print(f\"✅ AI生成了 {len(symbolic_commands)} 个IMAP命令变异\")
        print(f\"✅ AI生成了 {len(symbolic_usernames)} 个用户名变异\")
        print(f\"✅ AI生成了 {len(symbolic_passwords)} 个密码变异\")
        print(f\"✅ AI生成了 {len(symbolic_mailboxes)} 个邮箱名变异\")
        print(f\"✅ AI生成了 {len(symbolic_search_criteria)} 个搜索条件变异\")
        
    except Exception as e:
        print(f\"⚠️  AI数据生成失败，使用基础数据: {e}\")
        # 使用基础数据作为后备
        symbolic_commands = ['LOGIN', 'SELECT', 'EXAMINE', 'CREATE', 'DELETE', 'RENAME', 'SUBSCRIBE', 'UNSUBSCRIBE', 'LIST', 'LSUB', 'STATUS', 'APPEND', 'CHECK', 'CLOSE', 'EXPUNGE', 'SEARCH', 'FETCH', 'STORE', 'COPY', 'UID']
        symbolic_usernames = ['test', 'admin', 'user', 'root', 'postmaster']
        symbolic_passwords = ['password', '123456', 'admin123', 'testpass']
        symbolic_mailboxes = ['INBOX', 'Sent', 'Drafts', 'Junk', 'Trash']
        symbolic_search_criteria = ['ALL', 'ANSWERED', 'DELETED', 'FLAGGED', 'NEW', 'OLD', 'RECENT', 'SEEN', 'UNANSWERED', 'UNDELETED', 'UNFLAGGED', 'UNSEEN']

    requests = []
    
    # IMAP是基于文本的协议，使用CRLF作为行结束符，并且每个命令前有一个tag
    
    # 1. IMAP LOGIN命令
    s_initialize(\"IMAP_LOGIN\")
    s_string(\"A1 LOGIN \")
    s_delim(\"\"\")
    usernames = [
        \"test\",
        \"admin\",
        \"user\",
        \"root\",
        \"postmaster\"
    ] + symbolic_usernames[:8]
    s_group(\"username\", values=usernames)
    s_delim(\"\"\")
    s_delim(\" \")
    s_delim(\"\"\")
    passwords = [
        \"password\",
        \"123456\",
        \"admin123\",
        \"testpass\",
        \"\"
    ] + symbolic_passwords[:8]
    s_group(\"password\", values=passwords)
    s_delim(\"\"\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_LOGIN\"))
    
    # 2. IMAP SELECT命令
    s_initialize(\"IMAP_SELECT\")
    s_string(\"A2 SELECT \")
    s_delim(\"\"\")
    mailboxes = [
        \"INBOX\",
        \"Sent\",
        \"Drafts\",
        \"Junk\",
        \"Trash\",
        \"INBOX/SubFolder\"
    ] + symbolic_mailboxes[:5]
    s_group(\"mailbox\", values=mailboxes)
    s_delim(\"\"\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_SELECT\"))
    
    # 3. IMAP EXAMINE命令
    s_initialize(\"IMAP_EXAMINE\")
    s_string(\"A3 EXAMINE \")
    s_delim(\"\"\")
    s_group(\"examine_mailbox\", values=mailboxes)
    s_delim(\"\"\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_EXAMINE\"))
    
    # 4. IMAP CREATE命令
    s_initialize(\"IMAP_CREATE\")
    s_string(\"A4 CREATE \")
    s_delim(\"\"\")
    create_mailboxes = [
        \"NewFolder\",
        \"Test/Folder\",
        \"A\" * 1000  # 超长邮箱名测试
    ] + [f\"Test_{mb}\" for mb in symbolic_mailboxes[:5]]
    s_group(\"create_mailbox\", values=create_mailboxes)
    s_delim(\"\"\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_CREATE\"))
    
    # 5. IMAP DELETE命令
    s_initialize(\"IMAP_DELETE\")
    s_string(\"A5 DELETE \")
    s_delim(\"\"\")
    delete_mailboxes = [
        \"OldFolder\",
        \"Test/Folder\",
        \"NonExistentFolder\"
    ] + [f\"Delete_{mb}\" for mb in symbolic_mailboxes[:5]]
    s_group(\"delete_mailbox\", values=delete_mailboxes)
    s_delim(\"\"\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_DELETE\"))
    
    # 6. IMAP RENAME命令
    s_initialize(\"IMAP_RENAME\")
    s_string(\"A6 RENAME \")
    s_delim(\"\"\")
    s_group(\"rename_from\", values=mailboxes)
    s_delim(\"\"\")
    s_delim(\" \")
    s_delim(\"\"\")
    rename_tos = [
        \"RenamedFolder\",
        \"New/Location\",
        \"A\" * 1000  # 超长邮箱名测试
    ] + [f\"Renamed_{mb}\" for mb in symbolic_mailboxes[:5]]
    s_group(\"rename_to\", values=rename_tos)
    s_delim(\"\"\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_RENAME\"))
    
    # 7. IMAP LIST命令
    s_initialize(\"IMAP_LIST\")
    s_string(\"A7 LIST \")
    s_delim(\"\"\")
    # 引用名
    references = [\"\", \"INBOX.\", \"Other/\"]
    s_group(\"reference\", values=references)
    s_delim(\"\"\")
    s_delim(\" \")
    s_delim(\"\"\")
    # 邮箱名模式
    patterns = [\"*\", \"%\", \"INBOX*\", \"Sent*\"]
    s_group(\"pattern\", values=patterns)
    s_delim(\"\"\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_LIST\"))
    
    # 8. IMAP LSUB命令
    s_initialize(\"IMAP_LSUB\")
    s_string(\"A8 LSUB \")
    s_delim(\"\"\")
    s_group(\"lsub_reference\", values=references)
    s_delim(\"\"\")
    s_delim(\" \")
    s_delim(\"\"\")
    s_group(\"lsub_pattern\", values=patterns)
    s_delim(\"\"\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_LSUB\"))
    
    # 9. IMAP STATUS命令
    s_initialize(\"IMAP_STATUS\")
    s_string(\"A9 STATUS \")
    s_delim(\"\"\")
    s_group(\"status_mailbox\", values=mailboxes)
    s_delim(\"\"\")
    s_delim(\" \")
    s_delim(\"(\")
    # 状态项
    status_items = [\"MESSAGES\", \"RECENT\", \"UIDNEXT\", \"UIDVALIDITY\", \"UNSEEN\"]
    s_group(\"status_item\", values=status_items)
    s_delim(\")\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_STATUS\"))
    
    # 10. IMAP APPEND命令 (简化版)
    s_initialize(\"IMAP_APPEND\")
    s_string(\"A10 APPEND \")
    s_delim(\"\"\")
    s_group(\"append_mailbox\", values=mailboxes)
    s_delim(\"\"\")
    s_delim(\" \")
    # 可选的标志
    s_string(\"\\\\Seen \")
    s_delim(\"\"\")
    # 邮件内容 (简化)
    s_string(\"Subject: Test\\\\r\\\\n\\\\r\\\\nThis is a test message.\")
    s_delim(\"\"\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_APPEND\"))
    
    # 11. IMAP CHECK命令
    s_initialize(\"IMAP_CHECK\")
    s_string(\"A11 CHECK\\r\\n\")
    requests.append(s_get(\"IMAP_CHECK\"))
    
    # 12. IMAP CLOSE命令
    s_initialize(\"IMAP_CLOSE\")
    s_string(\"A12 CLOSE\\r\\n\")
    requests.append(s_get(\"IMAP_CLOSE\"))
    
    # 13. IMAP EXPUNGE命令
    s_initialize(\"IMAP_EXPUNGE\")
    s_string(\"A13 EXPUNGE\\r\\n\")
    requests.append(s_get(\"IMAP_EXPUNGE\"))
    
    # 14. IMAP SEARCH命令
    s_initialize(\"IMAP_SEARCH\")
    s_string(\"A14 SEARCH \")
    search_criteria = [
        \"ALL\",
        \"ANSWERED\",
        \"DELETED\",
        \"FLAGGED\",
        \"NEW\",
        \"OLD\",
        \"RECENT\",
        \"SEEN\",
        \"UNANSWERED\",
        \"UNDELETED\",
        \"UNFLAGGED\",
        \"UNSEEN\",
        \"SUBJECT \\\"test\\\"\",
        \"FROM \\\"admin\\\"\",
        \"TO \\\"user\\\"\"
    ] + symbolic_search_criteria[:8]
    s_group(\"search_criterion\", values=search_criteria)
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_SEARCH\"))
    
    # 15. IMAP FETCH命令
    s_initialize(\"IMAP_FETCH\")
    s_string(\"A15 FETCH \")
    # 邮件序列号
    seq_numbers = [\"1\", \"1:5\", \"1,2,3\", \"*\", \"1:*\"]
    s_group(\"seq_num\", values=seq_numbers)
    s_delim(\" \")
    # 数据项
    data_items = [\"ENVELOPE\", \"FLAGS\", \"INTERNALDATE\", \"RFC822\", \"RFC822.HEADER\", \"RFC822.TEXT\", \"UID\"]
    s_group(\"data_item\", values=data_items)
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_FETCH\"))
    
    # 16. IMAP STORE命令
    s_initialize(\"IMAP_STORE\")
    s_string(\"A16 STORE \")
    # 邮件序列号
    s_group(\"store_seq_num\", values=seq_numbers)
    s_delim(\" \")
    # 数据项名称
    s_string(\"FLAGS\")
    s_delim(\" \")
    # 标志列表
    s_delim(\"(\")
    flags = [\"\\\\Seen\", \"\\\\Answered\", \"\\\\Flagged\", \"\\\\Deleted\", \"\\\\Draft\"]
    s_group(\"flag\", values=flags)
    s_delim(\")\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_STORE\"))
    
    # 17. IMAP COPY命令
    s_initialize(\"IMAP_COPY\")
    s_string(\"A17 COPY \")
    # 邮件序列号
    s_group(\"copy_seq_num\", values=seq_numbers)
    s_delim(\" \")
    s_delim(\"\"\")
    s_group(\"copy_mailbox\", values=mailboxes)
    s_delim(\"\"\")
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_COPY\"))
    
    # 18. IMAP UID命令 (示例: UID FETCH)
    s_initialize(\"IMAP_UID\")
    s_string(\"A18 UID FETCH \")
    # UID序列号
    uid_seq_numbers = [\"1\", \"1:100\", \"1,2,3\", \"*\"]
    s_group(\"uid_seq_num\", values=uid_seq_numbers)
    s_delim(\" \")
    s_group(\"uid_data_item\", values=data_items)
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_UID\"))
    
    # 19. IMAP CAPABILITY命令
    s_initialize(\"IMAP_CAPABILITY\")
    s_string(\"A19 CAPABILITY\\r\\n\")
    requests.append(s_get(\"IMAP_CAPABILITY\"))
    
    # 20. IMAP NOOP命令
    s_initialize(\"IMAP_NOOP\")
    s_string(\"A20 NOOP\\r\\n\")
    requests.append(s_get(\"IMAP_NOOP\"))
    
    # 21. IMAP LOGOUT命令
    s_initialize(\"IMAP_LOGOUT\")
    s_string(\"A21 LOGOUT\\r\\n\")
    requests.append(s_get(\"IMAP_LOGOUT\"))
    
    # 22. 恶意IMAP命令 (缓冲区溢出测试)
    s_initialize(\"IMAP_MALICIOUS\")
    # 超长命令测试
    malicious_commands = [
        \"A999 LOGIN \" + \"\\\"A\\\" * 500 + \" \" + \"\\\"B\\\" * 500\",
        \"A998 SELECT \" + \"\\\"C\\\" * 1000\",
        \"A997 LIST \\\"\\\" \" + \"\\\"D\\\" * 1000\",
        \"A996 SEARCH \" + \"E\" * 1000,
        \"A995 FETCH 1 \" + \"F\" * 1000
    ]
    s_group(\"malicious_command\", values=malicious_commands)
    s_delim(\"\\r\\n\")
    requests.append(s_get(\"IMAP_MALICIOUS\"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description=\"Enhanced IMAP Protocol Fuzzer\")
    parser.add_argument(\"target\", help=\"Target IP address\")
    parser.add_argument(\"port\", type=int, help=\"Target port (default: 143)\", nargs='?', default=143)
    parser.add_argument(\"--timeout\", type=int, default=5, help=\"Connection timeout\")
    parser.add_argument(\"--dry-run\", action=\"store_true\", help=\"Test without actual fuzzing\")
    parser.add_argument(\"--web-port\", type=int, default=26010, help=\"Web interface port\")
    parser.add_argument(\"--ssl\", action=\"store_true\", help=\"Use IMAPS (SSL/TLS)\")
    
    args = parser.parse_args()
    
    print(\"📧 Enhanced IMAP Protocol Fuzzer\")
    print(\"=\" * 50)
    print(f\"Target: {args.target}:{args.port}\")
    print(f\"SSL: {'Yes' if args.ssl else 'No'}\")
    print(f\"Web Interface: http://localhost:{args.web_port}\")
    print()
    
    if args.dry_run:
        print(\"🧪 Dry run mode - testing request generation...\")
        requests = create_imap_requests()
        print(f\"✅ Successfully created {len(requests)} IMAP request templates\")
        
        for i, req in enumerate(requests):
            print(f\"\\n📋 Request {i+1}: {req.name}\")
            try:
                rendered = req.render()
                print(f\"   Size: {len(rendered)} bytes\")
                # IMAP是文本协议，可以直接显示
                preview = rendered.decode('utf-8', errors='ignore')[:100]
                preview_clean = preview.replace(chr(13), '\\\\r').replace(chr(10), '\\\\n')
                print(f\"   Preview: {preview_clean}...\")
            except Exception as e:
                print(f\"   Error: {e}\")
        
        print(\"\\n✅ Dry run completed successfully!\")
        return
    
    # 创建会话
    session = Session(
        target=Target(
            connection=SocketConnection(
                host=args.target,
                port=args.port,
                proto=\"ssl\" if args.ssl else \"tcp\",
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
    
    print(\"🤖 AI自适应策略已启用\")
    
    # 创建IMAP请求
    requests = create_imap_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(s_get(\"target\"), request)
    
    print(f\"🚀 开始IMAP协议模糊测试...\")
    print(f\"📊 监控界面: http://localhost:{args.web_port}\")
    print(\"⚠️  警告: 这将对目标IMAP服务器执行潜在危险的操作!\")

    try:
        session.fuzz()
    except KeyboardInterrupt:
        print(\"\\n⏹️  用户中断测试\")
    except Exception as e:
        print(f\"\\n❌ 测试过程中出现错误: {e}\")
    finally:
        print(\"🏁 IMAP模糊测试完成\")

if __name__ == \"__main__\":
    main()