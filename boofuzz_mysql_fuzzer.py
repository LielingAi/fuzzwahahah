#!/usr/bin/env python3
"""
Enhanced MySQL Protocol Fuzzer with Symbolic Execution
基于boofuzz的MySQL协议模糊测试工具，集成符号执行和智能优化
"""

import sys
import time
import argparse
import struct
import fw_vendor  # vendored boofuzz path bootstrap
from boofuzz import *
from boofuzz.utils.enhanced_symbolic_execution import (
    generate_protocol_data, 
    learn_from_test_result,
    save_ai_learning_data
)

def create_mysql_requests():
    """创建增强的MySQL请求模板"""
    
    
    print("Using AI to generate MySQL test data...")
    
    # 使用AI增强的协议数据生成
    try:
        symbolic_adaptation_interval = generate_protocol_data('mysql', 'adaptation_interval', 15, use_ai=True)
        symbolic_decision_threshold = generate_protocol_data('mysql', 'decision_threshold', 15, use_ai=True)
        symbolic_dbs = generate_protocol_data('mysql', 'dbs', 15, use_ai=True)
        symbolic_learning_data = generate_protocol_data('mysql', 'learning_data', 15, use_ai=True)
        symbolic_tables = generate_protocol_data('mysql', 'tables', 15, use_ai=True)
        symbolic_sqls = generate_protocol_data('mysql', 'sqls', 15, use_ai=True)
        symbolic_execution = generate_protocol_data('mysql', 'execution', 15, use_ai=True)
        symbolic_strategy_enabled = generate_protocol_data('mysql', 'strategy_enabled', 15, use_ai=True)
        symbolic_symbolic_execution = generate_protocol_data('mysql', 'symbolic_execution', 15, use_ai=True)
        
        print("AI data generation completed")
        
    except Exception as e:
        print(f"AI data generation failed, using base data: {e}")
        # 使用基础数据作为后备
        symbolic_adaptation_interval = ["test_adaptation_interval", "default_adaptation_interval", "sample_adaptation_interval"]
        symbolic_decision_threshold = ["test_decision_threshold", "default_decision_threshold", "sample_decision_threshold"]
        symbolic_dbs = ["test_dbs", "default_dbs", "sample_dbs"]
        symbolic_learning_data = ["test_learning_data", "default_learning_data", "sample_learning_data"]
        symbolic_tables = ["test_tables", "default_tables", "sample_tables"]
        symbolic_sqls = ["test_sqls", "default_sqls", "sample_sqls"]
        symbolic_execution = ["test_execution", "default_execution", "sample_execution"]
        symbolic_strategy_enabled = ["test_strategy_enabled", "default_strategy_enabled", "sample_strategy_enabled"]
        symbolic_symbolic_execution = ["test_symbolic_execution", "default_symbolic_execution", "sample_symbolic_execution"]
    
    requests = []
    
    # MySQL协议包结构: [长度3字节][序号1字节][数据]
    
    # 1. 登录请求 (Client Authentication Packet)
    s_initialize("MYSQL_LOGIN")
    
    # 包头
    s_size("login_packet", length=3, endian="<")  # 包长度 (小端序)
    s_byte(0x01, name="sequence_id")  # 序列号
    
    s_block_start("login_packet")
    
    # 客户端能力标志 (4字节)
    s_dword(0x00000001, endian="<", name="client_flags")
    
    # 最大包大小 (4字节)
    s_dword(0x01000000, endian="<", name="max_packet_size")
    
    # 字符集 (1字节)
    s_byte(0x08, name="charset")  # latin1_swedish_ci
    
    # 保留字段 (23字节)
    s_bytes(b'\x00' * 23, name="reserved")
    
    # 用户名 (null结尾字符串)
    usernames = ["root", "admin", "test", "mysql"] + symbolic_dbs[:5]
    s_group("username", values=usernames)
    s_delim(b"\x00")
    
    # 密码长度和密码
    s_byte(0x00, name="password_length")  # 无密码
    
    # 数据库名 (可选, null结尾)
    s_group("database", values=symbolic_dbs[:8])
    s_delim(b"\x00")
    
    s_block_end("login_packet")
    
    requests.append(s_get("MYSQL_LOGIN"))
    
    # 2. COM_QUERY - SELECT查询
    s_initialize("MYSQL_SELECT")
    
    s_size("select_packet", length=3, endian="<")
    s_byte(0x00, name="sequence_id")
    
    s_block_start("select_packet")
    
    # 命令类型: COM_QUERY (0x03)
    s_byte(0x03, name="command")
    
    # SQL查询语句
    select_queries = [
        "SELECT 1",
        "SELECT VERSION()",
        "SELECT USER()",
        "SELECT DATABASE()",
        "SHOW DATABASES",
        "SHOW TABLES"
    ] + symbolic_sqls[:10]
    
    s_group("query", values=select_queries)
    
    s_block_end("select_packet")
    
    requests.append(s_get("MYSQL_SELECT"))
    
    # 3. COM_QUERY - INSERT语句
    s_initialize("MYSQL_INSERT")
    
    s_size("insert_packet", length=3, endian="<")
    s_byte(0x00, name="sequence_id")
    
    s_block_start("insert_packet")
    
    s_byte(0x03, name="command")  # COM_QUERY
    
    # INSERT语句模板
    s_string("INSERT INTO ")
    s_group("table", values=symbolic_tables[:10])
    s_string(" (id, name) VALUES (")
    s_group("id_value", values=["1", "999", "-1", "NULL"] + [str(i) for i in range(5)])
    s_string(", '")
    s_group("name_value", values=["test", "admin", "user"] + symbolic_dbs[:5])
    s_string("')")
    
    s_block_end("insert_packet")
    
    requests.append(s_get("MYSQL_INSERT"))
    
    # 4. COM_QUERY - UPDATE语句  
    s_initialize("MYSQL_UPDATE")
    
    s_size("update_packet", length=3, endian="<")
    s_byte(0x00, name="sequence_id")
    
    s_block_start("update_packet")
    
    s_byte(0x03, name="command")
    
    s_string("UPDATE ")
    s_group("table", values=symbolic_tables[:8])
    s_string(" SET name='")
    s_group("new_value", values=["updated", "modified"] + symbolic_dbs[:3])
    s_string("' WHERE id=")
    s_group("where_id", values=["1", "2", "999"])
    
    s_block_end("update_packet")
    
    requests.append(s_get("MYSQL_UPDATE"))
    
    # 5. COM_QUERY - DELETE语句
    s_initialize("MYSQL_DELETE")
    
    s_size("delete_packet", length=3, endian="<")
    s_byte(0x00, name="sequence_id")
    
    s_block_start("delete_packet")
    
    s_byte(0x03, name="command")
    
    s_string("DELETE FROM ")
    s_group("table", values=symbolic_tables[:5])
    s_string(" WHERE id=")
    s_group("where_id", values=["999", "0", "-1"])
    
    s_block_end("delete_packet")
    
    requests.append(s_get("MYSQL_DELETE"))
    
    # 6. COM_INIT_DB - 切换数据库
    s_initialize("MYSQL_USE_DB")
    
    s_size("usedb_packet", length=3, endian="<")
    s_byte(0x00, name="sequence_id")
    
    s_block_start("usedb_packet")
    
    # 命令类型: COM_INIT_DB (0x02)
    s_byte(0x02, name="command")
    
    # 数据库名
    s_group("database", values=symbolic_dbs[:12])
    
    s_block_end("usedb_packet")
    
    requests.append(s_get("MYSQL_USE_DB"))
    
    # 7. COM_QUERY - 危险查询 (用于安全测试)
    s_initialize("MYSQL_DANGEROUS")
    
    s_size("dangerous_packet", length=3, endian="<")
    s_byte(0x00, name="sequence_id")
    
    s_block_start("dangerous_packet")
    
    s_byte(0x03, name="command")
    
    # 潜在的SQL注入和危险查询
    dangerous_queries = [
        "SELECT * FROM mysql.user",
        "SHOW GRANTS",
        "SELECT @@version_comment",
        "SELECT LOAD_FILE('/etc/passwd')",
        "SELECT 1 UNION SELECT 2",
        "'; DROP TABLE test; --"
    ] + [q for q in symbolic_sqls if any(keyword in q.upper() for keyword in ['UNION', 'DROP', 'DELETE', 'UPDATE'])]
    
    s_group("query", values=dangerous_queries[:15])
    
    s_block_end("dangerous_packet")
    
    requests.append(s_get("MYSQL_DANGEROUS"))
    
    # 8. COM_QUIT - 断开连接
    s_initialize("MYSQL_QUIT")
    
    s_size("quit_packet", length=3, endian="<")
    s_byte(0x00, name="sequence_id")
    
    s_block_start("quit_packet")
    
    # 命令类型: COM_QUIT (0x01)
    s_byte(0x01, name="command")
    
    s_block_end("quit_packet")
    
    requests.append(s_get("MYSQL_QUIT"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description="Enhanced MySQL Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 3306)", nargs='?', default=3306)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26003, help="Web interface port")
    parser.add_argument("--username", default="root", help="MySQL username")
    parser.add_argument("--database", default="test", help="Target database")
    
    args = parser.parse_args()
    
    print("Enhanced MySQL Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Username: {args.username}")
    print(f"Database: {args.database}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("Dry run mode - testing request generation...")
        requests = create_mysql_requests()
        print(f"Successfully created {len(requests)} MySQL request templates")
        
        for i, req in enumerate(requests):
            print(f"\nRequest {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # MySQL协议是二进制的，显示十六进制
                hex_preview = rendered[:50].hex()
                print(f"   Hex Preview: {hex_preview}...")
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
    
    # 创建MySQL请求
    requests = create_mysql_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(request)
    
    print("Starting MySQL protocol fuzzing...")
    print(f"Monitor: http://localhost:{args.web_port}")
    print("WARNING: this will perform potentially dangerous operations against the target MySQL server!")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
    except Exception as e:
        print(f"\nError during fuzzing: {e}")
    finally:
        try:
            save_ai_learning_data("mysql")
        except Exception:
            pass
        print("MySQL fuzzing completed")

if __name__ == "__main__":
    main()
