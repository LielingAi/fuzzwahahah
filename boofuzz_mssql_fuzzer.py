#!/usr/bin/env python3
"""
Enhanced MSSQL Protocol Fuzzer with Symbolic Execution
基于boofuzz的MSSQL协议模糊测试工具，集成符号执行和智能优化
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

def create_mssql_requests():
    """创建增强的MSSQL请求模板"""
    
    
    print("Using AI to generate MSSQL test data...")
    
    # 使用AI增强的协议数据生成
    try:
        symbolic_queries = generate_protocol_data('mssql', 'queries', 15, use_ai=True)
        symbolic_databases = generate_protocol_data('mssql', 'databases', 12, use_ai=True)
        symbolic_tables = generate_protocol_data('mssql', 'tables', 10, use_ai=True)
        symbolic_procedures = generate_protocol_data('mssql', 'procedures', 8, use_ai=True)

        print(f"AI generated {len(symbolic_queries)} MSSQL query variants")
        print(f"AI generated {len(symbolic_databases)} database variants")
        print(f"AI generated {len(symbolic_tables)} table name variants")
        print(f"AI generated {len(symbolic_procedures)} stored procedure variants")

    except Exception as e:
        print(f"AI data generation failed, using base data: {e}")
        # 使用基础数据作为后备
        symbolic_queries = ["SELECT @@VERSION", "SELECT SYSTEM_USER", "EXEC sp_helpdb"]
        symbolic_databases = ["master", "tempdb", "msdb", "model"]
        symbolic_tables = ["sysobjects", "sysusers", "syscolumns"]
        symbolic_procedures = ["sp_help", "sp_helpdb", "sp_who", "xp_cmdshell"]
    
    requests = []
    
    # MSSQL TDS协议 (Tabular Data Stream)
    
    # 1. 预登录包 (Pre-Login Packet)
    s_initialize("MSSQL_PRELOGIN")
    
    # TDS头部: [类型1字节][状态1字节][长度2字节][SPID2字节][包ID1字节][窗口1字节]
    s_byte(0x12, name="packet_type")  # Pre-Login
    s_byte(0x01, name="status")       # EOM (End of Message)
    s_word(0x0000, endian=">", name="length")  # 会被自动计算
    s_word(0x0000, endian=">", name="spid")    # Server Process ID
    s_byte(0x00, name="packet_id")
    s_byte(0x00, name="window")
    
    # Pre-Login选项
    # 版本选项
    s_byte(0x00, name="version_option")  # VERSION
    s_word(0x0015, endian=">", name="version_offset")  # 偏移
    s_word(0x0006, endian=">", name="version_length")  # 长度
    
    # 加密选项
    s_byte(0x01, name="encryption_option")  # ENCRYPTION
    s_word(0x001B, endian=">", name="encryption_offset")
    s_word(0x0001, endian=">", name="encryption_length")
    
    # 结束标记
    s_byte(0xFF, name="terminator")
    
    # 版本数据 (6字节)
    s_dword(0x09000000, endian=">", name="version_major")  # 版本号
    s_word(0x0000, endian=">", name="version_minor")
    
    # 加密数据 (1字节)
    s_byte(0x00, name="encryption_not_supported")  # 不支持加密
    
    requests.append(s_get("MSSQL_PRELOGIN"))
    
    # 2. 登录包 (Login7 Packet)
    s_initialize("MSSQL_LOGIN")
    
    s_byte(0x10, name="packet_type")  # Login7
    s_byte(0x01, name="status")
    s_size("login_data", length=2, endian=">")
    s_word(0x0000, endian=">", name="spid")
    s_byte(0x01, name="packet_id")
    s_byte(0x00, name="window")
    
    s_block_start("login_data")
    
    # Login7固定头部
    s_dword(0x00000000, endian="<", name="length")  # 总长度
    s_dword(0x71000001, endian="<", name="tds_version")  # TDS 7.1
    s_dword(0x00000800, endian="<", name="packet_size")  # 包大小
    s_dword(0x09000000, endian="<", name="client_version")  # 客户端版本
    s_dword(0x00000000, endian="<", name="client_pid")  # 进程ID
    s_dword(0x00000000, endian="<", name="connection_id")  # 连接ID
    
    # 选项标志
    s_byte(0xE0, name="option_flags1")  # 各种选项
    s_byte(0x03, name="option_flags2")
    s_byte(0x00, name="type_flags")
    s_byte(0x00, name="option_flags3")
    
    # 时区和排序规则
    s_dword(0x00000000, endian="<", name="client_timezone")
    s_dword(0x00000000, endian="<", name="client_lcid")
    
    # 偏移量和长度 (各字段的位置信息)
    s_word(0x005E, endian="<", name="hostname_offset")
    s_word(0x0000, endian="<", name="hostname_length")
    s_word(0x005E, endian="<", name="username_offset")
    s_word(0x0004, endian="<", name="username_length")  # 用户名长度
    s_word(0x0066, endian="<", name="password_offset")
    s_word(0x0004, endian="<", name="password_length")  # 密码长度
    s_word(0x006E, endian="<", name="appname_offset")
    s_word(0x0000, endian="<", name="appname_length")
    s_word(0x006E, endian="<", name="servername_offset")
    s_word(0x0000, endian="<", name="servername_length")
    s_word(0x006E, endian="<", name="extension_offset")
    s_word(0x0000, endian="<", name="extension_length")
    s_word(0x006E, endian="<", name="ctlintname_offset")
    s_word(0x0000, endian="<", name="ctlintname_length")
    s_word(0x006E, endian="<", name="language_offset")
    s_word(0x0000, endian="<", name="language_length")
    s_word(0x006E, endian="<", name="database_offset")
    s_word(0x0004, endian="<", name="database_length")  # 数据库名长度
    
    # 客户端MAC地址 (6字节)
    s_bytes(b'\x00\x00\x00\x00\x00\x00', name="client_id")
    
    # SSPI相关
    s_word(0x0076, endian="<", name="sspi_offset")
    s_word(0x0000, endian="<", name="sspi_length")
    s_word(0x0076, endian="<", name="atchdbfile_offset")
    s_word(0x0000, endian="<", name="atchdbfile_length")
    
    # 变长数据
    # 用户名 (Unicode, 8字节 = "test")
    usernames = ["test", "sa", "admin", "user"] + symbolic_databases[:5]
    for username in usernames[:1]:  # 只用第一个作为默认
        s_bytes(username.encode('utf-16le'), name="username_data")
        break
    
    # 密码 (Unicode, 8字节 = "pass")  
    s_bytes("pass".encode('utf-16le'), name="password_data")
    
    # 数据库名 (Unicode, 8字节 = "test")
    databases = ["master", "tempdb", "msdb"] + symbolic_databases[:3]
    for database in databases[:1]:  # 只用第一个作为默认
        s_bytes(database.encode('utf-16le'), name="database_data")
        break
    
    s_block_end("login_data")
    
    requests.append(s_get("MSSQL_LOGIN"))
    
    # 3. SQL批处理包 (SQL Batch)
    s_initialize("MSSQL_SQLBATCH")
    
    s_byte(0x01, name="packet_type")  # SQL Batch
    s_byte(0x01, name="status")
    s_size("sql_data", length=2, endian=">")
    s_word(0x0000, endian=">", name="spid")
    s_byte(0x01, name="packet_id")
    s_byte(0x00, name="window")
    
    s_block_start("sql_data")
    
    # SQL查询 (Unicode编码)
    sql_queries = [
        "SELECT @@VERSION",
        "SELECT SYSTEM_USER",
        "SELECT DB_NAME()",
        "SELECT COUNT(*) FROM sysobjects",
        "EXEC sp_helpdb"
    ] + symbolic_queries[:10]
    
    s_group("sql_query_text", values=sql_queries)
    
    s_block_end("sql_data")
    
    requests.append(s_get("MSSQL_SQLBATCH"))
    
    # 4. 存储过程调用
    s_initialize("MSSQL_RPC")
    
    s_byte(0x03, name="packet_type")  # RPC Request
    s_byte(0x01, name="status")
    s_size("rpc_data", length=2, endian=">")
    s_word(0x0000, endian=">", name="spid")
    s_byte(0x01, name="packet_id")
    s_byte(0x00, name="window")
    
    s_block_start("rpc_data")
    
    # 存储过程名长度和名称
    procedures = [
        "sp_help",
        "sp_helpdb", 
        "sp_who",
        "sp_configure",
        "xp_cmdshell"
    ] + symbolic_procedures[:5]
    
    s_group("procedure_name", values=procedures)
    
    # 参数标志
    s_word(0x0000, endian="<", name="parameter_flags")
    
    s_block_end("rpc_data")
    
    requests.append(s_get("MSSQL_RPC"))
    
    # 5. 危险查询测试
    s_initialize("MSSQL_DANGEROUS")
    
    s_byte(0x01, name="packet_type")
    s_byte(0x01, name="status")
    s_size("dangerous_data", length=2, endian=">")
    s_word(0x0000, endian=">", name="spid")
    s_byte(0x01, name="packet_id")
    s_byte(0x00, name="window")
    
    s_block_start("dangerous_data")
    
    dangerous_queries = [
        "SELECT * FROM sys.databases",
        "SELECT * FROM sys.tables",
        "EXEC xp_cmdshell 'whoami'",
        "SELECT * FROM sys.sql_logins",
        "BACKUP DATABASE master TO DISK='C:\\temp\\backup.bak'",
        "'; DROP TABLE test; --"
    ] + [q for q in symbolic_queries if any(keyword in q.upper() for keyword in ['XP_', 'DROP', 'EXEC', 'BACKUP'])]
    
    s_group("dangerous_query", values=dangerous_queries[:10])
    
    s_block_end("dangerous_data")
    
    requests.append(s_get("MSSQL_DANGEROUS"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description="Enhanced MSSQL Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 1433)", nargs='?', default=1433)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26004, help="Web interface port")
    parser.add_argument("--username", default="sa", help="MSSQL username")
    parser.add_argument("--database", default="master", help="Target database")
    
    args = parser.parse_args()
    
    print("Enhanced MSSQL Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Username: {args.username}")
    print(f"Database: {args.database}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("Dry run mode - testing request generation...")
        requests = create_mssql_requests()
        print(f"Successfully created {len(requests)} MSSQL request templates")
        
        for i, req in enumerate(requests):
            print(f"\nRequest {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # TDS协议是二进制的，显示十六进制
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
    
    # 创建MSSQL请求
    requests = create_mssql_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(request)
    
    print("Starting MSSQL protocol fuzzing...")
    print(f"Monitor: http://localhost:{args.web_port}")
    print("WARNING: this will perform potentially dangerous operations against the target MSSQL server!")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
    except Exception as e:
        print(f"\nError during fuzzing: {e}")
    finally:
        try:
            save_ai_learning_data("mssql")
        except Exception:
            pass
        print("MSSQL fuzzing completed")

if __name__ == "__main__":
    main()
