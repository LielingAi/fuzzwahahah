#!/usr/bin/env python3
"""
Enhanced Redis Protocol Fuzzer with Symbolic Execution
基于boofuzz的Redis协议模糊测试工具，集成符号执行和智能优化
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

def create_redis_requests():
    """创建增强的Redis请求模板"""
    
    print("🧠 使用AI增强生成Redis测试数据...")

    # 使用AI增强的协议数据生成
    try:
        symbolic_cmds = generate_protocol_data('redis', 'commands', 15, use_ai=True)
        symbolic_keys = generate_protocol_data('redis', 'keys', 20, use_ai=True)
        symbolic_vals = generate_protocol_data('redis', 'values', 25, use_ai=True)

        print(f"✅ AI生成了 {len(symbolic_cmds)} 个Redis命令变异")
        print(f"✅ AI生成了 {len(symbolic_keys)} 个Redis键名变异")
        print(f"✅ AI生成了 {len(symbolic_vals)} 个Redis值变异")

    except Exception as e:
        print(f"⚠️  AI数据生成失败，使用基础数据: {e}")
        # 使用基础数据作为后备
        symbolic_cmds = ["GET", "SET", "DEL", "HGET", "HSET", "EVAL", "CONFIG"]
        symbolic_keys = ["test", "user:1", "session:abc", "config:key", "data:item"]
        symbolic_vals = ["value", "123", "test_data", "{'json': 'data'}", "admin"]
    
    requests = []
    
    # Redis使用RESP协议 (Redis Serialization Protocol)
    
    # 1. 基本GET命令
    s_initialize("REDIS_GET")
    
    # RESP数组格式: *<参数数量>\r\n$<字符串长度>\r\n<字符串>\r\n
    s_string("*2\r\n")  # 2个参数
    
    # 命令参数
    s_string("$")
    s_size("get_cmd", length=1)
    s_delim("\r\n")
    s_block_start("get_cmd")
    commands = ["GET", "MGET", "HGET"] + symbolic_cmds[:5]
    s_group("command", values=commands)
    s_block_end("get_cmd")
    s_delim("\r\n")
    
    # 键名参数
    s_string("$")
    s_size("get_key", length=1) 
    s_delim("\r\n")
    s_block_start("get_key")
    keys = ["test", "user:1", "session:abc123"] + symbolic_keys[:10]
    s_group("key", values=keys)
    s_block_end("get_key")
    s_delim("\r\n")
    
    requests.append(s_get("REDIS_GET"))
    
    # 2. SET命令
    s_initialize("REDIS_SET")
    
    s_string("*3\r\n")  # 3个参数
    
    # SET命令
    s_string("$3\r\nSET\r\n")
    
    # 键名
    s_string("$")
    s_size("set_key", length=1)
    s_delim("\r\n")
    s_block_start("set_key")
    s_group("key", values=symbolic_keys[:15])
    s_block_end("set_key")
    s_delim("\r\n")
    
    # 值
    s_string("$")
    s_size("set_value", length=2)
    s_delim("\r\n")
    s_block_start("set_value")
    values = ["test_value", "123", "{'json': 'data'}"] + symbolic_vals[:15]
    s_group("value", values=values)
    s_block_end("set_value")
    s_delim("\r\n")
    
    requests.append(s_get("REDIS_SET"))
    
    # 3. HSET命令 (哈希表)
    s_initialize("REDIS_HSET")
    
    s_string("*4\r\n")  # 4个参数
    
    # HSET命令
    s_string("$4\r\nHSET\r\n")
    
    # 哈希表名
    s_string("$")
    s_size("hash_name", length=1)
    s_delim("\r\n")
    s_block_start("hash_name")
    hash_names = ["user", "session", "config"] + symbolic_keys[:5]
    s_group("hash", values=hash_names)
    s_block_end("hash_name")
    s_delim("\r\n")
    
    # 字段名
    s_string("$")
    s_size("field_name", length=1)
    s_delim("\r\n")
    s_block_start("field_name")
    fields = ["name", "email", "password"] + symbolic_keys[:8]
    s_group("field", values=fields)
    s_block_end("field_name")
    s_delim("\r\n")
    
    # 字段值
    s_string("$")
    s_size("field_value", length=2)
    s_delim("\r\n")
    s_block_start("field_value")
    s_group("value", values=symbolic_vals[:12])
    s_block_end("field_value")
    s_delim("\r\n")
    
    requests.append(s_get("REDIS_HSET"))
    
    # 4. DEL命令
    s_initialize("REDIS_DEL")
    
    s_string("*2\r\n")
    s_string("$3\r\nDEL\r\n")
    
    s_string("$")
    s_size("del_key", length=1)
    s_delim("\r\n")
    s_block_start("del_key")
    s_group("key", values=symbolic_keys[:10])
    s_block_end("del_key")
    s_delim("\r\n")
    
    requests.append(s_get("REDIS_DEL"))
    
    # 5. EVAL命令 (Lua脚本) - 高风险测试
    s_initialize("REDIS_EVAL")
    
    s_string("*3\r\n")  # 3个参数
    
    # EVAL命令
    s_string("$4\r\nEVAL\r\n")
    
    # Lua脚本
    s_string("$")
    s_size("lua_script", length=2)
    s_delim("\r\n")
    s_block_start("lua_script")
    scripts = [
        "return 1",
        "return redis.call('get', 'test')",
        "return KEYS[1]"
    ] + ["return 2", "return redis.call('ping')", "return 'hello'"]
    s_group("script", values=scripts)
    s_block_end("lua_script")
    s_delim("\r\n")
    
    # 键数量
    s_string("$1\r\n0\r\n")
    
    requests.append(s_get("REDIS_EVAL"))
    
    # 6. INFO命令
    s_initialize("REDIS_INFO")
    
    s_string("*1\r\n")
    s_string("$4\r\nINFO\r\n")
    
    requests.append(s_get("REDIS_INFO"))
    
    # 7. CONFIG命令 - 敏感操作
    s_initialize("REDIS_CONFIG")
    
    s_string("*3\r\n")
    
    # CONFIG命令
    s_string("$6\r\nCONFIG\r\n")
    
    # 子命令
    s_string("$")
    s_size("config_cmd", length=1)
    s_delim("\r\n")
    s_block_start("config_cmd")
    config_cmds = ["GET", "SET", "RESETSTAT"] + symbolic_cmds[:3]
    s_group("subcmd", values=config_cmds)
    s_block_end("config_cmd")
    s_delim("\r\n")
    
    # 配置参数
    s_string("$")
    s_size("config_param", length=1)
    s_delim("\r\n")
    s_block_start("config_param")
    params = ["*", "save", "maxmemory"] + symbolic_keys[:5]
    s_group("param", values=params)
    s_block_end("config_param")
    s_delim("\r\n")
    
    requests.append(s_get("REDIS_CONFIG"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description="Enhanced Redis Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 6379)", nargs='?', default=6379)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26002, help="Web interface port")
    parser.add_argument("--auth", help="Redis AUTH password")
    
    args = parser.parse_args()
    
    print("🔴 Enhanced Redis Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Auth: {'Yes' if args.auth else 'No'}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("🧪 Dry run mode - testing request generation...")
        requests = create_redis_requests()
        print(f"✅ Successfully created {len(requests)} Redis request templates")
        
        for i, req in enumerate(requests):
            print(f"\n📋 Request {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                print(f"   Preview: {rendered[:100]}")
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
                proto="tcp",
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
    
    # 如果需要认证，先发送AUTH命令
    if args.auth:
        s_initialize("REDIS_AUTH")
        s_string(f"*2\r\n$4\r\nAUTH\r\n${len(args.auth)}\r\n{args.auth}\r\n")
        session.connect(s_get("target"), s_get("REDIS_AUTH"))
    
    # 创建Redis请求
    requests = create_redis_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(s_get("target"), request)
    
    print(f"🚀 开始Redis协议模糊测试...")
    print(f"📊 监控界面: http://localhost:{args.web_port}")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\n⏹️  用户中断测试")
    except Exception as e:
        print(f"\n❌ 测试过程中出现错误: {e}")
    finally:
        print("🏁 Redis模糊测试完成")

if __name__ == "__main__":
    main()
