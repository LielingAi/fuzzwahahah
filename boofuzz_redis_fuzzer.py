#!/usr/bin/env python3
"""
Enhanced Redis Protocol Fuzzer with Symbolic Execution
基于boofuzz的Redis协议模糊测试工具，集成符号执行和智能优化
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

def create_redis_requests():
    """创建增强的Redis请求模板 - 支持完整的Redis命令集"""

    print("Using AI to generate Redis test data...")

    # 使用AI增强的协议数据生成
    try:
        symbolic_cmds = generate_protocol_data('redis', 'commands', 15, use_ai=True)
        symbolic_keys = generate_protocol_data('redis', 'keys', 20, use_ai=True)
        symbolic_vals = generate_protocol_data('redis', 'values', 25, use_ai=True)

        print(f"AI generated {len(symbolic_cmds)} Redis command variants")
        print(f"AI generated {len(symbolic_keys)} Redis key name variants")
        print(f"AI generated {len(symbolic_vals)} Redis value variants")

    except Exception as e:
        print(f"AI data generation failed, using base data: {e}")
        # 使用基础数据作为后备
        symbolic_cmds = ["GET", "SET", "DEL", "HGET", "HSET", "EVAL", "CONFIG"]
        symbolic_keys = ["test", "user:1", "session:abc", "config:key", "data:item"]
        symbolic_vals = ["value", "123", "test_data", "{'json': 'data'}", "admin"]

    requests = []

    # Redis使用RESP协议 (Redis Serialization Protocol)
    print("Creating Redis command fuzzing templates...")
    
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

    # 8. 字符串命令 - MGET (批量获取)
    s_initialize("REDIS_MGET")

    s_string("*3\r\n")  # 可变参数数量
    s_string("$4\r\nMGET\r\n")

    # 第一个键
    s_string("$")
    s_size("mget_key1", length=1)
    s_delim("\r\n")
    s_block_start("mget_key1")
    s_group("key1", values=symbolic_keys[:8])
    s_block_end("mget_key1")
    s_delim("\r\n")

    # 第二个键
    s_string("$")
    s_size("mget_key2", length=1)
    s_delim("\r\n")
    s_block_start("mget_key2")
    s_group("key2", values=symbolic_keys[8:16])
    s_block_end("mget_key2")
    s_delim("\r\n")

    requests.append(s_get("REDIS_MGET"))

    # 9. MSET命令 (批量设置)
    s_initialize("REDIS_MSET")

    s_string("*5\r\n")  # 5个参数: MSET key1 value1 key2 value2
    s_string("$4\r\nMSET\r\n")

    # 键值对1
    s_string("$")
    s_size("mset_key1", length=1)
    s_delim("\r\n")
    s_block_start("mset_key1")
    s_group("key1", values=symbolic_keys[:5])
    s_block_end("mset_key1")
    s_delim("\r\n")

    s_string("$")
    s_size("mset_val1", length=1)
    s_delim("\r\n")
    s_block_start("mset_val1")
    s_group("val1", values=symbolic_vals[:8])
    s_block_end("mset_val1")
    s_delim("\r\n")

    # 键值对2
    s_string("$")
    s_size("mset_key2", length=1)
    s_delim("\r\n")
    s_block_start("mset_key2")
    s_group("key2", values=symbolic_keys[5:10])
    s_block_end("mset_key2")
    s_delim("\r\n")

    s_string("$")
    s_size("mset_val2", length=1)
    s_delim("\r\n")
    s_block_start("mset_val2")
    s_group("val2", values=symbolic_vals[8:16])
    s_block_end("mset_val2")
    s_delim("\r\n")

    requests.append(s_get("REDIS_MSET"))

    # 10. INCR/DECR命令 (数值操作)
    s_initialize("REDIS_INCR")

    s_string("*2\r\n")

    # 命令变异 (INCR, DECR, INCRBY, DECRBY)
    s_string("$")
    s_size("incr_cmd", length=1)
    s_delim("\r\n")
    s_block_start("incr_cmd")
    incr_cmds = ["INCR", "DECR", "INCRBY", "DECRBY", "INCRBYFLOAT"]
    s_group("incr_command", values=incr_cmds)
    s_block_end("incr_cmd")
    s_delim("\r\n")

    # 键名
    s_string("$")
    s_size("incr_key", length=1)
    s_delim("\r\n")
    s_block_start("incr_key")
    counter_keys = ["counter", "score", "visits", "count"] + symbolic_keys[:5]
    s_group("counter_key", values=counter_keys)
    s_block_end("incr_key")
    s_delim("\r\n")

    requests.append(s_get("REDIS_INCR"))

    # 11. EXPIRE命令 (过期时间设置)
    s_initialize("REDIS_EXPIRE")

    s_string("*3\r\n")

    # 命令变异
    s_string("$")
    s_size("expire_cmd", length=1)
    s_delim("\r\n")
    s_block_start("expire_cmd")
    expire_cmds = ["EXPIRE", "EXPIREAT", "PEXPIRE", "PEXPIREAT", "TTL", "PTTL", "PERSIST"]
    s_group("expire_command", values=expire_cmds)
    s_block_end("expire_cmd")
    s_delim("\r\n")

    # 键名
    s_string("$")
    s_size("expire_key", length=1)
    s_delim("\r\n")
    s_block_start("expire_key")
    s_group("expire_key_name", values=symbolic_keys[:10])
    s_block_end("expire_key")
    s_delim("\r\n")

    # 时间值
    s_string("$")
    s_size("expire_time", length=1)
    s_delim("\r\n")
    s_block_start("expire_time")
    time_values = ["60", "3600", "86400", "-1", "0", "999999999"]
    s_group("time_val", values=time_values)
    s_block_end("expire_time")
    s_delim("\r\n")

    requests.append(s_get("REDIS_EXPIRE"))

    # 12. 列表命令 - LPUSH/RPUSH
    s_initialize("REDIS_LIST_PUSH")

    s_string("*3\r\n")

    # 命令变异
    s_string("$")
    s_size("list_push_cmd", length=1)
    s_delim("\r\n")
    s_block_start("list_push_cmd")
    list_push_cmds = ["LPUSH", "RPUSH", "LPUSHX", "RPUSHX"]
    s_group("list_push_command", values=list_push_cmds)
    s_block_end("list_push_cmd")
    s_delim("\r\n")

    # 列表名
    s_string("$")
    s_size("list_name", length=1)
    s_delim("\r\n")
    s_block_start("list_name")
    list_names = ["queue", "tasks", "messages", "logs"] + symbolic_keys[:5]
    s_group("list_key", values=list_names)
    s_block_end("list_name")
    s_delim("\r\n")

    # 值
    s_string("$")
    s_size("list_value", length=1)
    s_delim("\r\n")
    s_block_start("list_value")
    s_group("list_val", values=symbolic_vals[:10])
    s_block_end("list_value")
    s_delim("\r\n")

    requests.append(s_get("REDIS_LIST_PUSH"))

    # 13. 列表命令 - LPOP/RPOP
    s_initialize("REDIS_LIST_POP")

    s_string("*2\r\n")

    # 命令变异
    s_string("$")
    s_size("list_pop_cmd", length=1)
    s_delim("\r\n")
    s_block_start("list_pop_cmd")
    list_pop_cmds = ["LPOP", "RPOP", "BLPOP", "BRPOP", "LLEN", "LINDEX"]
    s_group("list_pop_command", values=list_pop_cmds)
    s_block_end("list_pop_cmd")
    s_delim("\r\n")

    # 列表名
    s_string("$")
    s_size("list_pop_name", length=1)
    s_delim("\r\n")
    s_block_start("list_pop_name")
    s_group("list_pop_key", values=list_names)
    s_block_end("list_pop_name")
    s_delim("\r\n")

    requests.append(s_get("REDIS_LIST_POP"))

    # 14. 集合命令 - SADD/SREM
    s_initialize("REDIS_SET_OPS")

    s_string("*3\r\n")

    # 命令变异
    s_string("$")
    s_size("set_cmd", length=1)
    s_delim("\r\n")
    s_block_start("set_cmd")
    set_cmds = ["SADD", "SREM", "SISMEMBER", "SCARD", "SMEMBERS", "SPOP", "SRANDMEMBER"]
    s_group("set_command", values=set_cmds)
    s_block_end("set_cmd")
    s_delim("\r\n")

    # 集合名
    s_string("$")
    s_size("set_name", length=1)
    s_delim("\r\n")
    s_block_start("set_name")
    set_names = ["tags", "users", "permissions", "groups"] + symbolic_keys[:5]
    s_group("set_key", values=set_names)
    s_block_end("set_name")
    s_delim("\r\n")

    # 成员
    s_string("$")
    s_size("set_member", length=1)
    s_delim("\r\n")
    s_block_start("set_member")
    members = ["member1", "admin", "user", "guest"] + symbolic_vals[:8]
    s_group("set_member_val", values=members)
    s_block_end("set_member")
    s_delim("\r\n")

    requests.append(s_get("REDIS_SET_OPS"))

    # 15. 有序集合命令 - ZADD/ZREM
    s_initialize("REDIS_ZSET_OPS")

    s_string("*4\r\n")

    # 命令变异
    s_string("$")
    s_size("zset_cmd", length=1)
    s_delim("\r\n")
    s_block_start("zset_cmd")
    zset_cmds = ["ZADD", "ZREM", "ZSCORE", "ZRANK", "ZCARD", "ZCOUNT", "ZINCRBY"]
    s_group("zset_command", values=zset_cmds)
    s_block_end("zset_cmd")
    s_delim("\r\n")

    # 有序集合名
    s_string("$")
    s_size("zset_name", length=1)
    s_delim("\r\n")
    s_block_start("zset_name")
    zset_names = ["leaderboard", "scores", "ranking", "top"] + symbolic_keys[:5]
    s_group("zset_key", values=zset_names)
    s_block_end("zset_name")
    s_delim("\r\n")

    # 分数
    s_string("$")
    s_size("zset_score", length=1)
    s_delim("\r\n")
    s_block_start("zset_score")
    scores = ["1", "100", "0", "-1", "999.99", "inf", "-inf"]
    s_group("score_val", values=scores)
    s_block_end("zset_score")
    s_delim("\r\n")

    # 成员
    s_string("$")
    s_size("zset_member", length=1)
    s_delim("\r\n")
    s_block_start("zset_member")
    s_group("zset_member_val", values=members)
    s_block_end("zset_member")
    s_delim("\r\n")

    requests.append(s_get("REDIS_ZSET_OPS"))

    # 16. 发布订阅命令 - PUBLISH/SUBSCRIBE
    s_initialize("REDIS_PUBSUB")

    s_string("*3\r\n")

    # 命令变异
    s_string("$")
    s_size("pubsub_cmd", length=1)
    s_delim("\r\n")
    s_block_start("pubsub_cmd")
    pubsub_cmds = ["PUBLISH", "SUBSCRIBE", "UNSUBSCRIBE", "PSUBSCRIBE", "PUNSUBSCRIBE", "PUBSUB"]
    s_group("pubsub_command", values=pubsub_cmds)
    s_block_end("pubsub_cmd")
    s_delim("\r\n")

    # 频道名
    s_string("$")
    s_size("channel_name", length=1)
    s_delim("\r\n")
    s_block_start("channel_name")
    channels = ["news", "alerts", "chat", "notifications", "events"] + symbolic_keys[:5]
    s_group("channel", values=channels)
    s_block_end("channel_name")
    s_delim("\r\n")

    # 消息内容
    s_string("$")
    s_size("message_content", length=1)
    s_delim("\r\n")
    s_block_start("message_content")
    messages = ["hello", "test message", "alert!", "notification"] + symbolic_vals[:8]
    s_group("message", values=messages)
    s_block_end("message_content")
    s_delim("\r\n")

    requests.append(s_get("REDIS_PUBSUB"))

    # 17. 事务命令 - MULTI/EXEC
    s_initialize("REDIS_TRANSACTION")

    s_string("*1\r\n")

    # 事务命令
    s_string("$")
    s_size("trans_cmd", length=1)
    s_delim("\r\n")
    s_block_start("trans_cmd")
    trans_cmds = ["MULTI", "EXEC", "DISCARD", "WATCH", "UNWATCH"]
    s_group("transaction_command", values=trans_cmds)
    s_block_end("trans_cmd")
    s_delim("\r\n")

    requests.append(s_get("REDIS_TRANSACTION"))

    # 18. 连接命令 - PING/ECHO/SELECT
    s_initialize("REDIS_CONNECTION")

    s_string("*2\r\n")

    # 连接命令
    s_string("$")
    s_size("conn_cmd", length=1)
    s_delim("\r\n")
    s_block_start("conn_cmd")
    conn_cmds = ["PING", "ECHO", "SELECT", "QUIT", "AUTH"]
    s_group("connection_command", values=conn_cmds)
    s_block_end("conn_cmd")
    s_delim("\r\n")

    # 参数
    s_string("$")
    s_size("conn_param", length=1)
    s_delim("\r\n")
    s_block_start("conn_param")
    conn_params = ["0", "1", "15", "hello", "test"] + symbolic_vals[:5]
    s_group("conn_parameter", values=conn_params)
    s_block_end("conn_param")
    s_delim("\r\n")

    requests.append(s_get("REDIS_CONNECTION"))

    # 19. 管理命令 - FLUSHDB/FLUSHALL/SAVE
    s_initialize("REDIS_ADMIN")

    s_string("*1\r\n")

    # 管理命令 (危险操作)
    s_string("$")
    s_size("admin_cmd", length=1)
    s_delim("\r\n")
    s_block_start("admin_cmd")
    admin_cmds = ["FLUSHDB", "FLUSHALL", "SAVE", "BGSAVE", "DBSIZE", "LASTSAVE", "MONITOR", "SHUTDOWN"]
    s_group("admin_command", values=admin_cmds)
    s_block_end("admin_cmd")
    s_delim("\r\n")

    requests.append(s_get("REDIS_ADMIN"))

    # 20. 脚本命令 - EVAL/EVALSHA
    s_initialize("REDIS_SCRIPT")

    s_string("*4\r\n")

    # 脚本命令
    s_string("$")
    s_size("script_cmd", length=1)
    s_delim("\r\n")
    s_block_start("script_cmd")
    script_cmds = ["EVAL", "EVALSHA", "SCRIPT"]
    s_group("script_command", values=script_cmds)
    s_block_end("script_cmd")
    s_delim("\r\n")

    # Lua脚本或SHA1
    s_string("$")
    s_size("script_content", length=2)
    s_delim("\r\n")
    s_block_start("script_content")
    scripts = [
        "return 1",
        "return redis.call('get', KEYS[1])",
        "return redis.call('set', KEYS[1], ARGV[1])",
        "return redis.call('ping')",
        "return KEYS[1] .. ARGV[1]",
        "for i=1,10 do redis.call('set', 'key'..i, i) end",
        "return redis.call('info')"
    ] + symbolic_vals[:5]
    s_group("script", values=scripts)
    s_block_end("script_content")
    s_delim("\r\n")

    # 键数量
    s_string("$1\r\n1\r\n")

    # 键名
    s_string("$")
    s_size("script_key", length=1)
    s_delim("\r\n")
    s_block_start("script_key")
    s_group("script_key_name", values=symbolic_keys[:8])
    s_block_end("script_key")
    s_delim("\r\n")

    requests.append(s_get("REDIS_SCRIPT"))

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
    
    print("Enhanced Redis Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Auth: {'Yes' if args.auth else 'No'}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("Dry run mode - testing request generation...")
        requests = create_redis_requests()
        print(f"Successfully created {len(requests)} Redis request templates")
        
        for i, req in enumerate(requests):
            print(f"\nRequest {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                print(f"   Preview: {rendered[:100]}")
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
                # timeout=args.timeout
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
    
    # 如果需要认证，先发送AUTH命令
    if args.auth:
        s_initialize("REDIS_AUTH")
        s_string(f"*2\r\n$4\r\nAUTH\r\n${len(args.auth)}\r\n{args.auth}\r\n")
        auth_request = s_get("REDIS_AUTH")
        session.connect(auth_request)

    # 创建Redis请求
    requests = create_redis_requests()

    # 添加请求到会话
    for request in requests:
        session.connect(request)
    
    print("Starting Redis protocol fuzzing...")
    print(f"Monitor: http://localhost:{args.web_port}")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
    except Exception as e:
        print(f"\nError during fuzzing: {e}")
    finally:
        try:
            save_ai_learning_data("redis")
        except Exception:
            pass
        print("Redis fuzzing completed")

if __name__ == "__main__":
    main()
