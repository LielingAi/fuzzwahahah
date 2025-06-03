#!/usr/bin/env python3
"""
Enhanced HTTP Protocol Fuzzer with Symbolic Execution
基于boofuzz的HTTP协议模糊测试工具，集成符号执行和智能优化
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

def create_http_requests():
    """创建增强的HTTP请求模板"""
    
    # 使用AI增强的符号执行数据生成
    print("🧠 使用AI增强生成HTTP测试数据...")

    # 使用AI增强的协议数据生成
    symbolic_methods = generate_protocol_data('http', 'methods', 15, use_ai=True)
    symbolic_paths = generate_protocol_data('http', 'paths', 25, use_ai=True)
    symbolic_header_names = generate_protocol_data('http', 'headers', 20, use_ai=True)
    symbolic_header_values = generate_protocol_data('http', 'values', 30, use_ai=True)
    symbolic_param_names = generate_protocol_data('http', 'params', 15, use_ai=True)
    symbolic_param_values = generate_protocol_data('http', 'values', 25, use_ai=True)

    print(f"✅ AI生成了 {len(symbolic_methods)} 个HTTP方法变异")
    print(f"✅ AI生成了 {len(symbolic_paths)} 个HTTP路径变异")
    print(f"✅ AI生成了 {len(symbolic_header_names)} 个HTTP头部变异")
    print(f"✅ AI生成了 {len(symbolic_param_names)} 个HTTP参数变异")
    
    requests = []
    
    # 1. 基本HTTP GET请求
    s_initialize("HTTP_GET")
    
    # HTTP方法 - 使用符号执行增强
    methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"] + symbolic_methods
    s_group("method", values=methods)
    s_delim(" ")
    
    # HTTP路径 - 使用符号执行增强  
    paths = ["/", "/index.html", "/admin", "/api/v1/users"] + symbolic_paths
    s_group("path", values=paths)
    s_delim(" ")
    
    # HTTP版本
    s_string("HTTP/1.1")
    s_delim("\r\n")
    
    # Host头部
    s_string("Host: ")
    s_string("target.example.com", name="host_value")
    s_delim("\r\n")
    
    # User-Agent头部 - 使用符号执行增强
    s_string("User-Agent: ")
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "curl/7.68.0",
        "python-requests/2.25.1"
    ] + symbolic_header_values[:5]
    s_group("user_agent", values=user_agents)
    s_delim("\r\n")
    
    # 自定义头部 - 使用符号执行增强
    custom_headers = symbolic_header_names[:10]
    custom_values = symbolic_header_values[:10]
    
    for i, (header_name, header_value) in enumerate(zip(custom_headers, custom_values)):
        s_string(f"{header_name}: ")
        s_string(header_value, name=f"custom_header_{i}")
        s_delim("\r\n")
    
    s_delim("\r\n")  # 结束头部
    
    requests.append(s_get("HTTP_GET"))
    
    # 2. HTTP POST请求 - 表单数据
    s_initialize("HTTP_POST_FORM")
    
    s_group("method", values=["POST"] + [m for m in symbolic_methods if m in ["POST", "PUT", "PATCH"]])
    s_delim(" ")
    s_group("path", values=["/login", "/submit", "/api/data"] + symbolic_paths[:10])
    s_delim(" ")
    s_string("HTTP/1.1")
    s_delim("\r\n")
    
    s_string("Host: target.example.com\r\n")
    s_string("Content-Type: application/x-www-form-urlencoded\r\n")
    
    # Content-Length会自动计算
    s_string("Content-Length: ")
    s_size("post_data", length=4, endian=">")
    s_delim("\r\n\r\n")
    
    # POST数据 - 使用符号执行增强
    s_block_start("post_data")
    
    param_pairs = []
    for i, (name, value) in enumerate(zip(symbolic_param_names, symbolic_param_values)):
        if i > 0:
            s_delim("&")
        s_string(name, name=f"param_name_{i}")
        s_delim("=")
        s_string(value, name=f"param_value_{i}")
        if i >= 5:  # 限制参数数量
            break
    
    s_block_end("post_data")
    
    requests.append(s_get("HTTP_POST_FORM"))
    
    # 3. HTTP POST请求 - JSON数据
    s_initialize("HTTP_POST_JSON")
    
    s_string("POST ")
    s_group("path", values=["/api/users", "/api/login", "/graphql"] + symbolic_paths[:5])
    s_string(" HTTP/1.1\r\n")
    s_string("Host: target.example.com\r\n")
    s_string("Content-Type: application/json\r\n")
    s_string("Content-Length: ")
    s_size("json_data", length=4, endian=">")
    s_delim("\r\n\r\n")
    
    # JSON数据 - 使用符号执行增强
    s_block_start("json_data")
    s_string('{"')
    s_group("json_key", values=symbolic_param_names[:5] + ["username", "password", "email"])
    s_string('":"')
    s_group("json_value", values=symbolic_param_values[:10] + ["admin", "test123", "user@example.com"])
    s_string('"}')
    s_block_end("json_data")
    
    requests.append(s_get("HTTP_POST_JSON"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description="Enhanced HTTP Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 80)", nargs='?', default=80)
    parser.add_argument("--ssl", action="store_true", help="Use HTTPS/SSL")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26001, help="Web interface port")
    
    args = parser.parse_args()
    
    print("🌐 Enhanced HTTP Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"SSL: {'Yes' if args.ssl else 'No'}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("🧪 Dry run mode - testing request generation...")
        requests = create_http_requests()
        print(f"✅ Successfully created {len(requests)} HTTP request templates")
        
        for i, req in enumerate(requests):
            print(f"\n📋 Request {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                print(f"   Preview: {rendered[:100].decode('utf-8', errors='ignore')}...")
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
    
    # 创建HTTP请求
    requests = create_http_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(s_get("target"), request)
    
    print(f"🚀 开始HTTP协议模糊测试...")
    print(f"📊 监控界面: http://localhost:{args.web_port}")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\n⏹️  用户中断测试")
    except Exception as e:
        print(f"\n❌ 测试过程中出现错误: {e}")
    finally:
        print("🏁 HTTP模糊测试完成")

if __name__ == "__main__":
    main()
