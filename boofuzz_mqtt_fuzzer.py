#!/usr/bin/env python3
"""
MQTT Protocol Fuzzer with AI Enhancement
基于boofuzz的MQTT协议模糊测试工具，集成符号执行和智能优化
"""

import sys
import time
import argparse
import fw_vendor  # vendored boofuzz path bootstrap
from boofuzz import *
from boofuzz.utils.enhanced_symbolic_execution import (
    generate_protocol_data,
    convert_to_bytes,
    learn_from_test_result,
    save_ai_learning_data
)

def create_mqtt_requests():
    """创建增强的MQTT请求模板"""
    
    print("Generating MQTT symbolic execution data...")
    
    # 使用增强的符号执行框架生成测试数据
    symbolic_topics = generate_protocol_data('mqtt', 'topics', 10, use_ai=True)
    symbolic_messages = generate_protocol_data('mqtt', 'messages', 10, use_ai=True)
    symbolic_client_ids = generate_protocol_data('mqtt', 'client_ids', 10, use_ai=True)
    symbolic_usernames = generate_protocol_data('mqtt', 'usernames', 10, use_ai=True)
    symbolic_passwords = generate_protocol_data('mqtt', 'passwords', 10, use_ai=True)
    symbolic_protocol_names = generate_protocol_data('mqtt', 'protocol_names', 10, use_ai=True)
    
    
    print("Symbolic execution test data prepared")
    
    requests = []
    
    # 1. MQTT Connect Packet
    s_initialize("MQTT_CONNECT")
    
    s_byte(16, name="fixed_header")
    s_byte(12, name="remaining_length")
    s_word(4, name="protocol_name_length", endian="big")
    s_string("MQTT")
    s_byte(4, name="protocol_level")
    s_word(12, name="client_id_length", endian="big")
    # 使用符号执行数据
    s_group("client_id", values=symbolic_client_ids)
    # 使用符号执行数据
    s_group("username", values=symbolic_usernames)
    # 使用符号执行数据
    s_group("password", values=symbolic_passwords)
    
    
    requests.append(s_get("MQTT_CONNECT"))
    
    # 2. MQTT Publish Packet
    s_initialize("MQTT_PUBLISH")
    
    s_byte(48, name="fixed_header")
    s_byte(15, name="remaining_length")
    s_word(10, name="topic_length", endian="big")
    # 使用符号执行数据
    s_group("topic_name", values=symbolic_topics)
    # 使用符号执行数据
    s_group("payload", values=symbolic_messages)
    
    
    requests.append(s_get("MQTT_PUBLISH"))
    
    # 3. MQTT Subscribe Packet
    s_initialize("MQTT_SUBSCRIBE")
    
    s_byte(130, name="fixed_header")
    s_byte(14, name="remaining_length")
    s_word(1, name="packet_id", endian="big")
    s_word(6, name="topic_filter_length", endian="big")
    # 使用符号执行数据
    s_group("topic_filter", values=symbolic_topics)
    
    
    requests.append(s_get("MQTT_SUBSCRIBE"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description="Enhanced MQTT Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 1883)", nargs='?', default=1883)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26020, help="Web interface port")
    args = parser.parse_args()
    
    print("Enhanced MQTT Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("Dry run mode - testing request generation...")
        requests = create_mqtt_requests()
        print(f"Successfully created {len(requests)} MQTT request templates")
        
        for i, req in enumerate(requests):
            print(f"\nRequest {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # MQTT协议是二进制的，显示十六进制
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
    
    # 创建MQTT请求
    requests = create_mqtt_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(request)
    
    print("Starting MQTT protocol fuzzing...")
    print(f"Monitor: http://localhost:{args.web_port}")
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
    except Exception as e:
        print(f"\nError during fuzzing: {e}")
    finally:
        try:
            save_ai_learning_data("mqtt")
        except Exception:
            pass
        print("MQTT fuzzing completed")

if __name__ == "__main__":
    main()