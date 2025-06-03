#!/usr/bin/env python3
"""
Enhanced DNS Protocol Fuzzer with Symbolic Execution
基于boofuzz的DNS协议模糊测试工具，集成符号执行和智能优化
"""

import sys
import time
import argparse
import struct
from boofuzz import *
from boofuzz.utils.enhanced_symbolic_execution import (
    generate_protocol_data, 
    learn_from_test_result,
    save_ai_learning_data
)

def create_dns_requests():
    """创建增强的DNS请求模板"""

    # 初始化符号执行引擎
    

    print("🧠 使用AI增强生成DNS测试数据...")

    # 使用AI增强的协议数据生成
    try:
        symbolic_domain_names = generate_protocol_data('dns', 'domains', 15, use_ai=True)
        symbolic_query_types = generate_protocol_data('dns', 'qtypes', 10, use_ai=True)

        print(f"✅ AI生成了 {len(symbolic_domain_names)} 个DNS域名变异")
        print(f"✅ AI生成了 {len(symbolic_query_types)} 个DNS查询类型变异")

    except Exception as e:
        print(f"⚠️  AI数据生成失败，使用基础数据: {e}")
        # 使用基础数据作为后备
        symbolic_domain_names = [
            "test.com", "example.org", "malicious.evil", "localhost.local",
            "very-long-domain-name-for-testing.com", "sub.domain.test.local",
            "xss-test.com", "sql-injection.test"
        ]
        symbolic_query_types = [1, 2, 5, 6, 12, 15, 16, 28, 33, 255]
    
    requests = []
    
    # DNS协议结构: [头部12字节][问题部分][答案部分][权威部分][附加部分]
    
    # 1. 标准DNS查询 (A记录)
    s_initialize("DNS_QUERY_A")
    
    # DNS头部 (12字节)
    s_word(0x1234, endian=">", name="transaction_id")  # 事务ID
    
    # 标志字段
    s_bit_field(0, width=1, name="qr")          # 查询/响应标志 (0=查询)
    s_bit_field(0, width=4, name="opcode")      # 操作码 (0=标准查询)
    s_bit_field(0, width=1, name="aa")          # 权威答案
    s_bit_field(0, width=1, name="tc")          # 截断标志
    s_bit_field(1, width=1, name="rd")          # 期望递归
    s_bit_field(0, width=1, name="ra")          # 递归可用
    s_bit_field(0, width=3, name="z")           # 保留字段
    s_bit_field(0, width=4, name="rcode")       # 响应码
    
    s_word(0x0001, endian=">", name="qdcount")  # 问题数量
    s_word(0x0000, endian=">", name="ancount")  # 答案数量
    s_word(0x0000, endian=">", name="nscount")  # 权威记录数量
    s_word(0x0000, endian=">", name="arcount")  # 附加记录数量
    
    # 问题部分
    # 域名 (标签格式) - 手动编码
    domains = [
        "google.com",
        "example.com",
        "localhost",
        "test.local"
    ] + symbolic_domain_names[:10]

    # 编码域名并使用s_group
    encoded_domains = [encode_dns_name(domain) for domain in domains]
    s_group("domain_name", values=encoded_domains)
    
    # 查询类型 (A记录 = 1)
    s_word(0x0001, endian=">", name="qtype")
    
    # 查询类 (IN = 1)
    s_word(0x0001, endian=">", name="qclass")
    
    requests.append(s_get("DNS_QUERY_A"))
    
    # 2. DNS查询 - 多种记录类型
    s_initialize("DNS_QUERY_MULTI")
    
    # DNS头部
    s_word(0x5678, endian=">", name="transaction_id")
    s_word(0x0100, endian=">", name="flags")    # 标准查询，期望递归
    s_word(0x0001, endian=">", name="qdcount")
    s_word(0x0000, endian=">", name="ancount")
    s_word(0x0000, endian=">", name="nscount")
    s_word(0x0000, endian=">", name="arcount")
    
    # 问题部分
    encoded_domains_multi = [encode_dns_name(domain) for domain in symbolic_domain_names[:8]]
    s_group("domain_name", values=encoded_domains_multi)
    
    # 不同的查询类型
    query_types = [
        1,   # A
        2,   # NS
        5,   # CNAME
        6,   # SOA
        12,  # PTR
        15,  # MX
        16,  # TXT
        28,  # AAAA
        33,  # SRV
        255  # ANY
    ] + [t for t in symbolic_query_types if isinstance(t, int)][:5]

    # 将整数转换为2字节大端序字节
    query_type_bytes = [struct.pack(">H", qtype) for qtype in query_types]
    s_group("qtype", values=query_type_bytes)
    s_word(0x0001, endian=">", name="qclass")
    
    requests.append(s_get("DNS_QUERY_MULTI"))
    
    # 3. DNS响应包 (用于DNS投毒测试)
    s_initialize("DNS_RESPONSE")
    
    # DNS头部 - 响应
    s_word(0x1234, endian=">", name="transaction_id")
    s_word(0x8180, endian=">", name="flags")    # 响应，递归可用
    s_word(0x0001, endian=">", name="qdcount")
    s_word(0x0001, endian=">", name="ancount")  # 1个答案
    s_word(0x0000, endian=">", name="nscount")
    s_word(0x0000, endian=">", name="arcount")
    
    # 问题部分 (重复查询)
    s_string(encode_dns_name("example.com"), name="query_domain")
    s_word(0x0001, endian=">", name="qtype")
    s_word(0x0001, endian=">", name="qclass")
    
    # 答案部分
    s_string(encode_dns_name("example.com"), name="answer_domain")
    s_word(0x0001, endian=">", name="answer_type")   # A记录
    s_word(0x0001, endian=">", name="answer_class")  # IN
    s_dword(0x00000300, endian=">", name="ttl")      # TTL = 768秒
    s_word(0x0004, endian=">", name="rdlength")      # 数据长度 = 4字节
    
    # IP地址数据
    malicious_ips = [
        b"\x7f\x00\x00\x01",  # 127.0.0.1
        b"\xc0\xa8\x01\x01",  # 192.168.1.1
        b"\x08\x08\x08\x08",  # 8.8.8.8
        b"\x01\x01\x01\x01"   # 1.1.1.1
    ]
    s_group("ip_address", values=malicious_ips)
    
    requests.append(s_get("DNS_RESPONSE"))
    
    # 4. DNS区域传输请求 (AXFR)
    s_initialize("DNS_AXFR")
    
    s_word(0x9ABC, endian=">", name="transaction_id")
    s_word(0x0000, endian=">", name="flags")    # 标准查询
    s_word(0x0001, endian=">", name="qdcount")
    s_word(0x0000, endian=">", name="ancount")
    s_word(0x0000, endian=">", name="nscount")
    s_word(0x0000, endian=">", name="arcount")
    
    # AXFR查询
    axfr_domains = ["example.com", "test.local"] + symbolic_domain_names[:5]
    encoded_axfr_domains = [encode_dns_name(domain) for domain in axfr_domains]
    s_group("domain_name", values=encoded_axfr_domains)
    s_word(0x00FC, endian=">", name="qtype")    # AXFR = 252
    s_word(0x0001, endian=">", name="qclass")
    
    requests.append(s_get("DNS_AXFR"))
    
    # 5. DNS更新请求 (RFC 2136)
    s_initialize("DNS_UPDATE")
    
    s_word(0xDEF0, endian=">", name="transaction_id")
    s_word(0x2800, endian=">", name="flags")    # 更新操作
    s_word(0x0001, endian=">", name="zocount")  # 区域数量
    s_word(0x0001, endian=">", name="prcount")  # 先决条件数量
    s_word(0x0001, endian=">", name="upcount")  # 更新数量
    s_word(0x0000, endian=">", name="adcount")  # 附加数量
    
    # 区域部分
    s_string(encode_dns_name("example.com"), name="zone_name")
    s_word(0x0006, endian=">", name="zone_type")   # SOA
    s_word(0x0001, endian=">", name="zone_class")
    
    # 先决条件部分
    s_string(encode_dns_name("test.example.com"), name="prereq_name")
    s_word(0x0001, endian=">", name="prereq_type")   # A
    s_word(0x0001, endian=">", name="prereq_class")
    s_dword(0x00000000, endian=">", name="prereq_ttl")
    s_word(0x0000, endian=">", name="prereq_rdlength")
    
    # 更新部分
    s_string(encode_dns_name("new.example.com"), name="update_name")
    s_word(0x0001, endian=">", name="update_type")   # A
    s_word(0x0001, endian=">", name="update_class")
    s_dword(0x00000E10, endian=">", name="update_ttl")  # 3600秒
    s_word(0x0004, endian=">", name="update_rdlength")
    s_bytes(b"\xc0\xa8\x01\x64", name="update_ip")  # 192.168.1.100
    
    requests.append(s_get("DNS_UPDATE"))
    
    # 6. 恶意DNS查询 (缓冲区溢出测试)
    s_initialize("DNS_MALICIOUS")

    s_word(0xEF11, endian=">", name="transaction_id")  # 修复：使用有效的十六进制值
    s_word(0x0100, endian=">", name="flags")
    s_word(0x0001, endian=">", name="qdcount")
    s_word(0x0000, endian=">", name="ancount")
    s_word(0x0000, endian=">", name="nscount")
    s_word(0x0000, endian=">", name="arcount")
    
    # 超长域名测试
    long_domains = [
        "a" * 63 + ".com",  # 最大标签长度
        "a" * 100 + ".test",  # 超长标签
        ".".join(["test"] * 50) + ".com"  # 多级域名
    ]
    
    encoded_long_domains = [encode_dns_name(domain) for domain in long_domains]
    s_group("malicious_domain", values=encoded_long_domains)
    s_word(0x0001, endian=">", name="qtype")
    s_word(0x0001, endian=">", name="qclass")
    
    requests.append(s_get("DNS_MALICIOUS"))
    
    return requests

def encode_dns_name(domain_name):
    """将域名编码为DNS格式"""
    if isinstance(domain_name, bytes):
        domain_name = domain_name.decode('utf-8', errors='ignore')
    
    parts = domain_name.split('.')
    encoded = b''
    
    for part in parts:
        if part:  # 跳过空部分
            part_bytes = part.encode('utf-8')
            if len(part_bytes) > 63:  # DNS标签最大63字节
                part_bytes = part_bytes[:63]
            encoded += bytes([len(part_bytes)]) + part_bytes
    
    encoded += b'\x00'  # 结束标记
    return encoded

def main():
    parser = argparse.ArgumentParser(description="Enhanced DNS Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 53)", nargs='?', default=53)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26009, help="Web interface port")
    parser.add_argument("--udp", action="store_true", help="Use UDP instead of TCP")
    
    args = parser.parse_args()
    
    print("🌐 Enhanced DNS Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Protocol: {'UDP' if args.udp else 'TCP'}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("🧪 Dry run mode - testing request generation...")
        requests = create_dns_requests()
        print(f"✅ Successfully created {len(requests)} DNS request templates")
        
        for i, req in enumerate(requests):
            print(f"\n📋 Request {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                hex_preview = rendered[:50].hex()
                print(f"   Hex Preview: {hex_preview}...")
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
                proto="udp" if args.udp else "tcp",
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
    
    # 创建DNS请求
    requests = create_dns_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(s_get("target"), request)
    
    print(f"🚀 开始DNS协议模糊测试...")
    print(f"📊 监控界面: http://localhost:{args.web_port}")
    print("⚠️  警告: 这将对目标DNS服务器执行潜在危险的操作!")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\n⏹️  用户中断测试")
    except Exception as e:
        print(f"\n❌ 测试过程中出现错误: {e}")
    finally:
        print("🏁 DNS模糊测试完成")

if __name__ == "__main__":
    main()
