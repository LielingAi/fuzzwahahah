#!/usr/bin/env python3
"""
Enhanced RDP Protocol Fuzzer with Symbolic Execution
基于boofuzz的RDP协议模糊测试工具，集成符号执行和智能优化
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

def create_rdp_requests():
    """创建增强的RDP请求模板"""
    
    
    print("Using AI to generate RDP test data...")
    
    # 使用AI增强的协议数据生成
    try:
        symbolic_usernames = generate_protocol_data('rdp', 'usernames', 15, use_ai=True)
        symbolic_passwords = generate_protocol_data('rdp', 'passwords', 12, use_ai=True)
        symbolic_channels = generate_protocol_data('rdp', 'channels', 10, use_ai=True)

        print(f"AI generated {len(symbolic_usernames)} RDP username variants")
        print(f"AI generated {len(symbolic_passwords)} RDP password variants")
        print(f"AI generated {len(symbolic_channels)} RDP channel variants")

    except Exception as e:
        print(f"AI data generation failed, using base data: {e}")
        # 使用基础数据作为后备
        symbolic_usernames = ['administrator', 'admin', 'user', 'guest', 'test']
        symbolic_passwords = ['password', 'admin', '123456', 'Password123']
        symbolic_channels = ['rdpdr', 'cliprdr', 'rdpsnd', 'drdynvc']
    
    requests = []
    
    # RDP协议基于X.224和T.125标准
    
    # 1. X.224 连接请求 (Connection Request)
    s_initialize("RDP_X224_CONNECTION_REQUEST")
    
    # TPKT头部 (4字节)
    s_byte(0x03, name="tpkt_version")      # TPKT版本
    s_byte(0x00, name="tpkt_reserved")     # 保留字段
    s_size("x224_data", length=2, endian=">", name="tpkt_length")  # 总长度
    
    s_block_start("x224_data")
    
    # X.224头部
    s_byte(0x0E, name="x224_length")       # X.224头部长度
    s_byte(0xE0, name="x224_pdu_type")     # PDU类型: Connection Request
    s_word(0x0000, endian=">", name="dst_ref")  # 目标参考
    s_word(0x0000, endian=">", name="src_ref")  # 源参考
    s_byte(0x00, name="class_option")      # 类和选项
    
    # RDP协商请求 (RDP Negotiation Request)
    s_byte(0x01, name="rdp_neg_type")      # 类型: RDP_NEG_REQ
    s_byte(0x00, name="rdp_neg_flags")     # 标志
    s_word(0x0008, endian="<", name="rdp_neg_length")  # 长度
    
    # 请求的协议 - 转换为字节
    protocols = [
        0x00000000,  # RDP
        0x00000001,  # SSL
        0x00000002,  # CredSSP
        0x00000003   # SSL + CredSSP
    ]
    protocol_bytes = [struct.pack("<L", proto) for proto in protocols]
    s_group("requested_protocols", values=protocol_bytes)
    
    s_block_end("x224_data")
    
    requests.append(s_get("RDP_X224_CONNECTION_REQUEST"))
    
    # 2. MCS连接初始化 (MCS Connect Initial)
    s_initialize("RDP_MCS_CONNECT_INITIAL")
    
    # TPKT头部
    s_byte(0x03, name="tpkt_version")
    s_byte(0x00, name="tpkt_reserved")
    s_size("mcs_data", length=2, endian=">")
    
    s_block_start("mcs_data")
    
    # X.224数据PDU
    s_byte(0x02, name="x224_length")       # 长度
    s_byte(0xF0, name="x224_pdu_type")     # Data PDU
    s_byte(0x80, name="eot_flag")          # End of transmission
    
    # MCS Connect Initial PDU (BER编码)
    s_byte(0x7F, name="ber_tag")           # BER标签
    s_byte(0x65, name="ber_length_form")   # 长度形式
    
    # MCS PDU内容
    s_byte(0x82, name="mcs_tag")           # MCS Connect Initial
    s_size("mcs_content", length=2, endian=">")
    
    s_block_start("mcs_content")
    
    # 调用域
    s_byte(0x04, name="calling_domain_tag")
    s_byte(0x01, name="calling_domain_length")
    s_byte(0x01, name="calling_domain_value")
    
    # 被调用域
    s_byte(0x04, name="called_domain_tag")
    s_byte(0x01, name="called_domain_length")
    s_byte(0x01, name="called_domain_value")
    
    # 上行标志
    s_byte(0x01, name="upward_flag_tag")
    s_byte(0x01, name="upward_flag_length")
    s_byte(0xFF, name="upward_flag_value")
    
    # 目标参数
    s_byte(0x30, name="target_params_tag")
    s_byte(0x19, name="target_params_length")
    
    # 最大通道数
    s_byte(0x02, name="max_channels_tag")
    s_byte(0x01, name="max_channels_length")
    s_byte(0x22, name="max_channels_value")  # 34个通道
    
    # 最大用户数
    s_byte(0x02, name="max_users_tag")
    s_byte(0x01, name="max_users_length")
    s_byte(0x02, name="max_users_value")
    
    # 最大令牌数
    s_byte(0x02, name="max_tokens_tag")
    s_byte(0x01, name="max_tokens_length")
    s_byte(0x00, name="max_tokens_value")
    
    # 用户数据
    s_byte(0x04, name="user_data_tag")
    s_size("user_data_content", length=1)
    
    s_block_start("user_data_content")
    
    # 客户端核心数据
    s_word(0x01C0, endian="<", name="cs_core_type")     # CS_CORE
    s_word(0x00D4, endian="<", name="cs_core_length")   # 长度
    s_dword(0x00080004, endian="<", name="version")     # RDP版本
    s_word(0x0400, endian="<", name="desktop_width")    # 桌面宽度
    s_word(0x0300, endian="<", name="desktop_height")   # 桌面高度
    s_word(0x01CA, endian="<", name="color_depth")      # 颜色深度
    s_word(0x0003, endian="<", name="sas_sequence")     # SAS序列
    s_dword(0x00000409, endian="<", name="keyboard_layout")  # 键盘布局
    s_dword(0x00000A28, endian="<", name="client_build")     # 客户端版本
    
    # 客户端名称 (32字节，Unicode)
    client_names = ["DESKTOP-TEST", "WORKSTATION", "CLIENT"] + symbolic_usernames[:3]
    for name in client_names[:1]:
        client_name_bytes = name.encode('utf-16le')[:30]  # 限制长度
        client_name_bytes += b'\x00' * (32 - len(client_name_bytes))  # 填充到32字节
        s_bytes(client_name_bytes, name="client_name")
        break
    
    s_block_end("user_data_content")
    s_block_end("mcs_content")
    s_block_end("mcs_data")
    
    requests.append(s_get("RDP_MCS_CONNECT_INITIAL"))
    
    # 3. 通道加入请求 (Channel Join Request)
    s_initialize("RDP_CHANNEL_JOIN")
    
    s_byte(0x03, name="tpkt_version")
    s_byte(0x00, name="tpkt_reserved")
    s_size("channel_data", length=2, endian=">")
    
    s_block_start("channel_data")
    
    s_byte(0x02, name="x224_length")
    s_byte(0xF0, name="x224_pdu_type")
    s_byte(0x80, name="eot_flag")
    
    # MCS Channel Join Request
    s_byte(0x38, name="mcs_channel_join")  # Channel Join Request
    s_word(0x1001, endian=">", name="user_id")      # 用户ID
    
    # 通道ID - 转换为字节
    channel_ids = [
        0x03EA,  # 全局通道
        0x03EB,  # 用户通道
        0x03EC,  # I/O通道
        0x03ED   # 虚拟通道
    ]
    channel_id_bytes = [struct.pack(">H", cid) for cid in channel_ids]
    s_group("channel_id", values=channel_id_bytes)
    
    s_block_end("channel_data")
    
    requests.append(s_get("RDP_CHANNEL_JOIN"))
    
    # 4. 安全交换 (Security Exchange)
    s_initialize("RDP_SECURITY_EXCHANGE")
    
    s_byte(0x03, name="tpkt_version")
    s_byte(0x00, name="tpkt_reserved")
    s_size("security_data", length=2, endian=">")
    
    s_block_start("security_data")
    
    s_byte(0x02, name="x224_length")
    s_byte(0xF0, name="x224_pdu_type")
    s_byte(0x80, name="eot_flag")
    
    # MCS Send Data Request
    s_byte(0x64, name="mcs_send_data")
    s_word(0x1001, endian=">", name="user_id")
    s_word(0x03EA, endian=">", name="channel_id")
    s_byte(0x70, name="data_priority")
    s_byte(0x80, name="segmentation")
    
    # RDP安全头部
    s_word(0x0000, endian="<", name="flags")
    s_word(0x0000, endian="<", name="flag_hi")
    
    # 客户端随机数 (64字节)
    s_random("client_random", min_length=64, max_length=64)
    
    s_block_end("security_data")
    
    requests.append(s_get("RDP_SECURITY_EXCHANGE"))
    
    # 5. 客户端信息 (Client Info)
    s_initialize("RDP_CLIENT_INFO")
    
    s_byte(0x03, name="tpkt_version")
    s_byte(0x00, name="tpkt_reserved")
    s_size("client_info_data", length=2, endian=">")
    
    s_block_start("client_info_data")
    
    s_byte(0x02, name="x224_length")
    s_byte(0xF0, name="x224_pdu_type")
    s_byte(0x80, name="eot_flag")
    
    # MCS Send Data Request
    s_byte(0x64, name="mcs_send_data")
    s_word(0x1001, endian=">", name="user_id")
    s_word(0x03EA, endian=">", name="channel_id")
    s_byte(0x70, name="data_priority")
    s_byte(0x80, name="segmentation")
    
    # RDP安全头部
    s_word(0x0048, endian="<", name="flags")  # SEC_INFO_PKT
    s_word(0x0000, endian="<", name="flag_hi")
    
    # 客户端信息PDU
    s_dword(0x00000000, endian="<", name="code_page")
    s_dword(0x00000000, endian="<", name="flags_info")
    
    # 域名长度和域名
    s_word(0x0000, endian="<", name="domain_length")
    
    # 用户名长度和用户名
    username_length = len(symbolic_usernames[0]) * 2 if symbolic_usernames else 24  # Unicode长度
    s_word(username_length, endian="<", name="username_length")
    
    # 密码长度和密码
    password_length = len(symbolic_passwords[0]) * 2 if symbolic_passwords else 16
    s_word(password_length, endian="<", name="password_length")
    
    # 实际的用户名和密码数据 (Unicode)
    if symbolic_usernames:
        s_bytes(symbolic_usernames[0].encode('utf-16le'), name="username_data")
    else:
        s_bytes("administrator".encode('utf-16le'), name="username_data")
        
    if symbolic_passwords:
        s_bytes(symbolic_passwords[0].encode('utf-16le'), name="password_data")
    else:
        s_bytes("password".encode('utf-16le'), name="password_data")
    
    s_block_end("client_info_data")
    
    requests.append(s_get("RDP_CLIENT_INFO"))
    
    # 6. 虚拟通道数据 (Virtual Channel Data)
    s_initialize("RDP_VIRTUAL_CHANNEL")
    
    s_byte(0x03, name="tpkt_version")
    s_byte(0x00, name="tpkt_reserved")
    s_size("vchannel_data", length=2, endian=">")
    
    s_block_start("vchannel_data")
    
    s_byte(0x02, name="x224_length")
    s_byte(0xF0, name="x224_pdu_type")
    s_byte(0x80, name="eot_flag")
    
    # MCS Send Data Request
    s_byte(0x64, name="mcs_send_data")
    s_word(0x1001, endian=">", name="user_id")
    s_word(0x03ED, endian=">", name="vchannel_id")  # 虚拟通道ID
    s_byte(0x70, name="data_priority")
    s_byte(0x80, name="segmentation")
    
    # 虚拟通道数据
    s_dword(0x00000020, endian="<", name="total_length")
    s_dword(0x00000001, endian="<", name="flags")
    
    # 通道特定数据
    channel_data_samples = [
        b"CLIPRDR_FORMAT_LIST",
        b"RDPDR_CTYP_CORE", 
        b"RDPSND_CTYP_AUDIO"
    ] + [name.encode('ascii') for name in symbolic_channels[:3]]
    
    s_group("channel_specific_data", values=channel_data_samples)
    
    s_block_end("vchannel_data")
    
    requests.append(s_get("RDP_VIRTUAL_CHANNEL"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description="Enhanced RDP Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 3389)", nargs='?', default=3389)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26005, help="Web interface port")
    parser.add_argument("--username", default="administrator", help="RDP username")
    parser.add_argument("--domain", default="", help="Domain name")
    
    args = parser.parse_args()
    
    print("Enhanced RDP Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Username: {args.username}")
    print(f"Domain: {args.domain if args.domain else 'None'}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("Dry run mode - testing request generation...")
        requests = create_rdp_requests()
        print(f"Successfully created {len(requests)} RDP request templates")
        
        for i, req in enumerate(requests):
            print(f"\nRequest {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # RDP协议是二进制的，显示十六进制
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
    
    # 创建RDP请求
    requests = create_rdp_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(request)
    
    print("Starting RDP protocol fuzzing...")
    print(f"Monitor: http://localhost:{args.web_port}")
    print("WARNING: this will perform potentially dangerous operations against the target RDP server!")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
    except Exception as e:
        print(f"\nError during fuzzing: {e}")
    finally:
        try:
            save_ai_learning_data("rdp")
        except Exception:
            pass
        print("RDP fuzzing completed")

if __name__ == "__main__":
    main()
