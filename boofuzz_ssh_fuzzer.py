#!/usr/bin/env python3
"""
Enhanced SSH Protocol Fuzzer with Symbolic Execution
基于boofuzz的SSH协议模糊测试工具，集成符号执行和智能优化
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

def create_ssh_requests():
    """创建增强的SSH请求模板"""
    
    
    print("🧠 使用AI增强生成SSH测试数据...")
    
    # 使用AI增强的协议数据生成
    try:
        symbolic_versions = generate_protocol_data('ssh', 'versions', 12, use_ai=True)
        symbolic_usernames = generate_protocol_data('ssh', 'usernames', 15, use_ai=True)
        symbolic_passwords = generate_protocol_data('ssh', 'passwords', 12, use_ai=True)
        symbolic_algorithms = generate_protocol_data('ssh', 'algorithms', 10, use_ai=True)

        print(f"✅ AI生成了 {len(symbolic_versions)} 个SSH版本变异")
        print(f"✅ AI生成了 {len(symbolic_usernames)} 个SSH用户名变异")
        print(f"✅ AI生成了 {len(symbolic_passwords)} 个SSH密码变异")
        print(f"✅ AI生成了 {len(symbolic_algorithms)} 个SSH算法变异")

    except Exception as e:
        print(f"⚠️  AI数据生成失败，使用基础数据: {e}")
        # 使用基础数据作为后备
        symbolic_versions = ['SSH-2.0-OpenSSH_8.0', 'SSH-2.0-libssh_0.8.0', 'SSH-1.99-Cisco-1.25']
        symbolic_usernames = ['root', 'admin', 'user', 'guest', 'test']
        symbolic_passwords = ['password', 'admin', '123456', 'root', 'test']
        symbolic_algorithms = ['diffie-hellman-group14-sha256', 'ecdh-sha2-nistp256']
# 初始化符号执行引擎
    
    
    print("🧠 生成SSH符号执行数据...")
    
    # SSH版本字符串分析
    ssh_versions = []
    
    # SSH算法协商分析
    ssh_algorithms = []
    
    # SSH认证数据分析
    ssh_auth = []
    
    print(f"✅ 生成了 {len(ssh_versions)} 个SSH版本变异")
    print(f"✅ 生成了 {len(ssh_algorithms)} 个SSH算法变异")
    print(f"✅ 生成了 {len(ssh_auth)} 个SSH认证变异")
    
    # 使用基础测试数据
    # 使用AI增强的协议数据生成
    print("🧠 使用AI增强生成SSH测试数据...")
    
    # AI增强的数据生成将在下面的代码中使用generate_protocol_data()
    # 使用AI增强的协议数据生成
    print("🧠 使用AI增强生成SSH测试数据...")
    
    # AI增强的数据生成将在下面的代码中使用generate_protocol_data()
    # 使用AI增强的协议数据生成
    print("🧠 使用AI增强生成SSH测试数据...")
    
    # AI增强的数据生成将在下面的代码中使用generate_protocol_data()
    
    requests = []
    
    # 1. SSH版本交换
    s_initialize("SSH_VERSION_EXCHANGE")
    
    # SSH版本字符串
    version_strings = [
        "SSH-2.0-OpenSSH_8.0",
        "SSH-2.0-libssh_0.8.0",
        "SSH-1.99-Cisco-1.25",
        "SSH-2.0-PuTTY_Release_0.76"
    ] + symbolic_versions
    
    s_group("version_string", values=version_strings)
    s_delim("\r\n")
    
    requests.append(s_get("SSH_VERSION_EXCHANGE"))
    
    # 2. SSH密钥交换初始化 (SSH_MSG_KEXINIT)
    s_initialize("SSH_KEXINIT")
    
    # SSH包结构: [包长度4字节][填充长度1字节][消息类型1字节][数据][填充][MAC]
    s_size("ssh_packet", length=4, endian=">")  # 包长度
    
    s_block_start("ssh_packet")
    
    s_byte(0x00, name="padding_length")  # 填充长度
    s_byte(0x14, name="message_type")    # SSH_MSG_KEXINIT (20)
    
    # 随机数据 (16字节)
    s_random("random_data", min_length=16, max_length=16)
    
    # 密钥交换算法列表
    kex_algorithms = [
        "diffie-hellman-group14-sha256",
        "ecdh-sha2-nistp256",
        "curve25519-sha256"
    ]
    kex_list = ",".join(kex_algorithms)
    s_size("kex_algorithms", length=4, endian=">")
    s_block_start("kex_algorithms")
    s_string(kex_list)
    s_block_end("kex_algorithms")
    
    # 服务器主机密钥算法
    host_key_algorithms = [
        "rsa-sha2-512",
        "rsa-sha2-256", 
        "ssh-rsa",
        "ecdsa-sha2-nistp256"
    ]
    host_key_list = ",".join(host_key_algorithms)
    s_size("host_key_algorithms", length=4, endian=">")
    s_block_start("host_key_algorithms")
    s_string(host_key_list)
    s_block_end("host_key_algorithms")
    
    # 客户端到服务器加密算法
    encryption_c2s = [
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "chacha20-poly1305@openssh.com"
    ]
    enc_c2s_list = ",".join(encryption_c2s)
    s_size("encryption_c2s", length=4, endian=">")
    s_block_start("encryption_c2s")
    s_string(enc_c2s_list)
    s_block_end("encryption_c2s")
    
    # 服务器到客户端加密算法
    s_size("encryption_s2c", length=4, endian=">")
    s_block_start("encryption_s2c")
    s_string(enc_c2s_list)  # 通常相同
    s_block_end("encryption_s2c")
    
    # MAC算法 (客户端到服务器)
    mac_algorithms = [
        "hmac-sha2-256",
        "hmac-sha2-512",
        "umac-128@openssh.com"
    ]
    mac_list = ",".join(mac_algorithms)
    s_size("mac_c2s", length=4, endian=">")
    s_block_start("mac_c2s")
    s_string(mac_list)
    s_block_end("mac_c2s")
    
    # MAC算法 (服务器到客户端)
    s_size("mac_s2c", length=4, endian=">")
    s_block_start("mac_s2c")
    s_string(mac_list)
    s_block_end("mac_s2c")
    
    # 压缩算法
    compression = ["none", "zlib@openssh.com"]
    comp_list = ",".join(compression)
    s_size("compression_c2s", length=4, endian=">")
    s_block_start("compression_c2s")
    s_string(comp_list)
    s_block_end("compression_c2s")
    
    s_size("compression_s2c", length=4, endian=">")
    s_block_start("compression_s2c")
    s_string(comp_list)
    s_block_end("compression_s2c")
    
    # 语言标签 (通常为空)
    s_dword(0x00000000, endian=">", name="languages_c2s")
    s_dword(0x00000000, endian=">", name="languages_s2c")
    
    # 首包跟随标志和保留字段
    s_byte(0x00, name="first_kex_packet_follows")
    s_dword(0x00000000, endian=">", name="reserved")
    
    s_block_end("ssh_packet")
    
    requests.append(s_get("SSH_KEXINIT"))
    
    # 3. SSH用户认证请求 (SSH_MSG_USERAUTH_REQUEST)
    s_initialize("SSH_USERAUTH_REQUEST")
    
    s_size("auth_packet", length=4, endian=">")
    
    s_block_start("auth_packet")
    
    s_byte(0x00, name="padding_length")
    s_byte(0x32, name="message_type")  # SSH_MSG_USERAUTH_REQUEST (50)
    
    # 用户名
    s_size("username", length=4, endian=">")
    s_block_start("username")
    s_group("user", values=symbolic_usernames)
    s_block_end("username")
    
    # 服务名
    s_size("service_name", length=4, endian=">")
    s_block_start("service_name")
    s_string("ssh-connection")
    s_block_end("service_name")
    
    # 认证方法
    s_size("auth_method", length=4, endian=">")
    s_block_start("auth_method")
    auth_methods = ["password", "publickey", "keyboard-interactive", "none"]
    s_group("method", values=auth_methods)
    s_block_end("auth_method")
    
    # 密码认证数据 (如果方法是password)
    s_byte(0x00, name="change_password")  # FALSE
    s_size("password", length=4, endian=">")
    s_block_start("password")
    s_group("pass", values=symbolic_passwords)
    s_block_end("password")
    
    s_block_end("auth_packet")
    
    requests.append(s_get("SSH_USERAUTH_REQUEST"))
    
    # 4. SSH通道打开请求 (SSH_MSG_CHANNEL_OPEN)
    s_initialize("SSH_CHANNEL_OPEN")
    
    s_size("channel_packet", length=4, endian=">")
    
    s_block_start("channel_packet")
    
    s_byte(0x00, name="padding_length")
    s_byte(0x5A, name="message_type")  # SSH_MSG_CHANNEL_OPEN (90)
    
    # 通道类型
    s_size("channel_type", length=4, endian=">")
    s_block_start("channel_type")
    channel_types = ["session", "x11", "forwarded-tcpip", "direct-tcpip"]
    s_group("type", values=channel_types)
    s_block_end("channel_type")
    
    # 发送方通道号
    s_dword(0x00000000, endian=">", name="sender_channel")
    
    # 初始窗口大小
    s_dword(0x00200000, endian=">", name="initial_window_size")  # 2MB
    
    # 最大包大小
    s_dword(0x00008000, endian=">", name="maximum_packet_size")  # 32KB
    
    s_block_end("channel_packet")
    
    requests.append(s_get("SSH_CHANNEL_OPEN"))
    
    # 5. SSH执行请求 (SSH_MSG_CHANNEL_REQUEST)
    s_initialize("SSH_CHANNEL_REQUEST")
    
    s_size("exec_packet", length=4, endian=">")
    
    s_block_start("exec_packet")
    
    s_byte(0x00, name="padding_length")
    s_byte(0x62, name="message_type")  # SSH_MSG_CHANNEL_REQUEST (98)
    
    # 接收方通道号
    s_dword(0x00000000, endian=">", name="recipient_channel")
    
    # 请求类型
    s_size("request_type", length=4, endian=">")
    s_block_start("request_type")
    request_types = ["exec", "shell", "pty-req", "env", "subsystem"]
    s_group("req_type", values=request_types)
    s_block_end("request_type")
    
    # 想要回复标志
    s_byte(0x01, name="want_reply")  # TRUE
    
    # 命令 (如果是exec请求)
    s_size("command", length=4, endian=">")
    s_block_start("command")
    commands = [
        "id",
        "whoami", 
        "uname -a",
        "cat /etc/passwd",
        "ls -la"
    ]
    s_group("cmd", values=commands)
    s_block_end("command")
    
    s_block_end("exec_packet")
    
    requests.append(s_get("SSH_CHANNEL_REQUEST"))
    
    # 6. SSH数据传输 (SSH_MSG_CHANNEL_DATA)
    s_initialize("SSH_CHANNEL_DATA")
    
    s_size("data_packet", length=4, endian=">")
    
    s_block_start("data_packet")
    
    s_byte(0x00, name="padding_length")
    s_byte(0x5E, name="message_type")  # SSH_MSG_CHANNEL_DATA (94)
    
    # 接收方通道号
    s_dword(0x00000000, endian=">", name="recipient_channel")
    
    # 数据
    s_size("data", length=4, endian=">")
    s_block_start("data")
    data_samples = [
        b"echo 'Hello World'",
        b"exit",
        b"logout",
        b"\x03",  # Ctrl+C
        b"\x04"   # Ctrl+D
    ]
    s_group("payload", values=data_samples)
    s_block_end("data")
    
    s_block_end("data_packet")
    
    requests.append(s_get("SSH_CHANNEL_DATA"))
    
    return requests

def main():
    parser = argparse.ArgumentParser(description="Enhanced SSH Protocol Fuzzer")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (default: 22)", nargs='?', default=22)
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--dry-run", action="store_true", help="Test without actual fuzzing")
    parser.add_argument("--web-port", type=int, default=26006, help="Web interface port")
    parser.add_argument("--username", default="root", help="SSH username")
    
    args = parser.parse_args()
    
    print("🔐 Enhanced SSH Protocol Fuzzer")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Username: {args.username}")
    print(f"Web Interface: http://localhost:{args.web_port}")
    print()
    
    if args.dry_run:
        print("🧪 Dry run mode - testing request generation...")
        requests = create_ssh_requests()
        print(f"✅ Successfully created {len(requests)} SSH request templates")
        
        for i, req in enumerate(requests):
            print(f"\n📋 Request {i+1}: {req.name}")
            try:
                rendered = req.render()
                print(f"   Size: {len(rendered)} bytes")
                # SSH协议部分是文本，部分是二进制
                if req.name == "SSH_VERSION_EXCHANGE":
                    print(f"   Preview: {rendered.decode('utf-8', errors='ignore').strip()}")
                else:
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
    
    # 创建SSH请求
    requests = create_ssh_requests()
    
    # 添加请求到会话
    for request in requests:
        session.connect(s_get("target"), request)
    
    print(f"🚀 开始SSH协议模糊测试...")
    print(f"📊 监控界面: http://localhost:{args.web_port}")
    print("⚠️  警告: 这将对目标SSH服务器执行潜在危险的操作!")
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\n⏹️  用户中断测试")
    except Exception as e:
        print(f"\n❌ 测试过程中出现错误: {e}")
    finally:
        print("🏁 SSH模糊测试完成")

if __name__ == "__main__":
    main()
