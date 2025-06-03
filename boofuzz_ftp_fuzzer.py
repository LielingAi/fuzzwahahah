#!/usr/bin/env python3
"""
标准boofuzz FTP FUZZ工具 - 集成优化功能

这是一个严格按照boofuzz架构编写的FTP FUZZ工具，展示了：
- 标准的boofuzz Session/Target/Request架构
- 使用boofuzz的String、Static、Delim等primitives
- 自动集成我们的优化功能（通过优化的primitives）
- 标准的boofuzz工作流程

基于官方boofuzz FTP示例，但增加了更多FTP命令和优化功能。

使用方法:
    python boofuzz_ftp_fuzzer.py [target_ip] [target_port]
    
示例:
    python boofuzz_ftp_fuzzer.py 127.0.0.1 21
"""

import sys
import os
import argparse

# 添加当前目录到Python路径以便导入boofuzz
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 标准boofuzz导入 - 这是关键！
from boofuzz import *

# 导入符号执行功能
try:
    from boofuzz.utils.enhanced_symbolic_execution import (
    generate_protocol_data, 
    learn_from_test_result,
    save_ai_learning_data
)
    SYMBOLIC_EXECUTION_AVAILABLE = True
    print("✅ 符号执行模块导入成功")
except ImportError as e:
    SYMBOLIC_EXECUTION_AVAILABLE = False
    print(f"⚠️ 符号执行模块不可用: {e}")


def generate_symbolic_ftp_values():
    """
    使用AI增强的符号执行生成FTP特定的测试值
    """
    symbolic_values = {}

    if SYMBOLIC_EXECUTION_AVAILABLE:
        print("🧠 使用AI增强生成FTP测试数据...")

        try:
            # 使用AI增强的协议数据生成
            symbolic_values['usernames'] = generate_protocol_data('ftp', 'usernames', 15, use_ai=True)
            symbolic_values['passwords'] = generate_protocol_data('ftp', 'passwords', 12, use_ai=True)
            symbolic_values['commands'] = generate_protocol_data('ftp', 'commands', 20, use_ai=True)
            symbolic_values['paths'] = generate_protocol_data('ftp', 'paths', 25, use_ai=True)

            print(f"  ✅ AI生成了 {len(symbolic_values)} 类FTP测试数据")
            for key, values in symbolic_values.items():
                print(f"    • {key}: {len(values)} 个值")

        except Exception as e:
            print(f"  ⚠️ AI数据生成失败: {e}")
            # 使用基础数据作为后备
            symbolic_values = {
                'usernames': ["anonymous", "admin", "root", "ftp", "test"],
                'passwords': ["", "password", "admin", "123456", "ftp"],
                'commands': ["USER", "PASS", "LIST", "RETR", "STOR", "DELE"],
                'paths': ["/", "/etc/passwd", "../../../etc/passwd", "test.txt"]
            }
    else:
        print("⚠️ AI增强功能不可用，使用默认值")
        symbolic_values = {
            'usernames': ["anonymous", "admin", "root", "ftp", "test"],
            'passwords': ["", "password", "admin", "123456", "ftp"],
            'commands': ["USER", "PASS", "LIST", "RETR", "STOR", "DELE"],
            'paths': ["/", "/etc/passwd", "../../../etc/passwd", "test.txt"]
        }

    return symbolic_values


def define_ftp_protocol(session):
    """
    定义FTP协议 - 严格按照boofuzz模式，集成符号执行

    这个函数使用标准的boofuzz Request/String/Static/Delim架构
    来定义FTP协议。我们的优化会自动应用到String primitives上。
    符号执行会增强测试值的生成。
    """

    print("📋 定义FTP协议请求...")

    # 生成符号执行增强的测试值
    symbolic_values = generate_symbolic_ftp_values()
    
    # ===== USER 命令 =====
    # 用户认证命令，使用优化的String primitive + 符号执行增强

    # 准备用户名值（包含符号执行生成的值）
    username_values = ["anonymous", "admin", "root", "ftp", "test"]
    if symbolic_values.get('usernames'):
        username_values.extend(symbolic_values['usernames'])
        print(f"  🧠 USER命令增强: 添加了 {len(symbolic_values['usernames'])} 个符号执行用户名")

    user = Request("user", children=(
        String(name="command", default_value="USER"),      # 自动优化
        Delim(name="space", default_value=" "),
        Group(name="username", values=username_values),    # 符号执行增强的用户名
        Static(name="crlf", default_value="\r\n"),
    ))
    
    # ===== PASS 命令 =====
    # 密码认证命令
    passw = Request("pass", children=(
        String(name="command", default_value="PASS"),      # 自动优化
        Delim(name="space", default_value=" "),
        String(name="password", default_value="password"), # 自动优化
        Static(name="crlf", default_value="\r\n"),
    ))
    
    # ===== LIST 命令 =====
    # 目录列表命令
    list_cmd = Request("list", children=(
        String(name="command", default_value="LIST"),      # 自动优化
        Delim(name="space", default_value=" "),
        String(name="path", default_value=""),             # 自动优化，用于路径FUZZ
        Static(name="crlf", default_value="\r\n"),
    ))
    
    # ===== RETR 命令 =====
    # 文件下载命令，包含路径遍历测试 + 符号执行增强

    # 准备文件名值（包含符号执行生成的路径）
    filename_values = ["test.txt", "../etc/passwd", "../../windows/system32", "/etc/shadow", "config.ini"]
    if symbolic_values.get('paths'):
        filename_values.extend(symbolic_values['paths'])
        print(f"  🧠 RETR命令增强: 添加了 {len(symbolic_values['paths'])} 个符号执行路径")
    if symbolic_values.get('constraint_based'):
        filename_values.extend([v for v in symbolic_values['constraint_based'] if isinstance(v, str)])
        print(f"  🧠 RETR命令增强: 添加了约束生成的文件名")

    retr = Request("retr", children=(
        String(name="command", default_value="RETR"),      # 自动优化
        Delim(name="space", default_value=" "),
        Group(name="filename", values=filename_values),    # 符号执行增强的文件名
        Static(name="crlf", default_value="\r\n"),
    ))
    
    # ===== STOR 命令 =====
    # 文件上传命令
    stor = Request("stor", children=(
        String(name="command", default_value="STOR"),      # 自动优化
        Delim(name="space", default_value=" "),
        String(name="filename", default_value="upload.txt"), # 自动优化
        Static(name="crlf", default_value="\r\n"),
    ))
    
    # ===== CWD 命令 =====
    # 改变目录命令，用于目录遍历测试
    cwd = Request("cwd", children=(
        String(name="command", default_value="CWD"),       # 自动优化
        Delim(name="space", default_value=" "),
        String(name="directory", default_value="/home"),   # 自动优化
        Static(name="crlf", default_value="\r\n"),
    ))
    
    # ===== DELE 命令 =====
    # 删除文件命令
    dele = Request("dele", children=(
        String(name="command", default_value="DELE"),      # 自动优化
        Delim(name="space", default_value=" "),
        String(name="filename", default_value="test.txt"), # 自动优化
        Static(name="crlf", default_value="\r\n"),
    ))
    
    # ===== 缓冲区溢出测试 =====
    # 长字符串测试，用于缓冲区溢出检测
    overflow = Request("overflow", children=(
        String(name="command", default_value="USER"),      # 自动优化
        Delim(name="space", default_value=" "),
        String(name="long_data", default_value="A" * 100, max_len=5000), # 自动优化，长字符串
        Static(name="crlf", default_value="\r\n"),
    ))
    
    # ===== 连接协议流程 =====
    # 使用boofuzz的connect方法定义FTP会话流程
    print("🔗 连接FTP协议流程...")
    
    # 基本认证流程
    session.connect(user)           # 开始：USER命令
    session.connect(user, passw)    # USER -> PASS
    
    # 认证后的命令
    session.connect(passw, list_cmd) # PASS -> LIST
    session.connect(passw, retr)     # PASS -> RETR
    session.connect(passw, stor)     # PASS -> STOR
    session.connect(passw, cwd)      # PASS -> CWD
    session.connect(passw, dele)     # PASS -> DELE
    
    # 高级测试
    session.connect(passw, overflow) # PASS -> 溢出测试
    
    # 额外的流程组合
    session.connect(list_cmd, retr)  # LIST -> RETR
    session.connect(cwd, list_cmd)   # CWD -> LIST
    
    print("✅ FTP协议定义完成")
    print(f"  • 定义了 8 个FTP请求类型")
    print(f"  • 包含认证、文件操作、目录操作")
    print(f"  • 包含安全测试（溢出、路径遍历）")
    print(f"  • 所有String primitives自动优化")


def main():
    """
    主函数 - 标准boofuzz模式
    """
    
    # 命令行参数解析
    parser = argparse.ArgumentParser(description="boofuzz FTP FUZZ工具")
    parser.add_argument("target", nargs='?', default="127.0.0.1", 
                       help="目标FTP服务器IP (默认: 127.0.0.1)")
    parser.add_argument("port", nargs='?', type=int, default=21,
                       help="目标FTP服务器端口 (默认: 21)")
    parser.add_argument("--web-port", type=int, default=5000,
                       help="Web界面端口 (默认: 5000)")
    parser.add_argument("--dry-run", action="store_true",
                       help="显示配置但不开始FUZZ")
    
    args = parser.parse_args()
    
    print("🎯 boofuzz FTP FUZZ工具")
    print("=" * 40)
    print(f"目标: {args.target}:{args.port}")
    print(f"Web界面: http://localhost:{args.web_port}")
    
    try:
        # ===== 创建boofuzz Session =====
        # 这是标准的boofuzz架构
        print("\n🔧 创建boofuzz会话...")

        # 创建Target对象
        target = Target(connection=TCPSocketConnection(args.target, args.port))

        # 创建Session对象（带优化的Web界面）
        session = Session(
            target=target,
            web_port=args.web_port,        # 增强的Web界面
            sleep_time=1.0,                # 测试间隔1秒
            restart_sleep_time=3.0,        # 重启间隔3秒
            crash_threshold_request=10,    # 10次失败后重启
            crash_threshold_element=3,     # 3次元素失败后重启
            keep_web_open=True,            # 保持Web界面开启
        )

        # 启用AI自适应策略
        session.ai_strategy_enabled = True
        session.ai_decision_threshold = 0.15
        session.ai_adaptation_interval = 50

        print("🤖 AI自适应策略已启用")
        print("✅ boofuzz会话创建成功")

        # ===== 定义FTP协议 =====
        # 使用我们的协议定义函数
        define_ftp_protocol(session)

        # ===== 显示优化信息 =====
        print(f"\n🚀 优化功能状态:")
        print(f"  ✅ String primitives: 自动缓存、去重、智能变异")
        print(f"  ✅ RandomData primitives: 批量生成、内存优化")
        print(f"  ✅ Web界面增强: 实时性能监控")

        if SYMBOLIC_EXECUTION_AVAILABLE:
            print(f"  ✅ AI增强: 协议感知的智能生成 (已集成)")
        else:
            print(f"  ⚠️ AI增强: 不可用 (使用标准boofuzz生成)")

        if args.dry_run:
            print(f"\n🧪 DRY RUN 模式 - 配置完成")
            print(f"移除 --dry-run 参数开始真实FUZZ")
            return

        print(f"\n🚀 开始FTP FUZZ...")
        print(f"⚠️  这将向 {args.target}:{args.port} 发送FTP数据包")
        print(f"📊 监控进度: http://localhost:{args.web_port}")
        print(f"\n按 Ctrl+C 停止FUZZ")

        # ===== 开始FUZZ =====
        # 使用标准boofuzz方法开始FUZZ
        session.fuzz()

    except KeyboardInterrupt:
        print(f"\n🛑 用户停止FUZZ")
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        print(f"请确保目标FTP服务器正在运行且可访问")
    
    print(f"\n✅ boofuzz FTP FUZZ完成")


def create_test_server():
    """
    创建测试FTP服务器脚本
    """
    
    server_code = '''#!/usr/bin/env python3
"""
简单的测试FTP服务器，用于安全的FUZZ测试
"""

import socket
import threading
import time

class SimpleFTPServer:
    def __init__(self, host='127.0.0.1', port=2121):
        self.host = host
        self.port = port
        self.running = False
    
    def handle_client(self, client_socket, addr):
        """处理FTP客户端连接"""
        print(f"[FTP] 连接来自 {addr}")
        
        try:
            # 发送欢迎消息
            client_socket.send(b"220 测试FTP服务器就绪\\r\\n")
            
            authenticated = False
            
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore').strip()
                print(f"[FTP] 命令: {command[:50]}...")
                
                # 基本FTP命令处理
                if command.startswith('USER'):
                    client_socket.send(b"331 需要密码\\r\\n")
                elif command.startswith('PASS'):
                    authenticated = True
                    client_socket.send(b"230 登录成功\\r\\n")
                elif command.startswith('QUIT'):
                    client_socket.send(b"221 再见\\r\\n")
                    break
                elif not authenticated:
                    client_socket.send(b"530 未登录\\r\\n")
                elif command.startswith('LIST'):
                    client_socket.send(b"150 目录列表\\r\\n")
                    time.sleep(0.1)
                    client_socket.send(b"226 传输完成\\r\\n")
                elif command.startswith(('RETR', 'STOR', 'DELE', 'MKD', 'CWD')):
                    client_socket.send(b"200 命令成功\\r\\n")
                else:
                    client_socket.send(b"500 命令不理解\\r\\n")
                    
        except Exception as e:
            print(f"[FTP] 客户端错误: {e}")
        finally:
            client_socket.close()
            print(f"[FTP] 连接关闭: {addr}")
    
    def start(self):
        """启动FTP服务器"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"[FTP] 测试服务器监听 {self.host}:{self.port}")
            print(f"[FTP] 使用方法: python boofuzz_ftp_fuzzer.py {self.host} {self.port}")
            
            self.running = True
            while self.running:
                try:
                    client_socket, addr = server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except:
                    break
                    
        except Exception as e:
            print(f"[FTP] 服务器错误: {e}")
        finally:
            server_socket.close()
            print("[FTP] 服务器停止")

if __name__ == "__main__":
    server = SimpleFTPServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\\n[FTP] 用户停止服务器")
        server.running = False
'''
    
    try:
        with open('ftp_test_server.py', 'w') as f:
            f.write(server_code)
        
        print("✅ 测试FTP服务器已创建: ftp_test_server.py")
        print("📋 使用步骤:")
        print("  1. 启动服务器: python ftp_test_server.py")
        print("  2. 运行FUZZ: python boofuzz_ftp_fuzzer.py 127.0.0.1 2121")
        print("  3. 监控Web界面: http://localhost:5000")
        return True
        
    except Exception as e:
        print(f"❌ 创建测试服务器失败: {e}")
        return False


if __name__ == "__main__":
    # 检查是否要创建测试服务器
    if len(sys.argv) > 1 and sys.argv[1] == "--create-server":
        create_test_server()
    else:
        main()
