import socket
import re
import random
from boofuzz.utils.enhanced_symbolic_execution import generate_protocol_data, generate_binary_data

def parse_resp(data):
    """严格解析RESP协议数据"""
    try:
        data_str = data.decode('utf-8')
        # 按RESP协议的行分隔符拆分
        parts = data_str.split('\r\n')
        parsed = []
        
        if not parts or len(parts) < 1:
            return []
        
        # 处理数组类型（*N开头）
        if parts[0].startswith('*'):
            array_len = int(parts[0][1:])
            idx = 1
            for _ in range(array_len):
                if idx >= len(parts):
                    break
                if parts[idx].startswith('$'):
                    # 处理批量字符串
                    str_len = int(parts[idx][1:])
                    idx += 1
                    if idx < len(parts) and len(parts[idx]) == str_len:
                        parsed.append(parts[idx])
                    idx += 1
                else:
                    # 处理其他类型
                    parsed.append(parts[idx])
                    idx += 1
        return parsed
    except Exception as e:
        print(f"解析错误: {e}")
        return []

def create_simple_string_response(message):
    """创建简单字符串响应 (+message\r\n)"""
    return f"+{message}\r\n"

def create_error_response(message):
    """创建错误响应 (-message\r\n)"""
    return f"-{message}\r\n"

def create_bulk_string_response(data):
    """创建批量字符串响应 ($length\r\ndata\r\n)"""
    if data is None:
        return "$-1\r\n"
    length = len(data)
    return f"${length}\r\n{data}\r\n"

def create_array_response(items):
    """创建数组响应 (*count\r\nitem1item2...)"""
    count = len(items)
    parts = [f"*{count}\r\n"]
    for item in items:
        if isinstance(item, str):
            # 字符串项作为批量字符串处理
            parts.append(create_bulk_string_response(item))
        elif isinstance(item, list):
            # 嵌套数组
            parts.append(create_array_response(item))
        else:
            # 其他类型转换为字符串
            parts.append(create_bulk_string_response(str(item)))
    return ''.join(parts)

def get_mock_info():
    """生成严格符合协议的INFO响应 - 集成boofuzz变异"""
    try:
        # 使用AI增强生成Redis INFO字段变异
        redis_versions = generate_protocol_data('redis', 'scores', 5, use_ai=True)
        redis_versions = redis_versions[-1]
        redis_values = generate_protocol_data('redis', 'values', 8, use_ai=True)
        redis_values = redis_values[-1]
        redis_os = generate_protocol_data('redis', 'values', 10, use_ai=True)
        random.shuffle(redis_os)
        redis_os = redis_os[-1]
        # 基础INFO行
        base_lines = [
            "# Server",
            f"redis_version:{redis_versions[0] if redis_versions else '6.2.5'}",
            "redis_mode:standalone",
            f"os:{redis_os}",
            "tcp_port:6379",
            f"uptime_in_days:{redis_values[0] if redis_values else '1'}",
            "# Clients",
            f"connected_clients:{redis_values[1] if len(redis_values) > 1 else '1'}",
            "# Memory", 
            f"used_memory_human:{redis_values[2] if len(redis_values) > 2 else '1.00M'}",
            "# Keyspace",
            f"db0:keys={redis_values[3] if len(redis_values) > 3 else '5'},expires=0"
        ]
        
        # 添加变异字段
        if len(redis_values) > 4:
            base_lines.extend([
                f"# Custom",
                f"custom_field:{redis_values[4]}",
                f"test_value:{redis_values[5] if len(redis_values) > 5 else 'test'}"
            ])
            
    except Exception as e:
        print(f"⚠️ boofuzz变异生成失败，使用基础数据: {e}")
        base_lines = [
            "# Server",
            "redis_version:6.2.5",
            "redis_mode:standalone", 
            "os:Linux x86_64",
            "tcp_port:6379",
            "uptime_in_days:1",
            "# Clients",
            "connected_clients:1",
            "# Memory",
            "used_memory_human:1.00M",
            "# Keyspace", 
            "db0:keys=5,expires=0"
        ]
    
    return "\r\n".join(base_lines)

def handle_command(command):
    """处理命令并返回严格符合协议的响应"""
    if not command:
        return create_simple_string_response("OK")
    
    cmd = command[0].lower()
    
    # 处理CLIENT SETNAME命令
    if cmd == 'client' and len(command) >= 3 and command[1].lower() == 'setname':
        return create_simple_string_response("OK")
    
    # 处理CONFIG GET命令
    if cmd == 'config' and len(command) >= 3 and command[1].lower() == 'get':
        config_key = command[2].lower()
        if config_key == 'databases':
            return create_array_response(["databases", "16"])
        else:
            return create_array_response([])
    
    # 处理SCAN命令
    if cmd == 'scan' and len(command) >= 2:
        cursor = command[1]
        if cursor == '0':
            return create_array_response(["79", ["user1", "user2", "order1"]])
        elif cursor == '79':
            return create_array_response(["0", ["order2", "product"]])
        else:
            return create_array_response(["0", []])
    
    # 处理INFO命令
    if cmd == 'info':
        return create_bulk_string_response(get_mock_info())
    
    # 未知命令
    return create_error_response(f"ERR unknown command '{command[0]}'")

def start_mock_redis_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = ('0.0.0.0', 6379)
    
    try:
        server_socket.bind(server_address)
        server_socket.listen(5)
        print(f"严格模式 - 监听 {server_address[0]}:{server_address[1]} 端口...")
        
        while True:
            client_socket, client_addr = server_socket.accept()
            print(f"客户端 {client_addr} 已连接")
            
            try:
                # 设置超时，防止客户端一直连接不发送数据
                client_socket.settimeout(30)
                
                while True:
                    data = client_socket.recv(4096)
                    if not data:
                        print(f"客户端 {client_addr} 断开连接")
                        break
                    
                    # 打印原始接收数据（用于调试）
                    print(f"原始接收: {repr(data)}")
                    
                    command = parse_resp(data)
                    print(f"解析命令: {command}")
                    
                    response = handle_command(command)
                    # 打印原始响应数据（用于调试）
                    print(f"原始响应: {repr(response)}")
                    
                    client_socket.sendall(response.encode('utf-8'))
                    
            except socket.timeout:
                print(f"客户端 {client_addr} 超时")
            except Exception as e:
                print(f"处理客户端时出错: {e}")
            finally:
                client_socket.close()
                
    except KeyboardInterrupt:
        print("\n服务器正在关闭...")
    except Exception as e:
        print(f"服务器错误: {e}")
    finally:
        server_socket.close()
        print("服务器已关闭")

if __name__ == "__main__":
    start_mock_redis_server()
    
