import socket
import threading

class MockRedisServer:
    def __init__(self, host='localhost', port=6379):
        self.host = host
        self.port = port
        self.data = {
            "key1": "value1",
            "key2": "value2",
            "key3": "value3"
        }
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Mock Redis server started on {self.host}:{self.port}")

    def handle_client(self, client_socket):
        while True:
            try:
                request = client_socket.recv(1024).decode('utf-8')
                if not request:
                    break

                parts = request.strip().split('\r\n')
                command = parts[2].upper()
                print(f"Received command: {command}")

                if command == 'PING':
                    response = "+PONG\r\n"
                elif command == 'SET':
                    key = parts[4]
                    value = parts[6]
                    self.data[key] = value
                    response = "+OK\r\n"
                elif command == 'GET':
                    key = parts[4]
                    print(key)
                    print(parts)
                    value = self.data.get(key, None)
                    if value is not None:
                        response = f"${len(value)}\r\n{value}\r\n"
                    else:
                        response = "$-1\r\n"
                elif command == 'TYPE':
                    response = "+string\r\n"
                elif command == 'DEL':
                    key = parts[4]
                    if key in self.data:
                        del self.data[key]
                        response = ":1\r\n"
                    else:
                        response = ":0\r\n"
                elif command == 'EXISTS':
                    key = parts[4]
                    response = f":{1 if key in self.data else 0}\r\n"
                elif command == 'KEYS':
                    pattern = parts[4]
                    matching_keys = [k for k in self.data.keys() if pattern in k]
                    response = f"*{len(matching_keys)}\r\n" + ''.join([f"${len(k)}\r\n{k}\r\n" for k in matching_keys])
                elif command == 'SCAN':
                    cursor = parts[4]
                    keys = list(self.data.keys())
                    response = f"*2\r\n:0\r\n*{len(keys)}\r\n" + ''.join([f"${len(k)}\r\n{k}\r\n" for k in keys])
                    print(response)
                elif command == "HELLO":
                    response = "*6\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n6.2.0\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n"
                    print(response)
                else:
                    response = "-ERR unknown command\r\n"

                client_socket.send(response.encode('utf-8'))
            except Exception as e:
                print(f"Error: {e}")
                break

        client_socket.close()

    def start(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Accepted connection from {addr}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
    server = MockRedisServer()
    server.start()