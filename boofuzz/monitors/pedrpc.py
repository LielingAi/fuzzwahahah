import errno
import pickle
import select
import socket
import struct
import sys
import time
import uuid

from boofuzz import exception


class Client:
    def __init__(self, host, port):
        self.__host = host
        self.__port = port
        self.__dbg_flag = False
        self.__server_sock = None
        self.__retry = 0
        self.NOLINGER = struct.pack("ii", 1, 0)
        self.known_server = None

    def __getattr__(self, method_name):
        """
        此方法在请求的属性（或方法）未定义时默认调用。
        __getattr__只传递请求的方法名，而不传递参数。
        因此，我们通过一些lambda魔法将功能扩展到方法method_missing()。
        这实际上是Ruby处理缺失方法的方式……带有参数。现在我们和Ruby一样酷。

        @type  method_name: str
        @param method_name: The name of the requested and undefined attribute (or method in our case).

        @rtype:  lambda
        @return: Lambda magic passing control (and in turn the arguments we want) to self.method_missing().
        """

        return lambda *args, **kwargs: self.__method_missing(method_name, *args, **kwargs)

    def __connect(self):
        """
        Connect to the PED-RPC server.
        """

        # 如果存在预先存在的服务器套接字，请确保关闭它。
        self.__disconnect()

        # connect to the server, timeout on failure.
        self.__server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__server_sock.settimeout(3.0)
        try:
            self.__server_sock.connect((self.__host, self.__port))
        except socket.error as e:
            # 如果重试次数小于5次，则等待5秒后重试。
            if self.__retry != 5:
                self.__retry += 1
                time.sleep(5)
                self.__connect()
            else:
                raise exception.BoofuzzRpcError(
                    'PED-RPC> unable to connect to server {0}:{1}. Error message: "{2}"\n'.format(
                        self.__host, self.__port, e
                    )
                )
        # 禁用超时和linger。
        self.__server_sock.settimeout(None)
        self.__server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, self.NOLINGER)

    def __disconnect(self):
        """
        确保套接字被关闭。
        """

        if self.__server_sock is not None:
            self.__debug("closing server socket")
            self.__server_sock.close()
            self.__server_sock = None

    def __debug(self, msg):
        if self.__dbg_flag:
            print("PED-RPC> %s" % msg)

    def __method_missing(self, method_name, *args, **kwargs):
        """
        有关__getattr__的注释。此方法在请求但未定义的类方法时调用。

        @type  method_name: str
        @param method_name: The name of the requested and undefined attribute (or method in our case).
        @type  *args:       tuple
        @param *args:       Tuple of arguments.
        @type  **kwargs     dict
        @param **kwargs:    Dictioanry of arguments.

        @rtype:  Mixed
        @return: Return value of the mirrored method.
        """

        # return a value so lines of code like the following work:
        #     x = pedrpc.client(host, port)
        #     if x:
        #         x.do_something()
        if method_name == "__bool__":
            return 1

        # subclasses run into this as they call a trampoline method...
        # not sure if this is the right way to handle it, but it seems to work
        if method_name.endswith("__method_missing"):
            return self.__method_missing(*args, **kwargs)
        elif method_name.endswith("__hot_transmit"):
            return self.__hot_transmit(*args, **kwargs)

        # 忽略所有其他尝试访问私有成员。
        if method_name.startswith("__"):
            # 这里是不是应该return None?    
            return None

        # connect to the PED-RPC server.
        # 这里每一次都会连接，但是不知道为什么
        self.__connect()

        server_uuid = self.__pickle_recv()
        if server_uuid != self.known_server:
            self.on_new_server(server_uuid)
            self.known_server = server_uuid

        # transmit the method name and arguments.
        # 发送方法名和参数。
        self.__pickle_send((method_name, (args, kwargs)))

        # snag the return value.
        # 获取返回值。
        ret = self.__pickle_recv()

        # close the sock and return.
        self.__disconnect()
        return ret

    def __hot_transmit(self, data):
        self.__pickle_send(data)
        self.__pickle_recv()
        self.__disconnect()
        self.__connect()
        # Grab the instance id. assume it hasn't changed, otherwise we're doomed.
        self.__pickle_recv()

    def __pickle_recv(self):
        """
        此方法用于从PyDbg服务器中解组任意数据。我们可以在这里发送几乎任何东西。
        例如一个包含整数、字符串、任意对象和结构的元组。我们的“协议”是一个简单的
        长度-值协议，其中每个数据报文都以4字节长度为前缀。

        @raise pdx: An exception is raised if the connection was severed.
        @rtype:     Mixed
        @return:    Whatever is received over the socket.
        """

        try:
            # TODO: this should NEVER fail, but alas, it does and for the time being i can't figure out why.
            #       it gets worse. you would think that simply returning here would break things, but it doesn't.
            #       gotta track this down at some point.
            recvd = self.__server_sock.recv(4)
            length = struct.unpack("<L", recvd)[0]
        except Exception:
            return

        try:
            received = b""

            while length:
                chunk = self.__server_sock.recv(length)
                received += chunk
                length -= len(chunk)
        except socket.error as e:
            raise exception.BoofuzzRpcError(
                "PED-RPC> unable to connect to server "
                '{0}:{1}. Error message: "{2}"\n'.format(self.__host, self.__port, e)
            )

        return pickle.loads(received)

    def __pickle_send(self, data):
        """
        This routine is used for marshaling arbitrary data to the PyDbg server. We can send pretty much anything here.
        For example a tuple containing integers, strings, arbitrary objects and structures. Our "protocol" is a simple
        length-value protocol where each datagram is prefixed by a 4-byte length of the data to be received.

        @type  data: Mixed
        @param data: Data to marshal and transmit. Data can *pretty much* contain anything you throw at it.

        @raise pdx: An exception is raised if the connection was severed.
        """

        data = pickle.dumps(data, protocol=2)
        self.__debug("sending %d bytes" % len(data))

        try:
            self.__server_sock.send(struct.pack("<L", len(data)))
            self.__server_sock.send(data)
        except socket.error as e:
            raise exception.BoofuzzRpcError(
                "PED-RPC> unable to connect to server "
                '{0}:{1}. Error message: "{2}"\n'.format(self.__host, self.__port, e)
            )

    def on_new_server(self, new_server):
        """Override this Method in a child class to be notified when the RPC server was restarted."""
        return


class Server:
    """
    The main PED-RPC Server class. To implement an RPC server, inherit from this class. Call ``serve_forever`` to start
    listening for RPC commands.
    """

    def __init__(self, host, port):
        self.__host = host
        self.__port = port
        self.__dbg_flag = False
        self.__client_sock = None
        self.__client_address = None
        self.__running = True

        # 开始选择
        # 这是一个不应该存在的问题的糟糕解决方案。
        # 问题在于客户端在每次RPC调用后都会断开连接，
        # 并在下一次重新连接，而没有任何方法可以知道RPC服务器的状态是否已更改。
        # 如果例如使用具有自动重启功能的虚拟机与在目标上运行RPC守护程序的监视器结合使用，则会出现问题。
        # 在这种情况下，监视器可能希望确保目标上的一组选项处于已知状态。
        # 为了使其工作，客户端需要知道服务器自上次连接以来是否已更改，
        # 以便可以通知实现重新发送任何初始化代码。服务器在启动时生成一个随机uuid并将其发送给每个新连接。
        #
        # 在理想的世界中，此协议不会为每个命令重新连接，
        # 并且选项将与连接关联，但目前我不想清理这个混乱。
        # 结束选择
        self.__instance = uuid.uuid4()

        try:
            # create a socket and bind to the specified port.
            self.__server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.__server.settimeout(None)
            self.__server.bind((host, port))
            self.__server.listen(1)
        except socket.error:
            sys.stderr.write("unable to bind to %s:%d\n" % (host, port))
            sys.exit(1)

    def __disconnect(self):
        """
        确保套接字被关闭。
        """

        if self.__client_sock is not None:
            self.__debug("closing client socket")
            try:
                self.__client_sock.shutdown(socket.SHUT_RDWR)
            except socket.error as e:
                if e.errno in [errno.ENOTCONN, errno.EBADF]:
                    pass
                else:
                    raise
            self.__client_sock.close()

    def __debug(self, msg):
        if self.__dbg_flag:
            print("PED-RPC> %s" % msg)

    def __pickle_recv(self):
        """
        这个例程用于从 PyDbg 服务器中编组任意数据。我们可以在这里发送几乎任何内容。
        例如，一个包含整数、字符串、任意对象和结构的元组。我们的“协议”是一个简单的
        长度-值协议，其中每个数据报的前缀是要接收的数据的4字节长度。

        @raise pdx: An exception is raised if the connection was severed.
        @rtype:     Mixed
        @return:    Whatever is received over the socket.
        """

        try:
            length = struct.unpack("<L", self.__client_sock.recv(4))[0]
            received = b""

            while length:
                chunk = self.__client_sock.recv(length)
                received += chunk
                length -= len(chunk)
        except Exception:
            sys.stderr.write("PED-RPC> connection client severed during recv()\n")
            raise Exception

        return pickle.loads(received)

    def __pickle_send(self, data):
        """
        这个例程用于将任意数据编组到 PyDbg 服务器。我们可以在这里发送几乎任何内容。
        例如，一个包含整数、字符串、任意对象和结构的元组。我们的“协议”是一个简单的
        长度-值协议，其中每个数据报的前缀是要接收的数据的4字节长度。

        @type  data: Mixed
        @param data: Data to marshal and transmit. Data can *pretty much* contain anything you throw at it.

        @raise pdx: An exception is raised if the connection was severed.
        """

        data = pickle.dumps(data, protocol=2)
        self.__debug("sending %d bytes" % len(data))

        try:
            self.__client_sock.send(struct.pack("<L", len(data)))
            self.__client_sock.send(data)
        except Exception:
            sys.stderr.write("PED-RPC> connection to client severed during send()\n")
            raise Exception

    def serve_forever(self):
        self.__debug("serving up a storm")

        while self.__running:
            # close any pre-existing socket.
            self.__disconnect()

            # accept a client connection.
            while self.__running:
                readable, writeable, errored = select.select([self.__server], [], [], 0.1)
                if len(readable) > 0:
                    assert readable[0] == self.__server
                    (self.__client_sock, self.__client_address) = self.__server.accept()
                    break

            self.__debug("accepted connection from %s:%d" % (self.__client_address[0], self.__client_address[1]))

            self.__pickle_send(self.__instance)

            # receive the method name and arguments, continue on socket disconnect.
            try:
                (method_name, (args, kwargs)) = self.__pickle_recv()
                self.__debug("%s(args=%s, kwargs=%s)" % (method_name, args, kwargs))
            except Exception:
                continue

            try:
                method = getattr(self, method_name)
            except AttributeError:
                # if the method can't be found notify the user and raise an error
                sys.stderr.write('PED-RPC> remote method "{0}" of {1} cannot be found\n'.format(method_name, self))
                raise
            
            # 调用方法并获取返回值。
            ret = method(*args, **kwargs)
            # 将返回值发送给客户端，继续在套接字断开时。
            try:
                self.__pickle_send(ret)
            except Exception:
                continue

    def stop(self):
        self.__running = False
        self.__disconnect()
        try:
            self.__server.shutdown(socket.SHUT_RDWR)
        except socket.error as e:
            if e.errno == errno.ENOTCONN:
                pass
            else:
                raise
        self.__server.close()
