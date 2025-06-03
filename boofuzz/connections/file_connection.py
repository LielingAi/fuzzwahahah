import errno
import os

from . import itarget_connection


class FileConnection(itarget_connection.ITargetConnection):
    """把每个信息写入给定目录中的一个新文件。

    参数:
        directory: 储存新信息文件的目录。
        one_file_only (bool): 如果为True，则会持续覆盖同一个文件。通常与处理文件的钩子结合使用。
    """

    def __init__(self, directory, one_file_only=False):
        # 初始化文件连接实例，并确保目录存在
        self._dirname = directory
        self._file_id = 1
        self._file_handle = None
        self._one_file_only = one_file_only

        # try:
        #     os.mkdir(self._dirname)  # 尝试创建目录
        # except OSError as exc:
        #     if exc.errno != errno.EEXIST:
        #         raise  # 如果目录已经存在之外的错误，则抛出异常
        #     pass  # 目录已存在，不做任何处理

        os.makedirs(self._dirname, exist_ok=True)

    def close(self):
        """
        关闭目标的连接。

        :return: None
        """
        # self._file_handle.close()  # 关闭文件句柄
        # if not self._one_file_only:
        #     self._file_id += 1  # 如果不是单文件模式，则递增文件ID

        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None
        if not self._one_file_only:
            self._file_id += 1

    def open(self):
        """
        打开目标连接。请确保调用close！

        :return: None
        """
        self._file_handle = open(os.path.join(self._dirname, str(self._file_id)), "wb")  # 以写入字节的模式打开文件

    def recv(self, max_bytes):
        """
        从目标接收最多max_bytes的数据。

        参数:
            max_bytes (int): 要接收的最大字节数。

        返回:
            bytes: 接收到的数据。
        """
        received_data = self._file_handle.read(max_bytes)  # 从文件中读取最多max_bytes的数据
        if not received_data:
            return b""  # 如果读取到的数据为空，则返回一个空字节串
        return received_data

    def send(self, data):
        """
        发送数据到目标。在调用open之后才有效！

        参数:
            data: 要发送的数据。

        返回:
            int: 实际发送的字节数。
        """
        self._file_handle.write(data)  # 写入数据到文件

    @property
    def info(self):
        # 返回当前使用的目录和文件名
        return "directory: {0}, filename: {1}".format(self._dirname, str(self._file_id))
