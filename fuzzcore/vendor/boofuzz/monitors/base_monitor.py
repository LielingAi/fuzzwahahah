class BaseMonitor:
    """
    Interface for Target monitors. All Monitors must adhere
    to this specification.

    .. versionadded:: 0.2.0
    """

    def __init__(self):
        return

    def alive(self):
        """
        当包含此监视器的目标添加到会话中时调用。
        如果您的目标存在，请使用此功能连接到RPC主机等
        在另一台机器上。
        如果监视器处于活动状态，则必须返回True。您必须返回False
        否则。如果监视器不活动，则将调用此方法
        直到它变得活跃或抛出异常。你应该处理
        监视器实现中的超时/连接重试限制。

        Defaults to return True.

        :returns: Bool
        """
        return True

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """
        在当前模糊节点传输之前调用。

        Defaults to no effect.

        :returns: None
        """
        return

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """
        在当前模糊节点传输后调用。用它来收集
        获取目标的数据，并判断其是否坠毁。

        如果目标仍然存在，则必须返回True。您必须返回False
        如果目标坠毁。如果一个监视器报告崩溃，整个测试用例
        将被标记为崩溃。

        Defaults to return True.

        :returns: Bool
        """
        return True

    def post_start_target(self, target=None, fuzz_data_logger=None, session=None):
        """在目标启动或重新启动后调用."""
        return

    def retrieve_data(self):
        """
        被调用以检索数据，与当前模糊节点是否崩溃无关
        目标与否。在模糊器进行新的测试用例之前调用。

        您应该返回应该记录的任何辅助数据。数据必须
        可序列化，例如字节串。

        Defaults to return None.
        """
        return None

    def set_options(self, *args, **kwargs):
        """
        调用以设置监视器的选项（例如本地崩溃转储存储）。
        \\*args和\\*\\*kwargs可以通过实现类来显式指定，
        但是，你应该忽略任何你不认识的kwarg。

        Defaults to no effect.

        :returns: None
        """
        return

    def get_crash_synopsis(self):
        """
        如果任何监视器指示当前测试用例失败，则调用，
        即使这个监视器没有检测到碰撞。你应该归还一个人-
        崩溃概要的可读表示（例如hexdump）。你可以
        把整个垃圾堆保存在某个地方。

        :returns: str
        """
        return ""

    def start_target(self):
        """
        启动一个目标。如果启动成功，则必须返回True。
        否则必须返回False。监视器将尝试启动目标
        按照它们被添加到目标中的顺序；第一个成功的Monitor
        迭代中断。

        :returns: Bool
        """
        return False

    def stop_target(self):
        """
        停止目标。如果停止成功，则必须返回True。
        否则必须返回False。监视器将尝试停止目标
        按照它们被添加到目标中的顺序；第一个成功的Monitor
        迭代中断。

        :returns: Bool
        """

        return False

    def restart_target(self, target=None, fuzz_data_logger=None, session=None):
        """
        重新启动目标。如果重启成功，则必须返回True；如果重启不成功，则返回False
        或者此监视器无法重新启动Target，这会导致链中的下一个监视器
        尝试重新启动。

        第一个成功的监视器会导致重启链停止应用。

        默认情况下调用stop and start，如果成功则返回True。

        :returns: Bool
        """
        if self.stop_target():
            return self.start_target()
        return False
