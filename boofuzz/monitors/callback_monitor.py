import traceback

from boofuzz import constants, exception
from .base_monitor import BaseMonitor


class CallbackMonitor(BaseMonitor):
    """
    会话中用于提供回调数组的新式回调监视器。
    它的目的是在会话类中保留\\*_callbacks参数，同时
    通过将这些回调转发给
    监控基础设施。
    
    此类的参数映射如下：

    - restart_callbacks --> target_restart
    - pre_send_callbacks --> pre_send
    - post_test_case_callbacks --> post_send
    - post_start_target_callbacks --> post_start_target

    所有其他实现的接口成员都是占位符，因为会话中没有相应的参数。
    在任何情况下，实现自定义监视器比使用回调函数更明智。

    .. versionadded:: 0.2.0
    """

    def __init__(self, on_pre_send=None, on_post_send=None, on_restart_target=None, on_post_start_target=None):
        BaseMonitor.__init__(self)

        self.on_pre_send = on_pre_send if on_pre_send is not None else []
        self.on_post_send = on_post_send if on_post_send is not None else []
        self.on_restart_target = on_restart_target if on_restart_target is not None else []
        self.on_post_start_target = on_post_start_target if on_post_start_target is not None else []

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """此方法迭代所有提供的预发送回调并执行它们。
        它们的返回值被丢弃，异常被捕获并记录，但其他情况被丢弃。
        """
        try:
            for f in self.on_pre_send:
                fuzz_data_logger.open_test_step('Pre_Send callback: "{0}"'.format(f.__name__))
                f(target=target, fuzz_data_logger=fuzz_data_logger, session=session, sock=target)
        except Exception:
            fuzz_data_logger.log_error(
                constants.ERR_CALLBACK_FUNC.format(func_name="pre_send") + traceback.format_exc()
            )

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """此方法迭代所有提供的后发送回调并执行它们。
        它们的返回值被丢弃，异常被捕获并记录：

        - :class:`BoofuzzTargetConnectionReset <boofuzz.exception.BoofuzzTargetConnectionReset>` will log a failure
        - :class:`BoofuzzTargetConnectionAborted <boofuzz.exception.BoofuzzTargetConnectionAborted>` will log an info
        - :class:`BoofuzzTargetConnectionFailedError <boofuzz.exception.BoofuzzTargetConnectionFailedError>` will log a
          failure
        - :class:`BoofuzzSSLError <boofuzz.exception.BoofuzzSSLError>` will log either info or failure, depending on
          if the session ignores SSL/TLS errors.
        - every other exception is logged as an error.

        所有异常在处理后被丢弃。
        """
        try:
            for f in self.on_post_send:
                fuzz_data_logger.open_test_step('Post-test case callback: "{0}"'.format(f.__name__))
                f(target=target, fuzz_data_logger=fuzz_data_logger, session=session, sock=target)
        except exception.BoofuzzTargetConnectionReset:
            fuzz_data_logger.log_fail(constants.ERR_CONN_RESET_FAIL)
        except exception.BoofuzzTargetConnectionAborted as e:
            fuzz_data_logger.log_info(
                constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            )
        except exception.BoofuzzTargetConnectionFailedError:
            fuzz_data_logger.log_fail(constants.ERR_CONN_FAILED)
        except exception.BoofuzzSSLError as e:
            if session._ignore_connection_ssl_errors:
                fuzz_data_logger.log_info(str(e))
            else:
                fuzz_data_logger.log_fail(str(e))
        except Exception:
            fuzz_data_logger.log_error(
                constants.ERR_CALLBACK_FUNC.format(func_name="post_send") + traceback.format_exc()
            )
        finally:
            fuzz_data_logger.open_test_step("Cleaning up connections from callbacks")
        return True

    def restart_target(self, target=None, fuzz_data_logger=None, session=None):
        """
        此方法尝试重启目标。如果没有重启回调，则返回false；否则返回true。

        :returns: bool
        """
        try:
            for f in self.on_restart_target:
                fuzz_data_logger.open_test_step('Target restart callback: "{0}"'.format(f.__name__))
                f(target=target, fuzz_data_logger=fuzz_data_logger, session=session, sock=target)
        except exception.BoofuzzRestartFailedError:
            raise
        except Exception:
            fuzz_data_logger.log_error(
                constants.ERR_CALLBACK_FUNC.format(func_name="restart_target") + traceback.format_exc()
            )
        finally:
            fuzz_data_logger.open_test_step("Cleaning up connections from callbacks")
            target.close()
            if session._reuse_target_connection:
                fuzz_data_logger.open_test_step("Reopening target connection")
                target.open()

        if len(self.on_restart_target) > 0:
            return True
        else:
            return False

    def post_start_target(self, target=None, fuzz_data_logger=None, session=None):
        """在目标启动或重启后调用。"""
        try:
            for f in self.on_post_start_target:
                fuzz_data_logger.open_test_step('Post-start-target callback: "{0}"'.format(f.__name__))
                f(target=target, fuzz_data_logger=fuzz_data_logger, session=session, sock=target)
        except Exception:
            fuzz_data_logger.log_error(
                constants.ERR_CALLBACK_FUNC.format(func_name="post_start_target") + traceback.format_exc()
            )

    def __repr__(self):
        return "CallbackMonitor#{}[pre=[{}],post=[{}],restart=[{}],post_start_target=[{}]]".format(
            id(self),
            ", ".join([x.__name__ for x in self.on_pre_send]),
            ", ".join([x.__name__ for x in self.on_post_send]),
            ", ".join([x.__name__ for x in self.on_restart_target]),
            ", ".join([x.__name__ for x in self.on_post_start_target]),
        )
