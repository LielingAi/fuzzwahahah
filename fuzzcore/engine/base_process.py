"""子进程型 Engine 公共生命周期（启动 / 停止 / 状态轮询 / 种子注入）。

子类实现：
- _build_command()：拼出启动命令行
- _coverage_from_dir()：从输出目录解析反馈

inject_seeds() 有默认实现（写 seed 目录）；各引擎对"运行时注入"的支持不同，
最终注入机制在二进制落地后按引擎校准。
"""
from __future__ import annotations

import abc
import subprocess
from pathlib import Path

from .base import CoverageReport, Engine, EngineHandle, EngineStatus, Input, Target


class BaseProcessEngine(Engine):
    """把内层引擎当作一个子进程运行，平台只监督与观察。"""

    def __init__(self, id: str):
        # 参数名 id 沿用子类调用约定 (super().__init__(id=...)); 局部遮蔽内建无害
        self.id = id

    @abc.abstractmethod
    def _build_command(self, target: Target, seed_dir: str, out_dir: str, **cfg) -> list[str]:
        ...

    @abc.abstractmethod
    def _coverage_from_dir(self, out_dir: str) -> CoverageReport:
        ...

    def start(self, target: Target, seed_dir: str, out_dir: str, **cfg) -> EngineHandle:
        Path(seed_dir).mkdir(parents=True, exist_ok=True)
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        cmd = self._build_command(target, seed_dir, out_dir, **cfg)
        log_path = Path(out_dir) / "engine.log"
        log_file = open(log_path, "ab")
        proc = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT)
        return EngineHandle(
            self.id,
            process=proc,
            meta={"cmd": cmd, "out_dir": out_dir, "seed_dir": seed_dir,
                  "log_path": str(log_path), "log_file": log_file},
        )

    def stop(self, handle: EngineHandle) -> None:
        p = handle.process
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        # 关闭引擎日志句柄, 避免句柄泄漏
        log_file = handle.meta.get("log_file")
        if log_file is not None:
            try:
                log_file.close()
            except Exception:
                pass

    def restart(self, handle: EngineHandle) -> None:
        """用记录的启动命令重启引擎子进程。

        用途: 消化 inject_seeds 注入的种子 —— AFL++/libFuzzer 只在启动时读语料目录,
        运行中注入的种子必须重启才生效（SeedDigestCycle 的核心动作）。
        日志以 append 模式续写, 保持覆盖统计的连续性。
        """
        cmd = handle.meta.get("cmd")
        if not cmd:
            raise NotImplementedError("engine did not record a start command")
        self.stop(handle)
        log_path = Path(handle.meta["log_path"])
        log_file = open(log_path, "ab")
        handle.process = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT)
        handle.meta["log_file"] = log_file

    def status(self, handle: EngineHandle) -> EngineStatus:
        running = handle.process is not None and handle.process.poll() is None
        cov = self._coverage_from_dir(handle.meta.get("out_dir", ""))
        return EngineStatus(running=running, coverage=cov, crash_count=cov.unique_crashes)

    def export_coverage(self, handle: EngineHandle) -> CoverageReport:
        return self._coverage_from_dir(handle.meta.get("out_dir", ""))

    def inject_seeds(self, handle: EngineHandle, seeds: list[Input]) -> None:
        """把种子写入语料目录。

        注意: 大多数引擎 (AFL++/libFuzzer) 只在启动时读取语料目录,
        运行中写入的新种子不会自动被采用 —— 需要重启引擎 (或 libFuzzer 的
        -merge=1) 才生效。调度层应在注入后重启引擎来真正消化新种子。
        """
        seed_dir = handle.meta.get("seed_dir")
        if not seed_dir:
            return
        d = Path(seed_dir)
        d.mkdir(parents=True, exist_ok=True)
        for s in seeds:
            (d / f"seed_{s.sha256[:12]}").write_bytes(s.data)
