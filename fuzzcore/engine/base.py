"""FuzzWahahah 平台核心抽象（见 ARCHITECTURE.md §2.2）。

设计决定：
- Engine 是"监督式黑盒"：AFL++ / libFuzzer / WinAFL / boofuzz / Domato 各自跑内层循环，
  平台只负责 start / stop / status / inject_seeds / export_*。
- 平台不重写各引擎的变异与调度。
"""
from __future__ import annotations

import abc
import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional


class TargetKind(str, enum.Enum):
    BINARY = "binary"    # 文件格式：字节缓冲 + @@ / stdin
    SERVICE = "service"  # 协议：网络端点
    BROWSER = "browser"  # 浏览器：DOM / JS


class FeedbackKind(str, enum.Enum):
    """引擎反馈信号的等级（Agent 按此降级决策策略）。

    EDGE_COVERAGE：真边/分支覆盖（AFL++/libFuzzer/Fuzzilli），可做平台期自救。
    PROXY_METRICS：代理指标（用例数/崩溃计数等），覆盖语义弱，
                   平台期检测只能当"活动停滞"用，不能当覆盖停滞用。
    """
    EDGE_COVERAGE = "edge_coverage"
    PROXY_METRICS = "proxy_metrics"


@dataclass
class Harness:
    """引擎输入接口描述。"""
    input_mode: str = "@@"      # '@@' | 'stdin' | 'libfuzzer'
    persistent: bool = False    # WinAFL persistent / libFuzzer 持久化
    timeout_ms: int = 5000


@dataclass
class Target:
    kind: TargetKind
    command: str                          # 二进制+args / endpoint / browser profile
    harness: Optional[Harness] = None


@dataclass
class Input:
    data: bytes
    provenance: dict = field(default_factory=dict)
    coverage_sig: Optional[str] = None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass
class CoverageReport:
    total_paths: int = 0         # 语料中的唯一路径数（AFL paths_total）
    bitmap_cvg: float = 0.0      # 位图覆盖率百分比（AFL bitmap_cvg）
    execs_done: int = 0
    unique_crashes: int = 0
    last_find_ts: Optional[float] = None
    extra: dict = field(default_factory=dict)


@dataclass
class EngineStatus:
    running: bool
    coverage: CoverageReport = field(default_factory=CoverageReport)
    crash_count: int = 0
    extra: dict = field(default_factory=dict)


class EngineHandle:
    def __init__(self, engine_id: str, process: Any = None, meta: Optional[dict] = None):
        self.engine_id = engine_id
        self.process = process
        self.meta = meta or {}


class Engine(abc.ABC):
    id: str = "engine"
    feedback_kind: FeedbackKind = FeedbackKind.EDGE_COVERAGE

    @abc.abstractmethod
    def start(self, target: Target, seed_dir: str, out_dir: str, **cfg) -> EngineHandle:
        ...

    @abc.abstractmethod
    def stop(self, handle: EngineHandle) -> None:
        ...

    @abc.abstractmethod
    def status(self, handle: EngineHandle) -> EngineStatus:
        ...

    @abc.abstractmethod
    def inject_seeds(self, handle: EngineHandle, seeds: list[Input]) -> None:
        ...

    @abc.abstractmethod
    def export_coverage(self, handle: EngineHandle) -> CoverageReport:
        ...
