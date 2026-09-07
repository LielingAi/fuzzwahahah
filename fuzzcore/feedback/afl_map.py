"""AFL++ 反馈解析（Phase 1 只接 AFL map，见 ARCHITECTURE.md §7）。

信号来源：
- fuzzer_stats：paths_total / bitmap_cvg / execs_done / unique_crashes / last_find
- afl-showmap：单个输入命中的边集合（用于语料溯源 + 后续验证门）
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..engine.base import CoverageReport  # 打破 feedback ↔ engine 模块级循环


def parse_fuzzer_stats(path) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    stats = {}
    for line in p.read_text(errors="ignore").splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        stats[k.strip()] = v.strip()
    return stats


def _to_int(mapping: dict, key: str, default: int = 0) -> int:
    try:
        return int(mapping.get(key, default))
    except (TypeError, ValueError):
        return default


def _to_float(mapping: dict, key: str, default: float = 0.0) -> float:
    try:
        return float(mapping.get(key, default))
    except (TypeError, ValueError):
        return default


def _to_float_pct(mapping: dict, key: str, default: float = 0.0) -> float:
    """解析带 % 后缀的浮点值 (如 bitmap_cvg 的 "0.05%")。"""
    v = mapping.get(key)
    if v is None:
        return default
    try:
        return float(str(v).rstrip("%"))
    except (TypeError, ValueError):
        return default


def coverage_from_fuzzer_stats(path) -> CoverageReport:
    from ..engine.base import CoverageReport  # 运行时延迟, 避免模块级循环
    s = parse_fuzzer_stats(path)
    lf = _to_float(s, "last_find", 0.0)
    return CoverageReport(
        total_paths=_to_int(s, "paths_total"),
        bitmap_cvg=_to_float_pct(s, "bitmap_cvg"),
        execs_done=_to_int(s, "execs_done"),
        unique_crashes=_to_int(s, "unique_crashes"),
        last_find_ts=(lf if lf > 0 else None),
        extra=s,
    )


def run_showmap(showmap_bin: str, target_cmd: str, input_file: str,
                out_file: str, timeout: int = 15) -> set[int]:
    """对单个输入运行 afl-showmap，返回命中的边 id 集合。

    target_cmd 中可用 '@@' 作为输入文件占位符。注意：简单按空格 split，
    含带空格/引号的参数时需改用列表形式传入（Phase 1 够用）。
    """
    parts = [input_file if p == "@@" else p for p in target_cmd.split()]
    cmd = [showmap_bin, "-q", "-o", out_file, "--"] + parts
    subprocess.run(cmd, timeout=timeout, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=False)
    return parse_showmap_output(out_file)


def parse_showmap_output(path) -> set[int]:
    """解析 afl-showmap 输出：默认每行一个十进制边 id（带 -e 时为 src->dst:id）。"""
    edges: set[int] = set()
    p = Path(path)
    if not p.exists():
        return edges
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            line = line.rsplit(":", 1)[1]
        try:
            edges.add(int(line))
        except ValueError:
            continue
    return edges
