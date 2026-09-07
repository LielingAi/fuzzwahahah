#!/usr/bin/env python3
"""phase1_demo.py - Phase 1 端到端演示：项目自己的代码跑通 fuzz loop。

流程：
  Corpus(SQLite) 存结构化种子 -> 写种子目录 -> LibFuzzerFileEngine 跑 harness
  -> 从 engine.log 解析 coverage -> 停掉引擎。

运行前先 `python harness/build.py` 编译 harness。
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fuzzcore.corpus import SqliteCorpus
from fuzzcore.engine import LibFuzzerFileEngine, Target, TargetKind

HARNESS = PROJECT_ROOT / "harness" / "fuzz_crc_lzma.exe"


def make_structured_seed() -> bytes:
    """构造一个合法种子：[4-byte CRC32][5-byte LZMA props][LZMA stream]"""
    import lzma
    import zlib
    data = b"hello structured fuzzing world " * 20
    c = lzma.compress(data, format=lzma.FORMAT_ALONE)
    lzma_stream = c[:5] + c[13:]  # props + compressed data (去 8 字节 size)
    crc = zlib.crc32(lzma_stream) & 0xFFFFFFFF
    return crc.to_bytes(4, "little") + lzma_stream


def main() -> int:
    if not HARNESS.exists():
        print("harness 未编译，先运行: python harness/build.py", file=sys.stderr)
        return 1

    # 1. Corpus (SQLite) 存结构化种子
    corpus = SqliteCorpus(str(PROJECT_ROOT / "phase1_corpus.db"))
    seed = make_structured_seed()
    corpus.add(seed, provenance={"src": "structured", "format": "crc+lzma"}, source="seed")
    corpus.enqueue_seed("lzma", seed, {"src": "structured"})
    print(f"[corpus] {corpus.count()} 个输入，种子 {len(seed)} 字节")

    # 2. 写种子目录
    seed_dir = tempfile.mkdtemp(prefix="lzma_seeds_")
    (Path(seed_dir) / "seed0").write_bytes(seed)

    # 3. 引擎跑 harness
    engine = LibFuzzerFileEngine(str(HARNESS), timeout_s=5, max_len=256)
    target = Target(TargetKind.BINARY, str(HARNESS))
    out_dir = tempfile.mkdtemp(prefix="lzma_out_")
    handle = engine.start(target, seed_dir, out_dir)

    # 4. 跑 ~8 秒（libFuzzer 周期输出 cov: 到 engine.log）
    time.sleep(8)

    # 5. 读 coverage（Feedback 逻辑在 engine._coverage_from_dir）
    status = engine.status(handle)
    print(f"[engine] running={status.running} "
          f"cov={status.coverage.total_paths} "
          f"crashes={status.coverage.unique_crashes}")

    engine.stop(handle)
    corpus.close()
    print("[done] Phase 1 loop 端到端跑通")
    return 0


if __name__ == "__main__":
    sys.exit(main())
