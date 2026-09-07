#!/usr/bin/env python3
"""build.py - compile the libFuzzer harness (fuzz_crc_lzma.c) with clang-cl.

Produces harness/fuzz_crc_lzma.exe (libFuzzer + ASAN, no external deps).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

CLANG_CL_CANDIDATES = [
    r"C:\Program Files\LLVM\bin\clang-cl.exe",
    r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\clang-cl.exe",
]

SOURCES = [
    "fuzz_crc_lzma.c",
    "7z/LzmaDec.c",
    "7z/7zCrc.c",
    "7z/7zCrcOpt.c",
    "7z/CpuArch.c",
]


def find_clang_cl() -> Path | None:
    for c in CLANG_CL_CANDIDATES:
        p = Path(c)
        if p.exists():
            return p
    import shutil
    which = shutil.which("clang-cl")
    return Path(which) if which else None


def main() -> int:
    clang = find_clang_cl()
    if clang is None:
        print("clang-cl not found (install LLVM / 'C++ Clang tools for Windows')", file=sys.stderr)
        return 1

    out = HERE / "fuzz_crc_lzma.exe"
    cmd = [str(clang), "-fsanitize=fuzzer,address", "-O1",
           "-I", str(HERE / "7z")]
    cmd += [str(HERE / s) for s in SOURCES]
    cmd += ["-o", str(out)]

    print("$", " ".join(cmd))
    r = subprocess.run(cmd, cwd=str(HERE))
    if r.returncode == 0 and out.exists():
        print(f"OK: {out}")
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
