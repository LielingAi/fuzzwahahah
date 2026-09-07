"""gate.py - JS 程序验证门：语法检查（node --check）。

对应 Phase 2 的 VerificationGate：生成的结构化 JS 先过语法门再进语料。
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


def node_available() -> bool:
    return shutil.which("node") is not None


def validate_js(js_code: str, timeout: int = 30) -> tuple[bool, str]:
    """用 node --check 校验 JS 语法，返回 (valid, error_message)。"""
    if not node_available():
        return False, "node 不可用"
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(js_code)
        path = f.name
    try:
        r = subprocess.run(["node", "--check", path], capture_output=True, timeout=timeout)
        err = r.stderr.decode("utf-8", errors="replace")
        return r.returncode == 0, err
    finally:
        Path(path).unlink(missing_ok=True)
