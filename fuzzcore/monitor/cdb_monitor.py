"""cdb_monitor.py - Windows crash monitor (cdb / WinDbg command-line).

Launches a target process under cdb and, on a crash, runs `!analyze -v` to
capture the faulting stack and root cause into a log file. Also supports
post-mortem analysis of a .dmp crash dump.

Requires: cdb.exe from the Windows SDK "Debugging Tools for Windows" component.
Not present on this machine yet (Windows SDK debuggers are not installed),
so this module is written but unverified until cdb is available.

See ARCHITECTURE.md §5.2 (replaces the old pedrpc process_monitor).
"""
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Optional


class CdbMonitor:
    """Run a target under cdb and extract crash root-cause via `!analyze -v`."""

    def __init__(self, cdb_path: str = "cdb.exe"):
        self.cdb_path = cdb_path

    def available(self) -> bool:
        import shutil
        return shutil.which(self.cdb_path) is not None or Path(self.cdb_path).exists()

    def run_under_cdb(self, target_cmd: str, log_file: str,
                      timeout: int = 120, args: str = "") -> Optional[dict]:
        """Run `target_cmd` under cdb; on crash, dump `!analyze -v` to log_file.

        Returns a dict with 'crashed' (bool), 'exit_code', and 'log' path, or
        None if cdb is not available.
        """
        if not self.available():
            return None

        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # g = run; on an exception, @$exr is set; then analyze and quit.
        # If the process exits cleanly, skip the analysis.
        script = (
            '.symfix; .reload; '
            'g; '
            '.if (@$exr != 0) { .echo ===CRASH_DETECTED===; !analyze -v; q } '
            '.else { .echo ===NO_CRASH===; q }'
        )

        parts = shlex.split(target_cmd)
        cmd = [self.cdb_path, "-c", script, "-logo", str(log_path), "--"] + parts
        if args:
            cmd[1:1] = shlex.split(args)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"crashed": False, "exit_code": -1, "log": str(log_path),
                    "error": "timeout"}

        text = log_path.read_text(errors="ignore") if log_path.exists() else ""
        crashed = "===CRASH_DETECTED===" in text
        return {"crashed": crashed, "exit_code": proc.returncode,
                "log": str(log_path), "output": text}

    def analyze_dump(self, dump_file: str, log_file: str,
                     timeout: int = 120) -> Optional[str]:
        """Run `!analyze -v` on a .dmp crash dump, returning the report text."""
        if not self.available():
            return None
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        script = '.symfix; .reload; !analyze -v; q'
        cmd = [self.cdb_path, "-z", dump_file, "-c", script,
               "-logo", str(log_path)]
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            pass
        return log_path.read_text(errors="ignore") if log_path.exists() else ""
