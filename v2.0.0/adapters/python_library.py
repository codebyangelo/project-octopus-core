# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - Python Library Scanner Adapter
Safely tests Python libraries (e.g. angr, scapy) via isolated subprocess evaluation.
"""

import os
import sys
import time
import subprocess
from typing import Optional
from .base import BaseScannerAdapter
from core.models import TargetProfile, TestCase, ScanVerdict, VerdictStatus

class PythonLibraryAdapter(BaseScannerAdapter):
    """Executes boundary queries against Python modules in an isolated subshell."""

    def __init__(self, target_path: str, timeout: float = 25.0):
        super().__init__(target_path)
        self.module_name: Optional[str] = None
        self.timeout: float = timeout

    def adapter_name(self) -> str:
        return "Python Library Adapter (Subprocess Isolation)"

    def is_compatible(self, profile: TargetProfile) -> bool:
        return profile.primary_language in ("Python", "Python Stub")

    def setup(self) -> bool:
        # Detect package name by examining top-level directories or setup.py
        target_basename = os.path.basename(self.target_path)
        if os.path.isdir(os.path.join(self.target_path, target_basename)):
            self.module_name = target_basename
            self.is_ready = True
            return True

        for item in os.listdir(self.target_path):
            item_path = os.path.join(self.target_path, item)
            if os.path.isdir(item_path) and os.path.exists(os.path.join(item_path, "__init__.py")):
                if item not in ["tests", "test", "docs", "scripts"]:
                    self.module_name = item
                    self.is_ready = True
                    return True

        self.is_ready = False
        return False

    def scan(self, test_case: TestCase) -> ScanVerdict:
        if not self.is_ready or not self.module_name:
            return ScanVerdict(
                status=VerdictStatus.SKIPPED,
                analysis="Top-level Python package directory not resolved"
            )

        # Properly indent multiline payloads to align with try block
        indented_lines = ["    " + line if line.strip() else "" for line in test_case.payload.strip().splitlines()]
        indented_payload = "\n".join(indented_lines)

        # Build runner script executing in isolated subshell
        runner_code = f"""
import sys, os
sys.path.insert(0, {repr(self.target_path)})
try:
    import {self.module_name}
except Exception as e:
    sys.stderr.write(f"IMPORT_ERROR: {{e}}\\n")
    sys.exit(2)

# Execute test payload safely
try:
{indented_payload}
    sys.stdout.write("SUCCESS\\n")
except Exception as e:
    sys.stderr.write(f"EXCEPTION: {{type(e).__name__}}: {{e}}\\n")
    sys.exit(1)
"""
        start_time = time.perf_counter()
        try:
            proc = subprocess.Popen(
                [sys.executable, "-c", runner_code],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(timeout=self.timeout)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            returncode = proc.returncode

            if returncode == 0:
                return ScanVerdict(
                    status=VerdictStatus.SAFE_ALLOW if test_case.expected == VerdictStatus.SAFE_ALLOW else VerdictStatus.BYPASS_FAIL,
                    analysis="Payload executed cleanly without boundary exceptions",
                    returncode=returncode,
                    latency_ms=elapsed_ms,
                    stdout=stdout,
                    stderr=stderr
                )
            elif returncode == 2:
                return ScanVerdict(
                    status=VerdictStatus.SKIPPED,
                    analysis=f"Module import failed: {stderr.strip()}",
                    returncode=returncode,
                    latency_ms=elapsed_ms,
                    stderr=stderr
                )
            else:
                # Returncode 1: Exception thrown
                if test_case.expected == VerdictStatus.SAFE_BLOCK:
                    return ScanVerdict(
                        status=VerdictStatus.SAFE_BLOCK,
                        analysis=f"Target boundary safely caught exception: {stderr.strip()[:100]}",
                        returncode=returncode,
                        latency_ms=elapsed_ms,
                        stderr=stderr
                    )
                else:
                    return ScanVerdict(
                        status=VerdictStatus.CRASH_FAIL,
                        analysis=f"Unhandled crash exception: {stderr.strip()[:100]}",
                        returncode=returncode,
                        latency_ms=elapsed_ms,
                        stderr=stderr
                    )

        except subprocess.TimeoutExpired:
            proc.kill()
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanVerdict(
                status=VerdictStatus.CRASH_FAIL,
                analysis=f"Python execution timed out after {self.timeout}s",
                latency_ms=elapsed_ms
            )
        except Exception as ex:
            return ScanVerdict(
                status=VerdictStatus.SKIPPED,
                analysis=f"Runner execution error: {str(ex)}"
            )
