# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - CLI State Integrity Adapter
Executes multi-turn command sequences to verify address preservation,
exit code contracts, whitespace trimming, and help fallthrough boundaries.
"""

import os
import time
import shutil
import subprocess
import resource
from typing import Optional, List
from .base import BaseScannerAdapter

try:
    from ..core.models import TargetProfile, TestCase, ScanVerdict, VerdictStatus
except (ImportError, ValueError):
    try:
        from octopus.core.models import TargetProfile, TestCase, ScanVerdict, VerdictStatus
    except ImportError:
        from core.models import TargetProfile, TestCase, ScanVerdict, VerdictStatus

class CLIStateIntegrityAdapter(BaseScannerAdapter):
    """Verifies that native tools preserve state invariants during invalid commands."""

    def __init__(self, target_path: str):
        super().__init__(target_path)
        self.binary_path: Optional[str] = None
        self.ld_library_path: str = ""

    def adapter_name(self) -> str:
        return "CLI State Integrity Adapter (Multi-Turn State Prober)"

    def is_compatible(self, profile: TargetProfile) -> bool:
        return (
            profile.capabilities.get("native_cli", {}).get("active", False) or
            profile.capabilities.get("binary_analysis", {}).get("active", False)
        )

    def setup(self) -> bool:
        # Discover local shared libraries
        local_lib_dirs = []
        for root, dirs, files in os.walk(self.target_path):
            if any(f.endswith((".so", ".dylib")) for f in files):
                local_lib_dirs.append(root)
        if local_lib_dirs:
            existing_ld = os.environ.get("LD_LIBRARY_PATH", "")
            self.ld_library_path = ":".join(local_lib_dirs) + (f":{existing_ld}" if existing_ld else "")

        # Search for compiled binary in target tree
        candidate_rel_paths = [
            "binr/radare2/radare2",
            "binr/rabin2/rabin2",
            "bin/radare2",
            "build/radare2"
        ]
        for rel in candidate_rel_paths:
            cand = os.path.join(self.target_path, rel)
            if os.path.exists(cand) and os.access(cand, os.X_OK):
                self.binary_path = cand
                self.is_ready = True
                return True

        # System fallback if target is radare2
        if "radare2" in self.target_path:
            sys_cand = shutil.which("radare2")
            if sys_cand:
                self.binary_path = sys_cand
                self.is_ready = True
                return True

        return False

    def scan(self, test_case: TestCase) -> ScanVerdict:
        if not self.is_ready or not self.binary_path:
            return ScanVerdict(
                status=VerdictStatus.SKIPPED,
                analysis="Native binary executable not resolved"
            )

        cmd = [self.binary_path, "-q", "-c", test_case.payload, "-"]

        env = os.environ.copy()
        if self.ld_library_path:
            env["LD_LIBRARY_PATH"] = self.ld_library_path

        def preexec_limit():
            try:
                resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            except Exception:
                pass

        start_time = time.perf_counter()
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                preexec_fn=preexec_limit
            )
            stdout, stderr = proc.communicate(timeout=4.0)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            returncode = proc.returncode

            # Check signal terminations
            if returncode < 0:
                sig = -returncode
                return ScanVerdict(
                    status=VerdictStatus.CRASH_FAIL,
                    analysis=f"Process crashed with signal {sig} during multi-turn state execution",
                    returncode=returncode,
                    signal=sig,
                    latency_ms=elapsed_ms,
                    stdout=stdout,
                    stderr=stderr
                )

            # Check specific multi-turn state contracts:
            # 1. Address Preservation: e.g. "s 0x1000; s unknown; ?v $$"
            if "?v $$" in test_case.payload and "0x1000" in test_case.payload:
                stdout_lines = [l.strip() for l in stdout.splitlines() if l.strip()]
                last_line = stdout_lines[-1] if stdout_lines else ""
                if "0x1000" in last_line or "4096" in last_line:
                    return ScanVerdict(
                        status=VerdictStatus.SAFE_BLOCK,
                        analysis="State preservation verified: invalid command did not corrupt address to 0x0",
                        returncode=returncode,
                        latency_ms=elapsed_ms,
                        stdout=stdout,
                        stderr=stderr
                    )
                elif "0x0" in last_line or "0" == last_line:
                    return ScanVerdict(
                        status=VerdictStatus.BYPASS_FAIL,
                        analysis="Silent state corruption: invalid seek expression reset address to 0x00000000",
                        returncode=returncode,
                        latency_ms=elapsed_ms,
                        stdout=stdout,
                        stderr=stderr
                    )

            # 2. Help Fallthrough Traps: e.g. "so?"
            if test_case.payload.strip().endswith("?"):
                # Help query must print help and not treat '?' as an error operand
                if "unknown opcode '?'" in stderr or "unknown symbol" in stderr:
                    return ScanVerdict(
                        status=VerdictStatus.BYPASS_FAIL,
                        analysis="Help fallthrough detected: command dispatcher fell through into opcode seek",
                        returncode=returncode,
                        latency_ms=elapsed_ms,
                        stdout=stdout,
                        stderr=stderr
                    )
                else:
                    return ScanVerdict(
                        status=VerdictStatus.SAFE_ALLOW,
                        analysis="Help query cleanly printed help without fallthrough execution",
                        returncode=returncode,
                        latency_ms=elapsed_ms,
                        stdout=stdout,
                        stderr=stderr
                    )

            # 3. Default check
            if returncode == 0:
                return ScanVerdict(
                    status=VerdictStatus.SAFE_ALLOW if test_case.expected == VerdictStatus.SAFE_ALLOW else VerdictStatus.BYPASS_FAIL,
                    analysis="Command executed with returncode 0",
                    returncode=returncode,
                    latency_ms=elapsed_ms,
                    stdout=stdout,
                    stderr=stderr
                )
            else:
                return ScanVerdict(
                    status=VerdictStatus.SAFE_BLOCK if test_case.expected == VerdictStatus.SAFE_BLOCK else VerdictStatus.CRASH_FAIL,
                    analysis=f"Command rejected with exit code {returncode}",
                    returncode=returncode,
                    latency_ms=elapsed_ms,
                    stdout=stdout,
                    stderr=stderr
                )

        except subprocess.TimeoutExpired:
            proc.kill()
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanVerdict(
                status=VerdictStatus.CRASH_FAIL,
                analysis="Execution exceeded 4.0s timeout during state audit",
                latency_ms=elapsed_ms
            )
        except Exception as ex:
            return ScanVerdict(
                status=VerdictStatus.SKIPPED,
                analysis=f"CLI state invocation error: {str(ex)}"
            )
