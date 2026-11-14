# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - Native Binary Scanner Adapter
Executes compiled native binaries (e.g. radare2, bcc, firejail) with signal trapping and resource limits.
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

class NativeBinaryAdapter(BaseScannerAdapter):
    """Executes native compiled binaries directly with POSIX signal trapping and RLIMIT sandboxing."""

    def __init__(self, target_path: str):
        super().__init__(target_path)
        self.binary_path: Optional[str] = None
        self.binary_type: str = "generic"
        self.ld_library_path: str = ""

    def adapter_name(self) -> str:
        return "Native Binary Adapter (CLI/ASan/Signal Trapping)"

    def is_compatible(self, profile: TargetProfile) -> bool:
        # Compatible if primary language is C/C++/Rust or native_cli / binary_analysis is active
        return (
            profile.primary_language in ("C", "C++", "Rust", "C/C++ Header") or
            profile.capabilities.get("native_cli", {}).get("active", False) or
            profile.capabilities.get("binary_analysis", {}).get("active", False)
        )

    def setup(self) -> bool:
        # 0. Discover local shared library paths to support uninstalled project builds
        local_lib_dirs = []
        for root, dirs, files in os.walk(self.target_path):
            if any(f.endswith((".so", ".dylib")) for f in files):
                local_lib_dirs.append(root)
        if local_lib_dirs:
            existing_ld = os.environ.get("LD_LIBRARY_PATH", "")
            self.ld_library_path = ":".join(local_lib_dirs) + (f":{existing_ld}" if existing_ld else "")

        # 1. Search inside target directory for compiled binaries
        candidate_rel_paths = [
            "binr/radare2/radare2",
            "binr/rabin2/rabin2",
            "bin/radare2",
            "build/radare2",
            "src/firejail",
            "bin/r2",
            "bin/morayd",
            "build/morayd"
        ]
        for rel in candidate_rel_paths:
            cand = os.path.join(self.target_path, rel)
            if os.path.exists(cand) and os.access(cand, os.X_OK):
                self.binary_path = cand
                if "radare2" in cand or "r2" in cand:
                    self.binary_type = "radare2"
                elif "morayd" in cand:
                    self.binary_type = "morayd"
                else:
                    self.binary_type = "generic"
                self.is_ready = True
                return True

        # 2. Check system PATH only if target is radare2 or specifies native CLI
        if "radare2" in self.target_path or "r2" in self.target_path:
            for cmd in ["radare2", "r2", "rabin2"]:
                sys_cand = shutil.which(cmd)
                if sys_cand:
                    self.binary_path = sys_cand
                    self.binary_type = "radare2"
                    self.is_ready = True
                    return True

        return False

    def scan(self, test_case: TestCase) -> ScanVerdict:
        if not self.is_ready or not self.binary_path:
            return ScanVerdict(
                status=VerdictStatus.SKIPPED,
                analysis="Native binary executable not located in target path or system PATH"
            )

        # Build command based on binary type
        cmd: List[str] = []
        if self.binary_type == "radare2":
            # Test payload as r2 batch command against null file descriptor
            cmd = [self.binary_path, "-q", "-c", test_case.payload, "-"]
        else:
            # Generic binary execution
            cmd = [self.binary_path, test_case.payload]

        start_time = time.perf_counter()
        
        # Set resource limit: 512MB address space limit to prevent OOM loops
        def preexec_limit():
            try:
                resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            except Exception:
                pass

        env = os.environ.copy()
        if self.ld_library_path:
            env["LD_LIBRARY_PATH"] = self.ld_library_path

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
            stdout, stderr = proc.communicate(input="", timeout=4.0)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            returncode = proc.returncode

            # Check 1: Trapped Signals (SIGSEGV=11, SIGABRT=6, SIGILL=4, SIGFPE=8)
            if returncode < 0:
                sig = -returncode
                signame = "SIGSEGV" if sig == 11 else "SIGABRT" if sig == 6 else f"Signal {sig}"
                return ScanVerdict(
                    status=VerdictStatus.CRASH_FAIL,
                    analysis=f"Process terminated abruptly with critical signal {signame} ({sig})",
                    returncode=returncode,
                    signal=sig,
                    latency_ms=elapsed_ms,
                    stdout=stdout,
                    stderr=stderr
                )

            # Check 2: Sanitizer traces
            if "AddressSanitizer" in stderr or "UndefinedBehaviorSanitizer" in stderr:
                return ScanVerdict(
                    status=VerdictStatus.CRASH_FAIL,
                    analysis="Memory corruption detected by LLVM/GCC Sanitizer instrumentation",
                    returncode=returncode,
                    latency_ms=elapsed_ms,
                    stdout=stdout,
                    stderr=stderr
                )

            # Check 3: Expected vs Actual Behavior
            if test_case.expected == VerdictStatus.SAFE_BLOCK:
                # If expecting boundary clamping / rejection:
                # Look for math clamp warning, invalid command rejection, or non-zero error return
                has_boundary_err = any(err in stderr.lower() or err in stdout.lower() for err in [
                    "error", "invalid", "cannot", "out of bounds", "overflow", "unknown", "failed", "nan"
                ])
                if returncode != 0 or has_boundary_err:
                    return ScanVerdict(
                        status=VerdictStatus.SAFE_BLOCK,
                        analysis="Target boundary successfully clamped or rejected malformed input",
                        returncode=returncode,
                        latency_ms=elapsed_ms,
                        stdout=stdout,
                        stderr=stderr
                    )
                else:
                    return ScanVerdict(
                        status=VerdictStatus.BYPASS_FAIL,
                        analysis="Silent state conversion or missing bounds validation on malformed input",
                        returncode=returncode,
                        latency_ms=elapsed_ms,
                        stdout=stdout,
                        stderr=stderr
                    )
            else:
                # Expected to allow/succeed
                if returncode == 0:
                    return ScanVerdict(
                        status=VerdictStatus.SAFE_ALLOW,
                        analysis="Command successfully processed cleanly",
                        returncode=returncode,
                        latency_ms=elapsed_ms,
                        stdout=stdout,
                        stderr=stderr
                    )
                else:
                    return ScanVerdict(
                        status=VerdictStatus.CRASH_FAIL,
                        analysis=f"Expected clean execution failed with returncode {returncode}",
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
                analysis="Execution exceeded 4.0s timeout (possible infinite loop or parser stall)",
                latency_ms=elapsed_ms
            )
        except Exception as ex:
            return ScanVerdict(
                status=VerdictStatus.SKIPPED,
                analysis=f"Subprocess invocation failure: {str(ex)}"
            )
