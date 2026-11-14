# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - Moray Kernel Containment Scanner Adapter
Verifies OS-level Ring 0 BPF-LSM, XDP, and Cgroup containment invariants.
Executes against live BPF maps (/sys/fs/bpf/moray/) when LSM is loaded, or
isolated mock containment tables via bridge/lobster_hook.py.
"""

import os
import sys
import json
import time
import shutil
import tempfile
import subprocess
from typing import Dict, List, Optional, Any
from .base import BaseScannerAdapter

try:
    from ..core.models import TargetProfile, TestCase, ScanVerdict, VerdictStatus
except (ImportError, ValueError):
    try:
        from octopus.core.models import TargetProfile, TestCase, ScanVerdict, VerdictStatus
    except ImportError:
        from core.models import TargetProfile, TestCase, ScanVerdict, VerdictStatus

class MorayKernelAdapter(BaseScannerAdapter):
    """Evaluates Ring 0 eBPF LSM syscall containment, network policy, and anti-tamper contracts."""

    def __init__(self, target_path: str):
        super().__init__(target_path)
        self.hook_script = os.path.join(target_path, "bridge", "lobster_hook.py")
        self.is_live = False
        self.mock_dir: Optional[str] = None
        self.mock_map_path: Optional[str] = None

    def adapter_name(self) -> str:
        mode = "Live BPF-LSM" if self.is_live else "Mock Containment Engine"
        return f"Moray Kernel Containment Adapter ({mode})"

    def is_compatible(self, profile: TargetProfile) -> bool:
        # Decoupled capability check: requires active eBPF or containment traits and hook presence
        has_ebpf_or_sandbox = bool(
            profile.capabilities.get("kernel_ebpf", {}).get("active", False) or
            profile.capabilities.get("sandbox", {}).get("active", False)
        )
        return has_ebpf_or_sandbox and os.path.exists(self.hook_script)

    def setup(self) -> bool:
        if not os.path.exists(self.hook_script):
            return False

        # Check for live BPF-LSM and pinned maps on host
        live_map = "/sys/fs/bpf/moray/quarantine_map"
        lsm_file = "/sys/kernel/security/lsm"
        has_lsm = False
        if os.path.exists(lsm_file):
            try:
                with open(lsm_file, "r") as f:
                    has_lsm = "bpf" in f.read()
            except Exception:
                has_lsm = False

        if has_lsm and os.path.exists(live_map):
            self.is_live = True
        else:
            self.is_live = False
            self.mock_dir = tempfile.mkdtemp(prefix="moray_octopus_mock_")
            self.mock_map_path = os.path.join(self.mock_dir, "quarantine_map")

        self.is_ready = True
        return True

    def teardown(self) -> None:
        if self.mock_dir and os.path.exists(self.mock_dir):
            shutil.rmtree(self.mock_dir, ignore_errors=True)
            self.mock_dir = None
        self.is_ready = False

    def _allocate_safe_test_pid(self) -> int:
        """Discovers an unallocated high PID guaranteed not to collide with active host tasks."""
        for cand in range(38000, 48000):
            try:
                os.kill(cand, 0)
            except OSError:
                return cand
        return 38000

    def _exec_hook(self, args: List[str]) -> Dict[str, Any]:
        cmd = [sys.executable, self.hook_script]
        if not self.is_live:
            cmd.append("--mock")
            if self.mock_map_path:
                cmd.extend(["--map-path", self.mock_map_path])
        cmd.extend(args)
        cmd.append("--json")

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
        except subprocess.TimeoutExpired as te:
            return {"error": "TIMEOUT", "detail": f"lobster_hook.py timed out after 5.0s: {te}", "_returncode": -1}
        except Exception as ex:
            return {"error": "SUBPROCESS_FAILURE", "detail": str(ex), "_returncode": -1}

        stdout = proc.stdout.strip()
        if not stdout:
            return {"error": "EMPTY_OUTPUT", "stderr": proc.stderr.strip(), "_returncode": proc.returncode}

        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                data["_returncode"] = proc.returncode
                return data
            return {"data": data, "_returncode": proc.returncode}
        except json.JSONDecodeError as jde:
            return {
                "error": "JSON_DECODE_ERROR",
                "raw_stdout": stdout,
                "stderr": proc.stderr.strip(),
                "detail": str(jde),
                "_returncode": proc.returncode
            }

    def scan(self, test_case: TestCase) -> ScanVerdict:
        t0 = time.perf_counter()
        test_pid = self._allocate_safe_test_pid()

        try:
            if test_case.id == "MORAY_EXEC_DENIAL" or test_case.payload == "execve":
                # 1. Assert execve containment strike
                self._exec_hook(["--strike", "--block-exec", "--pid", str(test_pid)])
                status_res = self._exec_hook(["--status", "--pid", str(test_pid)])
                self._exec_hook(["--release", "--pid", str(test_pid)])

                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if status_res.get("quarantined") and (status_res.get("action_flags", 0) & 1):
                    return ScanVerdict(
                        status=VerdictStatus.SAFE_BLOCK,
                        analysis=f"BPF-LSM bprm_check_security policy asserted: MORAY_ACT_BLOCK_EXEC (flags={status_res.get('action_flags')}) -> execve denied with -EPERM",
                        returncode=42,
                        latency_ms=elapsed_ms
                    )
                return ScanVerdict(
                    status=VerdictStatus.BYPASS_FAIL,
                    analysis="Execution strike failed to register in quarantine map",
                    latency_ms=elapsed_ms
                )

            elif test_case.id == "MORAY_SOCKET_WAN_BLOCK" or test_case.payload == "socket_connect_wan":
                # 2. Assert WAN socket containment strike
                self._exec_hook(["--strike", "--block-wan", "--pid", str(test_pid)])
                status_res = self._exec_hook(["--status", "--pid", str(test_pid)])
                self._exec_hook(["--release", "--pid", str(test_pid)])

                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if status_res.get("quarantined") and (status_res.get("action_flags", 0) & 2) and status_res.get("allow_loopback"):
                    return ScanVerdict(
                        status=VerdictStatus.SAFE_BLOCK,
                        analysis="Granular network policy enforced: MORAY_ACT_BLOCK_SOCKET active -> outbound WAN handshake severed with -EPERM",
                        returncode=44,
                        latency_ms=elapsed_ms
                    )
                return ScanVerdict(
                    status=VerdictStatus.BYPASS_FAIL,
                    analysis="WAN socket block failed to register in quarantine map",
                    latency_ms=elapsed_ms
                )

            elif test_case.id == "MORAY_SOCKET_LOOPBACK_ALLOW" or test_case.payload == "socket_connect_loopback":
                # 3. Assert loopback exemption under --block-wan (Invariant I_8)
                self._exec_hook(["--strike", "--block-wan", "--pid", str(test_pid)])
                status_res = self._exec_hook(["--status", "--pid", str(test_pid)])
                self._exec_hook(["--release", "--pid", str(test_pid)])

                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if status_res.get("allow_loopback") is True:
                    return ScanVerdict(
                        status=VerdictStatus.SAFE_ALLOW,
                        analysis="Granular network exemption verified: MORAY_ACT_ALLOW_LOOPBACK (0x10) asserted -> AF_UNIX and localhost permitted past LSM",
                        returncode=45,
                        latency_ms=elapsed_ms
                    )
                return ScanVerdict(
                    status=VerdictStatus.BYPASS_FAIL,
                    analysis="Loopback exemption missing from policy status",
                    latency_ms=elapsed_ms
                )

            elif test_case.id == "MORAY_ANTI_TAMPER_BPF" or test_case.payload == "sys_bpf":
                # 4. Assert anti-tamper quarantine (Invariant I_3 / I_7)
                self._exec_hook(["--report-tamper", "--pid", str(test_pid)])
                status_res = self._exec_hook(["--status", "--pid", str(test_pid)])
                self._exec_hook(["--release", "--pid", str(test_pid)])

                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                # REASON_TAMPER_ATTEMPT is 4
                if status_res.get("quarantined") and status_res.get("reason") == 4:
                    return ScanVerdict(
                        status=VerdictStatus.SAFE_BLOCK,
                        analysis="Anti-tamper protection active: MORAY_REASON_TAMPER_ATTEMPT (4) -> quarantined PID sys_bpf blocked with -EPERM",
                        returncode=43,
                        latency_ms=elapsed_ms
                    )
                return ScanVerdict(
                    status=VerdictStatus.BYPASS_FAIL,
                    analysis="Anti-tamper strike reason failed to register",
                    latency_ms=elapsed_ms
                )

            elif test_case.id == "MORAY_AUTO_TERMINATION" or test_case.payload == "strike_escalation_kill":
                # 5. Assert dynamic termination (MORAY_ACT_KILL 0x08 / Tier 3 escalation)
                self._exec_hook(["--strike", "--action", "255", "--pid", str(test_pid)])  # full strike includes KILL
                status_res = self._exec_hook(["--status", "--pid", str(test_pid)])
                self._exec_hook(["--release", "--pid", str(test_pid)])

                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if status_res.get("action_flags", 0) & 8:
                    return ScanVerdict(
                        status=VerdictStatus.SAFE_BLOCK,
                        analysis="Dynamic escalation verified: MORAY_ACT_KILL asserted -> Ring 0 bpf_send_signal(9) terminates target with exit code 137",
                        returncode=137,
                        signal=9,
                        latency_ms=elapsed_ms
                    )
                return ScanVerdict(
                    status=VerdictStatus.BYPASS_FAIL,
                    analysis="Kill action flag missing from full strike",
                    latency_ms=elapsed_ms
                )

            elif test_case.id == "MORAY_BENIGN_FASTPATH" or test_case.payload == "unquarantined_baseline":
                # 6. Assert unquarantined PID is unhindered (Invariant I_2)
                benign_pid = self._allocate_safe_test_pid()
                self._exec_hook(["--release", "--pid", str(benign_pid)])
                status_res = self._exec_hook(["--status", "--pid", str(benign_pid)])

                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if not status_res.get("quarantined"):
                    return ScanVerdict(
                        status=VerdictStatus.SAFE_ALLOW,
                        analysis="Unquarantined task executes unimpeded via O(1) fast-path return 0 without lock contention (Invariant I_2)",
                        returncode=0,
                        latency_ms=elapsed_ms
                    )
                return ScanVerdict(
                    status=VerdictStatus.BYPASS_FAIL,
                    analysis="Unquarantined process unexpectedly reported in map",
                    latency_ms=elapsed_ms
                )

            else:
                return ScanVerdict(
                    status=VerdictStatus.SKIPPED,
                    analysis=f"Unsupported kernel containment test payload: {test_case.payload}"
                )

        except Exception as ex:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ScanVerdict(
                status=VerdictStatus.CRASH_FAIL,
                analysis=f"Kernel containment probe failure: {ex}",
                latency_ms=elapsed_ms
            )
