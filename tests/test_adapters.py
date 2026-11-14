# -*- coding: utf-8 -*-
"""
Tests for Project Octopus Scanner Adapters
"""

import os
import shutil
import tempfile
import unittest

from octopus.core.models import TestCase, VerdictStatus, SVAPTier
from octopus.adapters.c_source import CSourceSemanticAdapter
from octopus.adapters.cli_state import CLIStateIntegrityAdapter
from octopus.adapters.python_library import PythonLibraryAdapter
from octopus.adapters.moray_kernel import MorayKernelAdapter


class TestScannerAdapters(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_octopus_adapters_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_c_source_semantic_adapter(self):
        c_proj = os.path.join(self.test_dir, "c_proj")
        os.makedirs(os.path.join(c_proj, "src"), exist_ok=True)
        # Write file with legacy math anti-pattern
        with open(os.path.join(c_proj, "src", "seek.c"), "w") as f:
            f.write("ut64 addr = r_num_math (core->num, expr);\n")
        # Write file with modern boundary-safe math API
        with open(os.path.join(c_proj, "src", "math.c"), "w") as f:
            f.write("ut64 addr = r_num_math_err (core->num, expr, &err);\n")

        adapter = CSourceSemanticAdapter(c_proj)
        self.assertTrue(adapter.setup())

        # Test 1: Anti-pattern detection (finding legacy r_num_math violates SAFE_BLOCK)
        tc_legacy = TestCase(
            id="LEGACY_TEST",
            suite="Math Safety",
            payload="LEGACY_MATH_CALL",
            expected=VerdictStatus.SAFE_BLOCK,
            severity="High",
            svap_tier=SVAPTier.TIER_2,
            description="Detect legacy math"
        )
        verdict1 = adapter.scan(tc_legacy)
        self.assertEqual(verdict1.status, VerdictStatus.BYPASS_FAIL)

        # Test 2: Invariant enforcement (finding r_num_math_err satisfies SAFE_ALLOW)
        tc_modern = TestCase(
            id="MODERN_TEST",
            suite="Math Safety",
            payload=r"\br_num_math_err\s*\(",
            expected=VerdictStatus.SAFE_ALLOW,
            severity="High",
            svap_tier=SVAPTier.TIER_2,
            description="Verify hardened API presence"
        )
        verdict2 = adapter.scan(tc_modern)
        self.assertEqual(verdict2.status, VerdictStatus.SAFE_ALLOW)

    def test_cli_state_integrity_adapter(self):
        cli_proj = os.path.join(self.test_dir, "cli_proj")
        bin_dir = os.path.join(cli_proj, "binr", "radare2")
        os.makedirs(bin_dir, exist_ok=True)
        mock_r2 = os.path.join(bin_dir, "radare2")

        with open(mock_r2, "w") as f:
            f.write("#!/bin/sh\n")
            f.write("if echo \"$*\" | grep -q '?v \\$\\$'; then\n")
            f.write("    echo '0x1000'\n")
            f.write("    exit 0\n")
            f.write("elif echo \"$*\" | grep -q 'so?'; then\n")
            f.write("    echo 'Usage: so [num] - seek opcodes'\n")
            f.write("    exit 0\n")
            f.write("fi\n")
            f.write("exit 0\n")
        os.chmod(mock_r2, 0o755)

        adapter = CLIStateIntegrityAdapter(cli_proj)
        self.assertTrue(adapter.setup())

        tc_state = TestCase(
            id="STATE_TEST",
            suite="CLI State",
            payload="s 0x1000; s unknown; ?v $$",
            expected=VerdictStatus.SAFE_BLOCK,
            severity="Critical",
            svap_tier=SVAPTier.TIER_2,
            description="State preservation test"
        )
        verdict_state = adapter.scan(tc_state)
        self.assertEqual(verdict_state.status, VerdictStatus.SAFE_BLOCK)

        tc_help = TestCase(
            id="HELP_TEST",
            suite="Command Dispatch",
            payload="so?",
            expected=VerdictStatus.SAFE_ALLOW,
            severity="High",
            svap_tier=SVAPTier.TIER_4,
            description="Help dispatcher test"
        )
        verdict_help = adapter.scan(tc_help)
        self.assertEqual(verdict_help.status, VerdictStatus.SAFE_ALLOW)

    def test_python_library_adapter(self):
        py_proj = os.path.join(self.test_dir, "sample_pkg")
        os.makedirs(py_proj, exist_ok=True)
        with open(os.path.join(py_proj, "__init__.py"), "w") as f:
            f.write("__version__ = '1.0.0'\ndef add(a, b): return a + b\n")

        adapter = PythonLibraryAdapter(self.test_dir)
        self.assertTrue(adapter.setup())

        multiline_payload = """
import sample_pkg
val = sample_pkg.add(10, 20)
assert val == 30
"""
        tc_multi = TestCase(
            id="PY_MULTI_TEST",
            suite="Python Library Execution",
            payload=multiline_payload,
            expected=VerdictStatus.SAFE_ALLOW,
            severity="High",
            svap_tier=SVAPTier.TIER_3,
            description="Multiline Python execution"
        )
        verdict_multi = adapter.scan(tc_multi)
        self.assertEqual(verdict_multi.status, VerdictStatus.SAFE_ALLOW)

        tc_exc = TestCase(
            id="PY_EXC_TEST",
            suite="Boundary Exception",
            payload="raise KeyError('Intentional key error')",
            expected=VerdictStatus.SAFE_BLOCK,
            severity="Medium",
            svap_tier=SVAPTier.TIER_4,
            description="Boundary exception safety"
        )
        verdict_exc = adapter.scan(tc_exc)
        self.assertEqual(verdict_exc.status, VerdictStatus.SAFE_BLOCK)

    def test_moray_kernel_adapter(self):
        live_moray_path = "/root/home/projects/project-moray"
        if not os.path.exists(live_moray_path):
            self.skipTest("project-moray not found locally")

        adapter = MorayKernelAdapter(live_moray_path)
        self.assertTrue(adapter.setup())

        tc_exec = TestCase(
            id="MORAY_EXEC_DENIAL",
            suite="Ring 0 LSM Syscall Containment",
            payload="execve",
            expected=VerdictStatus.SAFE_BLOCK,
            severity="Critical",
            svap_tier=SVAPTier.TIER_1,
            description="Execve denial"
        )
        verdict = adapter.scan(tc_exec)
        self.assertEqual(verdict.status, VerdictStatus.SAFE_BLOCK)

        tc_fast = TestCase(
            id="MORAY_BENIGN_FASTPATH",
            suite="Benign Execution Baseline",
            payload="unquarantined_baseline",
            expected=VerdictStatus.SAFE_ALLOW,
            severity="High",
            svap_tier=SVAPTier.TIER_3,
            description="Benign baseline"
        )
        verdict_fast = adapter.scan(tc_fast)
        self.assertEqual(verdict_fast.status, VerdictStatus.SAFE_ALLOW)


if __name__ == "__main__":
    unittest.main()
