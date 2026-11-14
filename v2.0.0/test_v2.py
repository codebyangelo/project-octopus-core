# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - Unit Test Suite
Verifies polyglot profiling, strict word boundary tokenization, adapters, and reporting.
"""

import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.models import VerdictStatus, SVAPTier, TestCase, ScanVerdict
from core.profiler import PolyglotProfiler
from core.engine import UniversalEngine
from core.reporter import UniversalReporter
from adapters.static_rule import StaticRuleAdapter
from adapters.c_source import CSourceSemanticAdapter
from adapters.cli_state import CLIStateIntegrityAdapter
from adapters.python_library import PythonLibraryAdapter

class TestUniversalOctopus(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="octopus_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_polyglot_profiler_c_project(self):
        # Create a mock C disassembler project
        os.makedirs(os.path.join(self.test_dir, "libr", "core"), exist_ok=True)
        os.makedirs(os.path.join(self.test_dir, "binr", "r2"), exist_ok=True)

        with open(os.path.join(self.test_dir, "meson.build"), "w") as f:
            f.write("project('mock-r2', 'c')\n")
        with open(os.path.join(self.test_dir, "libr", "core", "core.c"), "w") as f:
            f.write("int main() { return 0; }\n")
        with open(os.path.join(self.test_dir, "binr", "r2", "main.c"), "w") as f:
            f.write("int main() { return 0; }\n")

        profiler = PolyglotProfiler(self.test_dir)
        profile = profiler.profile()

        self.assertEqual(profile.primary_language, "C")
        self.assertIn("Meson", profile.build_systems)
        self.assertTrue(profile.capabilities["native_cli"]["active"])
        self.assertTrue(profile.capabilities["binary_analysis"]["active"])
        self.assertIn("Binary Analysis & Reverse Engineering", profile.architecture_style)
        self.assertFalse(profile.capabilities["database"]["active"])

    def test_strict_token_boundary_no_substring_collisions(self):
        # Create files that caused collisions in v1.0.6: deadblock_remover.py, getuid.py, clinic.py
        os.makedirs(os.path.join(self.test_dir, "src"), exist_ok=True)
        with open(os.path.join(self.test_dir, "src", "deadblock_remover.py"), "w") as f:
            f.write("# Dead code eliminator\n")
        with open(os.path.join(self.test_dir, "src", "getuid.py"), "w") as f:
            f.write("def getuid(): return 1000\n")
        with open(os.path.join(self.test_dir, "src", "clinic.py"), "w") as f:
            f.write("class Clinic: pass\n")

        profiler = PolyglotProfiler(self.test_dir)
        profile = profiler.profile()

        # In v1.0.6, 'deadblock' triggered database, and 'getuid' (tui) + 'clinic' (cli) triggered CLI.
        # In v2.0.0 with strict word boundaries, these must NOT falsely trigger!
        self.assertFalse(profile.capabilities["database"]["active"], "deadblock_remover.py must not trigger database")
        self.assertFalse(profile.capabilities["native_cli"]["active"], "clinic.py and getuid.py must not trigger native_cli")

    def test_universal_reporter_outputs(self):
        profiler = PolyglotProfiler(self.test_dir)
        profile = profiler.profile()

        out_dir = os.path.join(self.test_dir, "reports")
        reporter = UniversalReporter(out_dir)

        results = [{
            "id": "TEST_01",
            "suite": "Boundary Clamping",
            "severity": "High",
            "svap_tier": "Tier 2: State & Memory Integrity",
            "description": "Test description",
            "status": VerdictStatus.SAFE_BLOCK,
            "analysis": "Input clamped cleanly",
            "latency_ms": 1.2
        }]
        stats = {
            "evaluated": 1,
            "passed": 1,
            "crashed": 0,
            "bypassed": 0,
            "not_applicable": 0,
            "skipped": 0
        }

        reports = reporter.write_reports(profile, results, stats, "MockAdapter")
        self.assertTrue(os.path.exists(reports["markdown"]))
        self.assertTrue(os.path.exists(reports["json"]))
        self.assertTrue(os.path.exists(reports["sarif"]))

        with open(reports["markdown"], "r") as f:
            md = f.read()
            self.assertIn("100.0%", md)
            self.assertNotIn("IronDome", md, "Hardcoded Lobster WAF flowchart must be purged")

    def test_marine_ecosystem_pack_opt_in(self):
        # Create a mock Lobster project structure
        lobster_dir = os.path.join(self.test_dir, "project-lobster")
        os.makedirs(os.path.join(lobster_dir, "src"), exist_ok=True)
        os.makedirs(os.path.join(lobster_dir, "data"), exist_ok=True)

        with open(os.path.join(lobster_dir, "src", "core.py"), "w") as f:
            f.write("# Lobster core pipeline\n")
        with open(os.path.join(lobster_dir, "data", "threat_db.json"), "w") as f:
            f.write('{"threats": [{"id": 1}]}\n')

        engine = UniversalEngine(lobster_dir)
        run_output = engine.run(pack_name="marine_ecosystem")
        pack_results = run_output.get("pack_results", [])

        self.assertTrue(len(pack_results) >= 2)
        tests_passed = [pr["test"] for pr in pack_results if pr["status"] == "PASSED"]
        self.assertIn("Threat Database Serialization", tests_passed)
        self.assertIn("Core Pipeline Discovery", tests_passed)

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

        # Create mock radare2 executable script
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

        # Test state preservation
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

        # Test help dispatcher
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

        # Test multiline python statement execution
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

        # Test boundary exception trapping
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

    def test_polyglot_profiler_ebpf_containment_subsystem(self):
        # Create a mock eBPF containment project with test scripts exceeding C files in count
        ebpf_proj = os.path.join(self.test_dir, "project-moray-mock")
        os.makedirs(os.path.join(ebpf_proj, "src"), exist_ok=True)
        os.makedirs(os.path.join(ebpf_proj, "tests"), exist_ok=True)

        with open(os.path.join(ebpf_proj, "Makefile"), "w") as f:
            f.write("all: build\n")
        with open(os.path.join(ebpf_proj, "src", "moray_kern.bpf.c"), "w") as f:
            f.write("// BPF LSM hooks\n")
        with open(os.path.join(ebpf_proj, "src", "morayd.c"), "w") as f:
            f.write("int main() { return 0; }\n")
        # Add 5 python test files to ensure test harness does not skew primary language
        for i in range(5):
            with open(os.path.join(ebpf_proj, "tests", f"test_harness_{i}.py"), "w") as f:
                f.write("# Python test file\n")

        profiler = PolyglotProfiler(ebpf_proj)
        profile = profiler.profile()

        self.assertEqual(profile.primary_language, "C")
        self.assertTrue(profile.capabilities["kernel_ebpf"]["active"])
        self.assertTrue(profile.capabilities["native_cli"]["active"])
        self.assertTrue(profile.capabilities["sandbox"]["active"])
        self.assertIn("Ring 0 eBPF Containment", profile.architecture_style)

        # Ground-truth verification against actual local project-moray if present
        live_moray_path = "/root/home/projects/project-moray"
        if os.path.exists(live_moray_path):
            live_profile = PolyglotProfiler(live_moray_path).profile()
            self.assertEqual(live_profile.primary_language, "C")
            self.assertTrue(live_profile.capabilities["kernel_ebpf"]["active"])
            self.assertTrue(live_profile.capabilities["native_cli"]["active"])
            self.assertEqual(
                live_profile.architecture_style,
                "Linux Ring 0 eBPF Containment & Security Subsystem (BPF-LSM / XDP)"
            )

    def test_marine_ecosystem_pack_moray_compliance(self):
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root_dir not in sys.path:
            sys.path.insert(0, root_dir)
        from packs.marine_ecosystem import MarineEcosystemPack

        pack = MarineEcosystemPack()
        self.assertTrue(pack.is_target_compatible("/path/to/project-moray"))

        live_moray_path = "/root/home/projects/project-moray"
        if os.path.exists(live_moray_path):
            results = pack.run_moray_compliance(live_moray_path)
            self.assertEqual(len(results), 4)
            for r in results:
                self.assertEqual(r["status"], "PASSED", f"Audit {r['test']} failed: {r}")

    def test_moray_kernel_adapter(self):
        from adapters.moray_kernel import MorayKernelAdapter
        live_moray_path = "/root/home/projects/project-moray"
        if not os.path.exists(live_moray_path):
            return

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

        adapter.teardown()

    def test_moray_boundary_generator(self):
        from core.generator import MorayBoundaryGenerator
        live_moray_path = "/root/home/projects/project-moray"
        if not os.path.exists(live_moray_path):
            return

        profiler = PolyglotProfiler(live_moray_path)
        profile = profiler.profile()
        generator = MorayBoundaryGenerator(profile)
        manifest = generator.generate()

        self.assertEqual(manifest["version"], "1.0.0")
        self.assertEqual(manifest["target_name"], "project-moray")
        self.assertEqual(manifest["boundary_policy"]["default_action"], "AUTONOMOUS_STRIKE")
        self.assertEqual(manifest["boundary_policy"]["network_posture"], "ALLOW_LOOPBACK")
        self.assertIn("morayd", manifest["boundary_policy"]["allowed_comms"])
        self.assertIn("python3", manifest["boundary_policy"]["allowed_comms"])
        self.assertIn("make", manifest["boundary_policy"]["allowed_comms"])

        out_path = os.path.join(self.test_dir, "test_manifest.json")
        generator.write_manifest(out_path)
        self.assertTrue(os.path.exists(out_path))

if __name__ == "__main__":
    unittest.main()
