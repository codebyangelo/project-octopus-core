# -*- coding: utf-8 -*-
"""
Tests for Project Octopus PolyglotProfiler
"""

import os
import shutil
import tempfile
import unittest

from octopus.core.profiler import PolyglotProfiler


class TestPolyglotProfiler(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_octopus_profiler_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

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
        # In v2.0.0 with strict word boundaries, these must NOT falsely trigger.
        self.assertFalse(profile.capabilities["database"]["active"], "deadblock_remover.py must not trigger database")
        self.assertFalse(profile.capabilities["native_cli"]["active"], "clinic.py and getuid.py must not trigger native_cli")

    def test_polyglot_profiler_ebpf_containment_subsystem(self):
        ebpf_proj = os.path.join(self.test_dir, "mock_ebpf")
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


if __name__ == "__main__":
    unittest.main()
