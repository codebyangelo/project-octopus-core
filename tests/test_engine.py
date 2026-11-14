# -*- coding: utf-8 -*-
"""
Tests for Project Octopus UniversalEngine and Reporting
"""

import os
import json
import shutil
import tempfile
import unittest

from octopus.core.engine import UniversalEngine
from octopus.core.models import VerdictStatus
from octopus.core.profiler import PolyglotProfiler
from octopus.core.reporter import UniversalReporter


class TestUniversalEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_octopus_engine_")
        self.reports_dir = os.path.join(self.test_dir, "reports")
        os.makedirs(self.reports_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_universal_reporter_outputs(self):
        profiler = PolyglotProfiler(self.test_dir)
        profile = profiler.profile()

        reporter = UniversalReporter(self.reports_dir)

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

    def test_engine_run_on_self(self):
        engine = UniversalEngine(
            target_path=self.test_dir,
            output_dir=self.reports_dir
        )
        run_output = engine.run()
        self.assertIn("profile", run_output)
        self.assertIn("adapter", run_output)
        self.assertIn("stats", run_output)
        self.assertIn("results", run_output)
        self.assertIn("reports", run_output)
        self.assertTrue(os.path.exists(run_output["reports"]["markdown"]))
        self.assertTrue(os.path.exists(run_output["reports"]["json"]))
        self.assertTrue(os.path.exists(run_output["reports"]["sarif"]))


if __name__ == "__main__":
    unittest.main()
