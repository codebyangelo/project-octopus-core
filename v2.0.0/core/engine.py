# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - Universal Verification Engine
Coordinates polyglot profiling, adapter resolution, test execution, and reporting.
"""

import os
import sys
import json
from typing import Dict, List, Optional, Any

from .models import TargetProfile, TestCase, ScanVerdict, VerdictStatus, SVAPTier
from .profiler import PolyglotProfiler
from .reporter import UniversalReporter
from adapters.base import BaseScannerAdapter
from adapters.native_binary import NativeBinaryAdapter
from adapters.python_library import PythonLibraryAdapter
from adapters.static_rule import StaticRuleAdapter
from adapters.c_source import CSourceSemanticAdapter
from adapters.cli_state import CLIStateIntegrityAdapter
from adapters.moray_kernel import MorayKernelAdapter

class UniversalEngine:
    def __init__(self, target_path: str, output_dir: str = "./reports", adapter_override: Optional[str] = None):
        self.target_path = os.path.abspath(target_path)
        self.output_dir = os.path.abspath(output_dir)
        self.adapter_override = adapter_override
        self.profiler = PolyglotProfiler(self.target_path)
        self.reporter = UniversalReporter(self.output_dir)
        self.active_adapter: Optional[BaseScannerAdapter] = None

    def run(self, custom_test_file: Optional[str] = None, pack_name: Optional[str] = None) -> Dict[str, Any]:
        # 1. Profile Target
        profile = self.profiler.profile()

        # 2. Select & Initialize Scanner Adapter
        self.active_adapter = self._resolve_adapter(profile)
        adapter_name = self.active_adapter.adapter_name() if self.active_adapter else "None"

        # 3. Load Applicable Test Cases
        test_cases = self._load_test_cases(profile, custom_test_file)

        # 4. Optional Validation Pack Execution
        pack_results = []
        if pack_name == "marine_ecosystem":
            root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            if root_dir not in sys.path:
                sys.path.insert(0, root_dir)
            try:
                from packs.marine_ecosystem import MarineEcosystemPack
                pack = MarineEcosystemPack()
                if os.path.exists(os.path.join(self.target_path, "lobster_hook.py")) or "lobster" in self.target_path.lower():
                    pack_results.extend(pack.run_lobster_compliance(self.target_path))
                if os.path.exists(os.path.join(self.target_path, "hermit_hook.py")) or "hermit" in self.target_path.lower():
                    pack_results.extend(pack.run_hermit_compliance(self.target_path))
                if profile.capabilities.get("kernel_ebpf", {}).get("active") or os.path.exists(os.path.join(self.target_path, "src", "moray.h")):
                    pack_results.extend(pack.run_moray_compliance(self.target_path))
            except Exception as e:
                pack_results.append({
                    "suite": "Marine Ecosystem Pack",
                    "test": "Pack Loading",
                    "status": "FAILED",
                    "detail": str(e)
                })

        # 5. Execute Test Matrix
        results = []
        stats = {
            "evaluated": 0,
            "passed": 0,
            "crashed": 0,
            "bypassed": 0,
            "not_applicable": 0,
            "skipped": 0
        }

        for tc in test_cases:
            if not self.active_adapter or not self.active_adapter.is_ready:
                verdict = ScanVerdict(
                    status=VerdictStatus.SKIPPED,
                    analysis="No compatible scanner adapter available"
                )
            else:
                verdict = self.active_adapter.scan(tc)

            # Accumulate 5-state statistics
            if verdict.status in (VerdictStatus.SAFE_BLOCK, VerdictStatus.SAFE_ALLOW):
                stats["passed"] += 1
                stats["evaluated"] += 1
            elif verdict.status == VerdictStatus.CRASH_FAIL:
                stats["crashed"] += 1
                stats["evaluated"] += 1
            elif verdict.status == VerdictStatus.BYPASS_FAIL:
                stats["bypassed"] += 1
                stats["evaluated"] += 1
            elif verdict.status == VerdictStatus.NOT_APPLICABLE:
                stats["not_applicable"] += 1
            elif verdict.status == VerdictStatus.SKIPPED:
                stats["skipped"] += 1

            results.append({
                "id": tc.id,
                "suite": tc.suite,
                "severity": tc.severity,
                "svap_tier": tc.svap_tier.value,
                "description": tc.description,
                "status": verdict.status,
                "analysis": verdict.analysis,
                "latency_ms": verdict.latency_ms,
                "returncode": verdict.returncode,
                "signal": verdict.signal
            })

        # Teardown adapter if initialized
        if self.active_adapter:
            self.active_adapter.teardown()

        # 5. Generate Reports
        report_files = self.reporter.write_reports(profile, results, stats, adapter_name)

        return {
            "profile": profile,
            "adapter": adapter_name,
            "stats": stats,
            "results": results,
            "pack_results": pack_results,
            "reports": report_files
        }

    def _resolve_adapter(self, profile: TargetProfile) -> BaseScannerAdapter:
        # All available adapters
        adapter_map = {
            "moray_kernel": MorayKernelAdapter(self.target_path),
            "native": NativeBinaryAdapter(self.target_path),
            "python": PythonLibraryAdapter(self.target_path),
            "static": StaticRuleAdapter(self.target_path),
            "c_source": CSourceSemanticAdapter(self.target_path),
            "cli_state": CLIStateIntegrityAdapter(self.target_path)
        }

        # Explicit user override
        if self.adapter_override:
            override_key = self.adapter_override.lower()
            if override_key in adapter_map:
                ad = adapter_map[override_key]
                ad.setup()
                return ad

        # Candidate order prioritized by language and capabilities
        if profile.capabilities.get("kernel_ebpf", {}).get("active"):
            candidate_order = [
                adapter_map["moray_kernel"],
                adapter_map["c_source"],
                adapter_map["native"],
                adapter_map["static"]
            ]
        elif profile.primary_language in ("Python", "Python Stub"):
            candidate_order = [
                adapter_map["python"],
                adapter_map["static"],
                adapter_map["native"]
            ]
        elif profile.primary_language in ("C", "C++", "C/C++ Header"):
            candidate_order = [
                adapter_map["c_source"],
                adapter_map["native"],
                adapter_map["cli_state"],
                adapter_map["static"]
            ]
        else:
            candidate_order = [
                adapter_map["native"],
                adapter_map["static"],
                adapter_map["python"]
            ]

        # Automatic detection
        for ad in candidate_order:
            if ad.is_compatible(profile):
                if ad.setup():
                    return ad

        # Fallback to static rule adapter
        static_ad = adapter_map["static"]
        static_ad.setup()
        return static_ad

    def _load_test_cases(self, profile: TargetProfile, custom_test_file: Optional[str]) -> List[TestCase]:
        cases: List[TestCase] = []
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        file_to_load = custom_test_file
        if not file_to_load:
            if isinstance(self.active_adapter, MorayKernelAdapter):
                file_to_load = os.path.join(base_dir, "test_cases", "moray_kernel_containment.json")
            elif isinstance(self.active_adapter, CSourceSemanticAdapter):
                file_to_load = os.path.join(base_dir, "test_cases", "upstream_c_source.json")
            elif isinstance(self.active_adapter, PythonLibraryAdapter) or profile.primary_language in ("Python", "Python Stub"):
                file_to_load = os.path.join(base_dir, "test_cases", "upstream_python.json")
            else:
                file_to_load = os.path.join(base_dir, "test_cases", "upstream_native.json")

        if file_to_load and os.path.exists(file_to_load):
            with open(file_to_load, "r", encoding="utf-8") as f:
                raw_cases = json.load(f)
                for item in raw_cases:
                    cases.append(TestCase(
                        id=item["id"],
                        suite=item["suite"],
                        payload=item["payload"],
                        expected=VerdictStatus(item["expected"]),
                        severity=item.get("severity", "Medium"),
                        svap_tier=SVAPTier(item.get("svap_tier", SVAPTier.TIER_4.value)),
                        description=item.get("description", "")
                    ))
        return cases
