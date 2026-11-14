# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - Static Rule Scanner Adapter
Performs static code boundary verification when dynamic execution is not applicable.
"""

import os
import re
from .base import BaseScannerAdapter
from core.models import TargetProfile, TestCase, ScanVerdict, VerdictStatus

class StaticRuleAdapter(BaseScannerAdapter):
    """Audits code repositories statically against boundary integrity rules."""

    def adapter_name(self) -> str:
        return "Static Rule Adapter (Source & AST Boundary Checks)"

    def is_compatible(self, profile: TargetProfile) -> bool:
        return True  # Applicable to all codebases

    def setup(self) -> bool:
        self.is_ready = True
        return True

    def scan(self, test_case: TestCase) -> ScanVerdict:
        # Check payload pattern across production files
        payload = test_case.payload.strip()
        from .c_source import SEMANTIC_PATTERNS
        if payload in SEMANTIC_PATTERNS:
            pattern = SEMANTIC_PATTERNS[payload]["pattern"]
        else:
            try:
                pattern = re.compile(payload, re.MULTILINE)
            except re.error as e:
                return ScanVerdict(
                    status=VerdictStatus.SKIPPED,
                    analysis=f"Invalid regex rule: {e}"
                )

        matches = []
        for root, dirs, files in os.walk(self.target_path):
            rel_root = os.path.relpath(root, self.target_path)
            path_parts = set(rel_root.split(os.sep))
            if path_parts.intersection({".git", "subprojects", "test", "tests"}):
                continue
            for f in files:
                if f.endswith((".c", ".h", ".py", ".rs", ".go")):
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as src:
                            content = src.read()
                            if pattern.search(content):
                                matches.append(os.path.relpath(fpath, self.target_path))
                    except Exception:
                        pass

        if matches:
            if test_case.expected == VerdictStatus.SAFE_ALLOW:
                return ScanVerdict(
                    status=VerdictStatus.SAFE_ALLOW,
                    analysis=f"Required boundary control matched in {len(matches)} files: {', '.join(matches[:3])}"
                )
            else:
                return ScanVerdict(
                    status=VerdictStatus.BYPASS_FAIL,
                    analysis=f"Anti-pattern matched in {len(matches)} files: {', '.join(matches[:3])}"
                )
        else:
            if test_case.expected == VerdictStatus.SAFE_BLOCK:
                return ScanVerdict(
                    status=VerdictStatus.SAFE_BLOCK,
                    analysis="No instances of target anti-pattern detected in production code"
                )
            else:
                return ScanVerdict(
                    status=VerdictStatus.CRASH_FAIL,
                    analysis="Required boundary check not found in codebase"
                )
