# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - C Source Semantic Scanner Adapter
Audits C source trees for legacy math calls, switch-case help fallthroughs,
cache hygiene violations, and unsafe memory primitives.
"""

import os
import re
from typing import Dict, List, Any
from .base import BaseScannerAdapter
from core.models import TargetProfile, TestCase, ScanVerdict, VerdictStatus

# Semantic rule patterns targeting upstream bug classes
SEMANTIC_PATTERNS = {
    "LEGACY_MATH_CALL": {
        "pattern": re.compile(r'\br_num_math\s*\(\s*[^,]+,\s*[^,\)]+\)'),
        "description": "Call to legacy r_num_math without error pointer (risk of silent 0x0 conversions)",
        "recommended_fix": "Replace with r_num_math_err(core->num, expr, &err)"
    },
    "MISSING_HELP_BREAK": {
        "pattern": re.compile(r'case\s+[\'\"]\?[\'\"]\s*:[^;]+;\s*(?:if|switch|case|default|[a-zA-Z0-9_]+\s*\()', re.DOTALL),
        "description": "Potential missing break; after help query in command dispatcher",
        "recommended_fix": "Add explicit break; after help handler to prevent command fallthrough"
    },
    "UNBOUNDED_STRCPY": {
        "pattern": re.compile(r'\bstrcpy\s*\('),
        "description": "Direct call to unbounded strcpy()",
        "recommended_fix": "Replace with r_str_ncpy() or bounded snprintf()"
    },
    "DANGEROUS_GETS": {
        "pattern": re.compile(r'\bgets\s*\('),
        "description": "Direct call to gets()",
        "recommended_fix": "Replace with bounded fgets() or r_cons_read()"
    }
}

class CSourceSemanticAdapter(BaseScannerAdapter):
    """Inspects C source code for boundary verification invariants."""

    def adapter_name(self) -> str:
        return "C Source Semantic Adapter (AST & Boundary Pattern Auditor)"

    def is_compatible(self, profile: TargetProfile) -> bool:
        return profile.primary_language in ("C", "C++", "C/C++ Header")

    def setup(self) -> bool:
        self.is_ready = True
        return True

    def scan(self, test_case: TestCase) -> ScanVerdict:
        rule_key = test_case.payload.strip()

        # Check if payload references a pre-defined semantic pattern or custom regex
        if rule_key in SEMANTIC_PATTERNS:
            rule_info = SEMANTIC_PATTERNS[rule_key]
            pattern = rule_info["pattern"]
            rule_desc = rule_info["description"]
        else:
            try:
                pattern = re.compile(rule_key, re.MULTILINE)
                rule_desc = f"Custom pattern: {rule_key}"
            except re.error as e:
                return ScanVerdict(
                    status=VerdictStatus.SKIPPED,
                    analysis=f"Invalid regex rule: {e}"
                )

        matches: List[str] = []
        for root, dirs, files in os.walk(self.target_path):
            # Skip build directories, test directories, and third-party dependencies relative to target
            rel_root = os.path.relpath(root, self.target_path)
            path_parts = set(rel_root.split(os.sep))
            if path_parts.intersection({".git", "subprojects", "test", "tests", "fixtures"}):
                continue

            for f in files:
                if f.endswith((".c", ".h")):
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as src:
                            content = src.read()
                            if pattern.search(content):
                                rel = os.path.relpath(fpath, self.target_path)
                                matches.append(rel)
                    except Exception:
                        pass

        # Evaluate matches against expected outcome
        if matches:
            if test_case.expected == VerdictStatus.SAFE_BLOCK:
                # Anti-pattern detected in codebase: violates contract
                return ScanVerdict(
                    status=VerdictStatus.BYPASS_FAIL,
                    analysis=f"{rule_desc} detected in {len(matches)} files (e.g. {matches[0]})",
                    extra={"matching_files": matches[:5]}
                )
            else:
                return ScanVerdict(
                    status=VerdictStatus.SAFE_ALLOW,
                    analysis=f"Required boundary check verified in {len(matches)} files",
                    extra={"matching_files": matches[:5]}
                )
        else:
            if test_case.expected == VerdictStatus.SAFE_BLOCK:
                # Clean codebase: no instances of anti-pattern
                return ScanVerdict(
                    status=VerdictStatus.SAFE_BLOCK,
                    analysis=f"Zero instances of {rule_desc} found in production source"
                )
            else:
                return ScanVerdict(
                    status=VerdictStatus.CRASH_FAIL,
                    analysis=f"Expected boundary invariant '{rule_desc}' not found in source tree"
                )
