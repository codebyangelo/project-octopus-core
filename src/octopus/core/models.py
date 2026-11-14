# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - Core Domain Models & Verdict Taxonomy
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

class VerdictStatus(str, Enum):
    SAFE_BLOCK = "SAFE_BLOCK"       # Cleanly blocked / rejected by boundary
    SAFE_ALLOW = "SAFE_ALLOW"       # Clean benign execution
    CRASH_FAIL = "CRASH_FAIL"       # Process crashed (SIGSEGV, SIGABRT, unhandled exception)
    BYPASS_FAIL = "BYPASS_FAIL"     # Malicious payload bypassed boundary
    NOT_APPLICABLE = "NOT_APPLICABLE" # Test suite boundary not applicable to target
    SKIPPED = "SKIPPED"             # Test skipped (missing compiler/tool)

class SVAPTier(str, Enum):
    TIER_1 = "Tier 1: Memory Safety & Corruption"
    TIER_2 = "Tier 2: State & Memory Integrity"
    TIER_3 = "Tier 3: Tooling & Analysis Boundaries"
    TIER_4 = "Tier 4: Parser Robustness / Edge-Case DoS"
    TIER_5 = "Tier 5: Software Hygiene & Diagnostics"

@dataclass
class ScanVerdict:
    status: VerdictStatus
    analysis: str
    returncode: Optional[int] = None
    signal: Optional[int] = None
    latency_ms: float = 0.0
    stdout: str = ""
    stderr: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TargetProfile:
    target_path: str
    files_count: int
    languages: Dict[str, int]
    primary_language: str
    build_systems: List[str]
    key_files: List[str]
    architecture_style: str
    capabilities: Dict[str, Dict[str, Any]]
    risk_findings: List[Dict[str, Any]]
    dependency_graph: str

@dataclass
class TestCase:
    id: str
    suite: str
    payload: str
    expected: VerdictStatus
    severity: str = "Medium"
    svap_tier: SVAPTier = SVAPTier.TIER_4
    description: str = ""
    context_type: str = "raw"
