# -*- coding: utf-8 -*-
"""
🐙 Project Octopus: Universal Polyglot Security Verification and Boundary Compliance Platform
"""

__version__ = "2.0.0"
__author__ = "Angelo Ayton"

try:
    from .core.models import TargetProfile, TestCase, ScanVerdict, VerdictStatus, SVAPTier
    from .core.profiler import PolyglotProfiler
    from .core.engine import UniversalEngine
    from .core.reporter import UniversalReporter
    from .core.generator import MorayBoundaryGenerator
except ImportError:
    from core.models import TargetProfile, TestCase, ScanVerdict, VerdictStatus, SVAPTier
    from core.profiler import PolyglotProfiler
    from core.engine import UniversalEngine
    from core.reporter import UniversalReporter
    from core.generator import MorayBoundaryGenerator

__all__ = [
    "__version__",
    "__author__",
    "TargetProfile",
    "TestCase",
    "ScanVerdict",
    "VerdictStatus",
    "SVAPTier",
    "PolyglotProfiler",
    "UniversalEngine",
    "UniversalReporter",
    "MorayBoundaryGenerator",
]
