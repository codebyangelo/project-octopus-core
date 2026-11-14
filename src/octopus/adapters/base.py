# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - Base Scanner Adapter Interface
"""

from abc import ABC, abstractmethod
from typing import Optional

try:
    from ..core.models import TargetProfile, TestCase, ScanVerdict
except (ImportError, ValueError):
    try:
        from octopus.core.models import TargetProfile, TestCase, ScanVerdict
    except ImportError:
        from core.models import TargetProfile, TestCase, ScanVerdict

class BaseScannerAdapter(ABC):
    """Abstract base class for all Project Octopus verification adapters."""
    
    def __init__(self, target_path: str):
        self.target_path = target_path
        self.is_ready = False

    @abstractmethod
    def adapter_name(self) -> str:
        """User-friendly name of the adapter."""
        pass

    @abstractmethod
    def is_compatible(self, profile: TargetProfile) -> bool:
        """Determines if this adapter can execute against the profiled target."""
        pass

    @abstractmethod
    def setup(self) -> bool:
        """Prepares any binary paths, mock harnesses, or subprocess pipes."""
        pass

    @abstractmethod
    def scan(self, test_case: TestCase) -> ScanVerdict:
        """Executes a test case payload against the target boundary."""
        pass

    def teardown(self) -> None:
        """Cleans up temporary processes, FIFOs, or test fixtures."""
        pass
