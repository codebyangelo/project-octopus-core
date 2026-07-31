# -*- coding: utf-8 -*-
"""
🐙 Project Octopus Pluggable Validator SDK - Base Validator Definition
"""

class BaseValidator:
    """Base class for all Project Octopus pluggable validators."""
    
    def name(self) -> str:
        """Returns the user-friendly name of this validator."""
        raise NotImplementedError
        
    def description(self) -> str:
        """Returns a short description of what this validator verifies."""
        raise NotImplementedError
        
    def profile_key(self) -> str:
        """Returns the profile key this validator belongs to (e.g. optimizer, security_proxy, etc.)."""
        raise NotImplementedError
        
    def run(self, target_path: str, scanner) -> list:
        """
        Executes the validation audits.
        Returns a list of result dictionaries:
        [{
            "suite": str,
            "test_name": str,
            "status": "PASSED" | "WARNING" | "FAILED",
            "detail": str
        }]
        """
        raise NotImplementedError
