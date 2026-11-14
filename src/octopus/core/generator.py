# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - Moray Boundary Manifest Generator
Synthesizes PolyglotProfiler analysis into an authoritative, machine-readable
boundary manifest (moray_boundary.json) for zero-configuration morayd startup.
"""

import os
import json
import shutil
from datetime import datetime, timezone
from typing import Dict, List, Set, Any
from .models import TargetProfile

class MorayBoundaryGenerator:
    """Derives permitted process comms, binary paths, and network posture from target profile."""

    def __init__(self, profile: TargetProfile):
        self.profile = profile
        self.target_path = os.path.abspath(profile.target_path)

    def generate(self) -> Dict[str, Any]:
        target_name = os.path.basename(self.target_path)
        allowed_comms: Set[str] = set()
        allowed_paths: Set[str] = set()

        # 1. Base Runtime Interpreters & Toolchains based on detected languages and build systems
        if "Python" in self.profile.languages:
            allowed_comms.update(["python", "python3", "pytest", "ruff"])
            py3_path = shutil.which("python3")
            if py3_path:
                allowed_paths.add(py3_path)

        if any(lang in self.profile.languages for lang in ("C", "C++", "C/C++ Header", "Assembly")):
            allowed_comms.update(["gcc", "clang", "make", "ld", "as", "tcc"])
            make_path = shutil.which("make")
            if make_path:
                allowed_paths.add(make_path)

        if "Rust" in self.profile.languages:
            allowed_comms.update(["cargo", "rustc"])

        if "Shell" in self.profile.languages:
            allowed_comms.update(["bash", "sh", "true", "ls", "cat", "mkdir", "rm"])

        # 2. Add Target CLI Executables Discovered in target_path
        bin_dir = os.path.join(self.target_path, "bin")
        if os.path.exists(bin_dir) and os.path.isdir(bin_dir):
            for f in os.listdir(bin_dir):
                full = os.path.join(bin_dir, f)
                if os.path.isfile(full) and os.access(full, os.X_OK):
                    allowed_comms.add(f)
                    allowed_paths.add(full)

        # 3. Discover Project Daemons and Workers Structurally
        src_dir = os.path.join(self.target_path, "src")
        if os.path.isdir(src_dir):
            for root_dir, _, files in os.walk(src_dir):
                for f in files:
                    if f.endswith(".c"):
                        stem = os.path.splitext(f)[0]
                        if stem.endswith("d") or "worker" in stem:
                            allowed_comms.add(stem)
                            cand_bin = os.path.join(self.target_path, "bin", stem)
                            if os.path.exists(cand_bin):
                                allowed_paths.add(cand_bin)

        # Also discover test victim workers if present
        tests_dir = os.path.join(self.target_path, "tests")
        if os.path.isdir(tests_dir):
            for root_dir, _, files in os.walk(tests_dir):
                for f in files:
                    if f.endswith(".c") and "worker" in f:
                        stem = os.path.splitext(f)[0]
                        allowed_comms.add(stem)
                        cand_bin = os.path.join(self.target_path, "bin", stem)
                        if os.path.exists(cand_bin):
                            allowed_paths.add(cand_bin)

        # 4. Network Posture Deduction
        # Default to safe local loopback / IPC unless declared network server or remote RPC active
        has_net_server = self.profile.capabilities.get("network_server", {}).get("active", False)
        if has_net_server:
            network_posture = "REQUIRE_WAN"
        else:
            network_posture = "ALLOW_LOOPBACK"

        # 5. Build Canonical Manifest Object
        manifest = {
            "version": "1.0.0",
            "target_name": target_name,
            "target_path": self.target_path,
            "generated_by": "Project Octopus v2.0.0 (PolyglotProfiler & BoundaryGenerator)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "primary_language": self.profile.primary_language,
            "architecture_style": self.profile.architecture_style,
            "boundary_policy": {
                "default_action": "AUTONOMOUS_STRIKE",
                "allowed_comms": sorted(list(allowed_comms)),
                "allowed_paths": sorted(list(allowed_paths)),
                "network_posture": network_posture,
                "cgroup_slice": "agent.slice",
                "auto_quarantine_violations": True,
                "max_strike_threshold": 5
            }
        }
        return manifest

    def write_manifest(self, output_file: str = "moray_boundary.json") -> Dict[str, Any]:
        manifest = self.generate()
        out_dir = os.path.dirname(os.path.abspath(output_file))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        return manifest
