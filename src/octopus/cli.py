#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🐙 Project Octopus: Universal Polyglot Security Verification and Boundary Compliance Platform
CLI Entry Point
"""

import sys
import os
import argparse
from datetime import datetime, timezone

try:
    from octopus.core.engine import UniversalEngine
    from octopus.core.models import VerdictStatus
    from octopus.core.generator import MorayBoundaryGenerator
except ImportError:
    # Allow running directly from script directory
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from core.engine import UniversalEngine
    from core.models import VerdictStatus
    from core.generator import MorayBoundaryGenerator


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="octopus",
        description="🐙 Project Octopus v2.0.0: Universal Upstream Security Verification Platform"
    )
    parser.add_argument(
        "--target",
        default=".",
        help="Path to project codebase to scan/verify (default: current directory)"
    )
    parser.add_argument(
        "--output-dir",
        default="./reports",
        help="Directory where Markdown, JSON, and SARIF 2.1.0 reports are written"
    )
    parser.add_argument(
        "--adapter",
        choices=["auto", "native", "python", "static", "c_source", "cli_state", "moray_kernel"],
        default="auto",
        help="Scanner adapter to execute (auto, native, python, static, c_source, cli_state, moray_kernel)"
    )
    parser.add_argument(
        "--tests",
        default=None,
        help="Path to custom test cases JSON file"
    )
    parser.add_argument(
        "--pack",
        choices=["marine_ecosystem"],
        default=None,
        help="Optional validation pack to execute (e.g. marine_ecosystem)"
    )
    parser.add_argument(
        "--generate-moray-profile",
        nargs="?",
        const="",
        default=None,
        help="Generate an autonomous boundary manifest (moray_boundary.json) from target profile"
    )
    parser.add_argument(
        "--output-manifest",
        default="moray_boundary.json",
        help="Path where generated Moray boundary manifest is saved (default: moray_boundary.json)"
    )
    parser.add_argument(
        "--profile-only",
        action="store_true",
        help="Run polyglot profiling only and output architecture findings"
    )
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    print("======================================================================")
    print("🐙 PROJECT OCTOPUS v2.0.0: UNIVERSAL UPSTREAM VERIFICATION PLATFORM")
    print("======================================================================")
    print(f"Targeting: {os.path.abspath(args.target)}")
    print(f"Time (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}\n")

    adapter_arg = None if args.adapter == "auto" else args.adapter
    engine = UniversalEngine(
        target_path=args.target,
        output_dir=args.output_dir,
        adapter_override=adapter_arg
    )

    if args.profile_only:
        print("[*] Running Polyglot Repository Profiling...")
        profile = engine.profiler.profile()
        print(f"\n[+] Polyglot Findings:")
        print(f"    - Target Path: {profile.target_path}")
        print(f"    - Total Files: {profile.files_count}")
        print(f"    - Primary Language: {profile.primary_language}")
        print(f"    - Build Systems: {', '.join(profile.build_systems) or 'None'}")
        print(f"    - Inferred Architecture: {profile.architecture_style}")
        print("\n[+] Top Languages:")
        for lang, count in list(profile.languages.items())[:6]:
            print(f"    * {lang:<16}: {count} files")
        print("\n[+] Capability Matrix:")
        for cap, data in profile.capabilities.items():
            sym = "🟢 [Active]" if data["active"] else "⚪ [Inactive]"
            print(f"    {sym:<12} {cap.upper():<18} -> {data['description']}")
        print("\n======================================================================")
        return

    # Optional Moray boundary generation
    if args.generate_moray_profile is not None:
        target_to_profile = args.generate_moray_profile if args.generate_moray_profile != "" else args.target
        print(f"[*] Autonomous Boundary Profiling: Generating Moray boundary manifest for {target_to_profile}...")
        gen = MorayBoundaryGenerator(target_to_profile)
        manifest_path = gen.generate(args.output_manifest)
        print(f"[+] Moray Ring 0 Boundary Manifest successfully written to: {manifest_path}\n")

    # Run verification suite
    print("[*] Dispatching Universal Verification Run...")
    results = engine.run(
        custom_test_file=args.tests,
        pack_name=args.pack
    )

    profile = results["profile"]
    verdicts = results.get("results", [])
    stats = results.get("stats", {})
    reports = results.get("reports", {})
    adapter_name = results.get("adapter", "None")

    print("\n[+] Project Profile Findings:")
    print(f"    - Primary Language: {profile.primary_language}")
    print(f"    - Inferred Architecture: {profile.architecture_style}")
    print(f"    - Build Systems: {', '.join(profile.build_systems) or 'None'}")
    print(f"    - Scanner Adapter Resolved: {adapter_name}\n")

    print("[+] Verification Results:")
    for v in verdicts:
        status_val = v["status"].value if hasattr(v["status"], "value") else str(v["status"])
        if status_val in ("SAFE_BLOCK", "SAFE_ALLOW"):
            icon = "🟢"
        elif status_val in ("CRASH_FAIL", "BYPASS_FAIL"):
            icon = "🔴"
        else:
            icon = "⚪"
        test_id = v.get("id", v.get("test_id", "unknown"))
        details = v.get("analysis", v.get("details", ""))
        print(f"    * {icon} [{v['suite']}] `{test_id}` ({v['severity']}): {status_val}")
        if details:
            print(f"      Details: {details}")

    # Pack results if executed
    if results.get("pack_results"):
        print(f"\n[+] Validation Pack Execution: {args.pack}")
        for pr in results["pack_results"]:
            icon = "🟢" if pr.get("status") in ("PASSED", "BLOCKED") else "🔴"
            print(f"    * {icon} [{pr.get('suite', 'Pack')}] `{pr.get('test', 'unknown')}`: {pr.get('status')} - {pr.get('details', '')}")

    evaluated = stats.get("evaluated", len(verdicts))
    passed = stats.get("passed", 0)
    crashed = stats.get("crashed", 0)
    bypassed = stats.get("bypassed", 0)
    na_count = stats.get("not_applicable", 0)
    skipped = stats.get("skipped", 0)
    compliance_score = round((passed / evaluated * 100.0), 1) if evaluated > 0 else 100.0

    print("\n" + "="*70)
    print(f"VERIFICATION SUMMARY: {passed}/{evaluated} boundary tests passed ({compliance_score}%)")
    print(f"  - 🟢 Passed (Blocked / Allowed): {passed}")
    print(f"  - 🔴 Crashed (SIGSEGV / Fault):  {crashed}")
    print(f"  - 🔴 Bypassed (Missing Clamp):   {bypassed}")
    print(f"  - ⚪ Not Applicable (Excluded):  {na_count}")
    print(f"  - ⚪ Skipped (Tool Missing):     {skipped}")
    print("="*70)
    print(f"[+] Markdown Report: {reports.get('markdown')}")
    print(f"[+] Summary JSON:    {reports.get('json')}")
    print(f"[+] SARIF 2.1.0:     {reports.get('sarif')}")
    print("======================================================================\n")

    # Fail closed on crashes or bypasses
    if crashed > 0 or bypassed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
