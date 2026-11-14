#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0: Universal Upstream Security Verification Platform
"""

import sys
import os
import argparse
from datetime import datetime, timezone

# Add v2.0.0 root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import UniversalEngine
from core.models import VerdictStatus
from core.generator import MorayBoundaryGenerator

def main():
    parser = argparse.ArgumentParser(
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

    # Run complete verification
    run_output = engine.run(custom_test_file=args.tests, pack_name=args.pack)
    profile = run_output["profile"]
    adapter_name = run_output["adapter"]
    stats = run_output["stats"]
    results = run_output["results"]
    pack_results = run_output.get("pack_results", [])
    reports = run_output["reports"]

    print("[+] Project Profile Findings:")
    print(f"    - Primary Language: {profile.primary_language}")
    print(f"    - Inferred Architecture: {profile.architecture_style}")
    print(f"    - Build Systems: {', '.join(profile.build_systems) or 'None'}")
    print(f"    - Scanner Adapter Resolved: {adapter_name}\n")

    print("[+] Verification Results:")
    for r in results:
        status_sym = (
            "🟢" if r["status"] in (VerdictStatus.SAFE_BLOCK, VerdictStatus.SAFE_ALLOW)
            else "🔴" if r["status"] in (VerdictStatus.CRASH_FAIL, VerdictStatus.BYPASS_FAIL)
            else "⚪"
        )
        print(f"    * {status_sym} [{r['suite']}] `{r['id']}` ({r['severity']}): {r['status'].value}")
        print(f"      Details: {r['analysis']}")

    eval_cnt = stats["evaluated"]
    passed_cnt = stats["passed"]
    score_pct = (passed_cnt / eval_cnt * 100.0) if eval_cnt > 0 else 100.0

    if pack_results:
        print("\n[+] Validation Pack Findings:")
        for pr in pack_results:
            p_sym = "🟢" if pr["status"] == "PASSED" else "🟡" if pr["status"] == "WARNING" else "🔴"
            print(f"    * {p_sym} [{pr['suite']}] {pr['test']}: {pr['status']}")
            print(f"      Details: {pr['detail']}")

    print("\n======================================================================")
    print(f"VERIFICATION SUMMARY: {passed_cnt}/{eval_cnt} boundary tests passed ({score_pct:.1f}%)")
    print(f"  - 🟢 Passed (Blocked / Allowed): {passed_cnt}")
    print(f"  - 🔴 Crashed (SIGSEGV / Fault):  {stats['crashed']}")
    print(f"  - 🔴 Bypassed (Missing Clamp):   {stats['bypassed']}")
    print(f"  - ⚪ Not Applicable (Excluded):  {stats['not_applicable']}")
    print(f"  - ⚪ Skipped (Tool Missing):     {stats['skipped']}")
    if args.generate_moray_profile is not None:
        gen_target = args.generate_moray_profile if len(args.generate_moray_profile) > 0 else args.target
        gen_engine = UniversalEngine(target_path=gen_target)
        gen_profile = gen_engine.profiler.profile()
        generator = MorayBoundaryGenerator(gen_profile)
        manifest_path = os.path.abspath(args.output_manifest)
        manifest = generator.write_manifest(manifest_path)
        print(f"\n[+] Autonomous Boundary Manifest Generated: {manifest_path}")
        print(f"    - Target Name: {manifest['target_name']}")
        print(f"    - Allowed Comms: {', '.join(manifest['boundary_policy']['allowed_comms'])}")
        print(f"    - Network Posture: {manifest['boundary_policy']['network_posture']}")
        print(f"    - Default Action: {manifest['boundary_policy']['default_action']}")

    print("\nDeliverable Reports:")
    print(f"  - Markdown: {reports['markdown']}")
    print(f"  - Summary:  {reports['json']}")
    print(f"  - SARIF:    {reports['sarif']}")
    print("======================================================================")

if __name__ == "__main__":
    main()
