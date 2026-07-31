#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🐙 Project Octopus: Security Regression & Defensive Rule Validation Suite
Log everything, maintain transparency, and verify the robustness of security shields
like Project Lobster's Iron Dome.
"""

import os
import sys
import re
import json
import argparse
from datetime import datetime

# Define standard test suites based on known industry bypass techniques
TEST_CASES = {
    "SSRF Loopback Bypasses": [
        {"payload": "urllib.request.urlopen('http://127.0.0.2')", "expected": "BLOCKED", "description": "Loopback subnet variation"},
        {"payload": "urllib.request.urlopen('http://0.0.0.0')", "expected": "BLOCKED", "description": "All-zero address wildcard"},
        {"payload": "urllib.request.urlopen('http://[::1]')", "expected": "BLOCKED", "description": "IPv6 loopback address"},
        {"payload": "urllib.request.urlopen('http://2130706433')", "expected": "BLOCKED", "description": "Decimal representation of 127.0.0.1"},
        {"payload": "urllib.request.urlopen('http://0177.0.0.1')", "expected": "BLOCKED", "description": "Octal representation of 127.0.0.1"},
        {"payload": "urllib.request.urlopen('http://localhost.localdomain')", "expected": "BLOCKED", "description": "Localdomain sub-resolution"}
    ],
    "SSRF Cloud Metadata Bypasses": [
        {"payload": "urllib.request.urlopen('http://[::ffff:a9fe:a9fe]')", "expected": "BLOCKED", "description": "IPv4-mapped IPv6 Cloud Metadata IP"},
        {"payload": "urllib.request.urlopen('http://2852039166')", "expected": "BLOCKED", "description": "Decimal representation of 169.254.169.254"},
        {"payload": "urllib.request.urlopen('http://0251.0376.0251.0376')", "expected": "BLOCKED", "description": "Octal representation of 169.254.169.254"}
    ],
    "Command Injection Obfuscation": [
        {"payload": "os.system('sh\\x20-c\\x20whoami')", "expected": "BLOCKED", "description": "Hexadecimal space obfuscation"},
        {"payload": "os.system('sh$IFS-c$IFSwhoami')", "expected": "BLOCKED", "description": "Internal Field Separator (IFS) space bypass"},
        {"payload": "os.system('r\"m\"\\x20-\"r\"f\\x20/')", "expected": "BLOCKED", "description": "Quoted and hex obfuscated wiper command"}
    ],
    "Directory Traversal Bypasses": [
        {"payload": "with open('/etc/passwd', 'r') as f: print(f.read())", "expected": "BLOCKED", "description": "Basic Unix credential file access"},
        {"payload": "with open('/proc/self/environ', 'r') as f: print(f.read())", "expected": "BLOCKED", "description": "Process environment variables read"},
        {"payload": "with open('....//....//....//etc/passwd', 'r')", "expected": "BLOCKED", "description": "Nested traversal character injection"}
    ]
}

def load_iron_dome(lobster_path):
    """Dynamically loads the IronDome class from the specified Project Lobster path."""
    src_path = os.path.join(lobster_path, "src")
    if not os.path.exists(src_path):
        src_path = lobster_path  # Fallback if path is pointed directly to src
        
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
        
    try:
        from iron_dome import IronDome
        print(f"[+] Successfully loaded IronDome class from: {src_path}")
        return IronDome
    except ImportError as e:
        print(f"[-] Failed to import IronDome dynamically: {e}")
        print("[*] Reverting to static verification model using project rules.")
        return None

def analyze_target_rules(iron_dome_class):
    """Inspects the compiled patterns in IronDome to see which rules exist."""
    rules_detected = {}
    if iron_dome_class and hasattr(iron_dome_class, "PATTERNS"):
        for category, patterns in iron_dome_class.PATTERNS.items():
            rules_detected[category] = len(patterns)
    return rules_detected

def run_regression_tests(iron_dome_class, lobster_path=None):
    """Runs the suite of test cases and determines if they are blocked by IronDome."""
    results = {}
    total_run = 0
    total_passed = 0  # Passed means blocked if expected, or clean if expected

    # If dynamic loading failed, compile patterns from the local file if accessible
    local_iron_dome = None
    if iron_dome_class is None and lobster_path:
        iron_dome_file = os.path.join(lobster_path, "src", "iron_dome.py")
        if os.path.exists(iron_dome_file):
            print(f"[*] Reading rules statically from {iron_dome_file}...")
            # We can extract PATTERNS block statically or mock scan
            try:
                # Add path temporarily
                sys.path.insert(0, os.path.dirname(iron_dome_file))
                from iron_dome import IronDome
                local_iron_dome = IronDome
            except Exception as ex:
                print(f"[-] Static load error: {ex}")

    scanner = iron_dome_class or local_iron_dome

    for suite_name, cases in TEST_CASES.items():
        suite_results = []
        for case in cases:
            payload = case["payload"]
            expected = case["expected"]
            description = case["description"]
            total_run += 1
            
            verdict = None
            if scanner:
                try:
                    # Run target IronDome scan interface
                    verdict = scanner.scan(payload)
                except Exception as ex:
                    verdict = {"status": "ERROR", "analysis": str(ex)}
            else:
                verdict = {"status": "SKIPPED", "analysis": "IronDome scanner not available"}

            status = verdict.get("status") if verdict else "CLEAN"
            
            # Check if expected match occurred
            passed = (status == expected)
            if passed:
                total_passed += 1
                
            suite_results.append({
                "payload": payload,
                "description": description,
                "expected": expected,
                "actual": status,
                "passed": passed,
                "analysis": verdict.get("analysis", "") if verdict else "None"
            })
        results[suite_name] = suite_results

    return results, total_run, total_passed

def generate_hardening_recommendations(results):
    """Analyzes test failures and generates specific WAF regex hardening recommendations."""
    recommendations = []
    
    # 1. Check SSRF loopback bypasses
    ssrf_loopback_failed = [c for c in results.get("SSRF Loopback Bypasses", []) if not c["passed"]]
    if ssrf_loopback_failed:
        recommendations.append({
            "target": "SSRF Loopback Filtering",
            "findings": f"{len(ssrf_loopback_failed)} loopback bypasses allowed execution. Simple string checks for '127.0.0.1' and 'localhost' are easily evaded.",
            "remediation_regex": [
                r"127\.\d+\.\d+\.\d+",                  # Catches full 127.0.0.0/8 loopback block (e.g. 127.0.0.2)
                r"0\.0\.0\.0",                          # Catches 0.0.0.0 wildcards
                r"\[::1\]|::1",                          # Catches IPv6 loopback
                r"localhost\.?[a-zA-Z0-9_-]*"            # Catches localhost subdomains
            ],
            "structural_fix": "Perform host resolution using socket.gethostbyname() and validate the resolved IP before routing outbound requests."
        })
        
    # 2. Check Cloud Metadata bypasses
    metadata_failed = [c for c in results.get("SSRF Cloud Metadata Bypasses", []) if not c["passed"]]
    if metadata_failed:
        recommendations.append({
            "target": "SSRF Cloud Metadata Filtering",
            "findings": "Cloud Metadata IP (169.254.169.254) can be obfuscated using octal, decimal, or IPv6 mappings.",
            "remediation_regex": [
                r"169\.254\.\d+\.\d+",                  # Catches entire API metadata range
                r"\[::ffff:a9fe:a9fe\]"                  # IPv4-mapped IPv6 metadata range
            ],
            "structural_fix": "Filter out decimal and octal URL patterns or parse IP strings strictly with ipaddress.ip_address() before scanning."
        })

    # 3. Check Command injection bypasses
    cmd_failed = [c for c in results.get("Command Injection Obfuscation", []) if not c["passed"]]
    if cmd_failed:
        recommendations.append({
            "target": "Command Injection Obfuscation",
            "findings": "Attacks can bypass space filters using hexadecimal escapes or the bash $IFS shell variable.",
            "remediation_regex": [
                r"\\x[0-9a-fA-F]{2}",                   # Hex encoding check in code snippet
                r"\$IFS"                                # Shell delimiter manipulation
            ],
            "structural_fix": "Add a pre-decoder middleware to unescape character codes (such as unicode, URL encodings, or byte escapes) before scanning."
        })

    # 4. Check Directory Traversal bypasses
    traversal_failed = [c for c in results.get("Directory Traversal Bypasses", []) if not c["passed"]]
    if traversal_failed:
        recommendations.append({
            "target": "Directory Traversal Safeguards",
            "findings": "Accessing system credentials directly via /etc/passwd or process environment files is a critical risk.",
            "remediation_regex": [
                r"/etc/passwd",                         # System password file read
                r"/proc/self/",                         # Proc parameters read
                r"(?:\.\./){2,}|(?:\.\.\\){2,}"        # Directory traversal pattern
            ],
            "structural_fix": "Audit file read paths to ensure they stay confined inside the designated workspace base path using os.path.commonpath()."
        })

    return recommendations

def write_report(results, total_run, total_passed, recommendations, target_path, output_dir):
    """Writes a clean, formatted Markdown report detailing test suite execution."""
    os.makedirs(output_dir, exist_ok=True)
    report_file = os.path.join(output_dir, f"octopus_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md")
    
    passed_percentage = (total_passed / total_run * 100) if total_run > 0 else 0
    
    with open(report_file, "w") as f:
        f.write("# 🐙 Project Octopus: Security Control Regression Report\n\n")
        f.write(f"**Date (UTC):** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"**Target System:** `{target_path}`  \n")
        f.write(f"**Overall Compliance Rating:** {passed_percentage:.2f}% ({total_passed}/{total_run} tests blocked)  \n\n")
        
        f.write("## 📊 Test Suite Execution Details\n\n")
        for suite, cases in results.items():
            f.write(f"### {suite}\n")
            f.write("| Payload | Description | Expected | Actual | Verdict |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- |\n")
            for c in cases:
                verdict_str = "✅ Passed (Blocked)" if c["passed"] else "❌ Failed (Bypassed)"
                escaped_payload = c["payload"].replace("'", "`").replace('"', '`')
                f.write(f"| `{escaped_payload}` | {c['description']} | `{c['expected']}` | `{c['actual']}` | {verdict_str} |\n")
            f.write("\n")
            
        f.write("## 🛡️ Recommended Hardening Rules\n\n")
        f.write("Based on the bypassed techniques above, add the following pattern updates to your security sidecar (e.g. Project Lobster's `IronDome.PATTERNS`):\n\n")
        
        for rec in recommendations:
            f.write(f"### 🎯 Target: {rec['target']}\n")
            f.write(f"**Findings:** {rec['findings']}  \n")
            f.write("**Recommended Regex Patterns to Append:**\n")
            f.write("```python\n")
            f.write("PATTERNS_TO_ADD = [\n")
            for p in rec['remediation_regex']:
                f.write(f"    r\"{p}\",\n")
            f.write("]\n")
            f.write("```\n")
            f.write(f"**Recommended Structural Fix:** {rec['structural_fix']}  \n\n")
            
        f.write("---\n")
        f.write("*Project Octopus: Maintaining deterministic, transparent security validation.*")
        
    print(f"[+] Security regression report generated successfully: {report_file}")
    return report_file

def main():
    parser = argparse.ArgumentParser(description="🐙 Project Octopus: Security Regression & WAF Validator")
    parser.add_argument("--target", default="/root/home/projects/project-lobster/v0.4.1", help="Path to project codebase to scan/verify")
    parser.add_argument("--output-dir", default="./reports", help="Directory where reports are written")
    args = parser.parse_args()

    print("======================================================================")
    print("🐙 PROJECT OCTOPUS: SECURITY REGRESSION SUITE RUNNING")
    print("======================================================================")
    print(f"Targeting: {args.target}")
    
    # 1. Load security filter target
    iron_dome_class = load_iron_dome(args.target)
    
    # 2. Extract configuration rules count
    rules_count = analyze_target_rules(iron_dome_class)
    print(f"[+] Target security rules breakdown: {json.dumps(rules_count, indent=2)}")
    
    # 3. Run regression tests
    print("\n[*] Running test payload suites...")
    results, total_run, total_passed = run_regression_tests(iron_dome_class, args.target)
    
    # 4. Generate recommendations
    recommendations = generate_hardening_recommendations(results)
    
    # 5. Write Report
    report_path = write_report(results, total_run, total_passed, recommendations, args.target, args.output_dir)
    
    print("\n======================================================================")
    print(f"RUN COMPLETED: {total_passed}/{total_run} tests successfully blocked ({total_passed/total_run*100:.1f}%)")
    print(f"Report saved at: {report_path}")
    print("======================================================================")

if __name__ == "__main__":
    main()
