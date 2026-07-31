#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🐙 Project Octopus (v0.0.9): Security Control & Compliance Validation Suite
Confidence Scoring - Records Complete Block, Partial Block, Partial Leak, and Full Bypass outcomes.
"""

import os
import sys
import re
import json
import argparse
from datetime import datetime, timezone

# Load test cases from external configuration
script_dir = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(script_dir, "test_cases.json")

try:
    with open(json_path, "r") as f:
        TEST_CASES = json.load(f)
except Exception as e:
    print(f"[-] Error loading test cases from {json_path}: {e}")
    sys.exit(1)

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

# Context Suite I & II wrappers to check payload behaviors inside different syntax boundaries
CONTEXT_TEMPLATES = {
    "Raw": lambda p: p,
    "Markdown (Fenced)": lambda p: f"Some user content\n```python\n{p}\n```\nMore user content",
    "Markdown (Inline)": lambda p: f"Please review this inline snippet: `{p}`.",
    "Markdown (Link)": lambda p: f"Check out this [exploit link]({p}) for details.",
    "HTML (Div)": lambda p: f"<div>\n  <p>User Code:</p>\n  <pre>{p}</pre>\n</div>",
    "HTML (Attribute)": lambda p: f'<input type="hidden" name="payload" value="{p.replace("\"", "&quot;")}">',
    "HTML (Comment)": lambda p: f"<!-- Debug Info: {p} -->",
    "JSON": lambda p: json.dumps({"request": {"code": p, "metadata": {"length": len(p)}}}),
    "YAML": lambda p: f"request:\n  payload: |\n    {p.replace('\n', '\n    ')}",
    "XML (CDATA)": lambda p: f"<request>\n  <payload><![CDATA[{p}]]></payload>\n</request>",
    "CSV": lambda p: 'id,snippet\n1,"' + p.replace('"', '""') + '"',
    "Source (Comment)": lambda p: f"# Validation check payload:\n# {p.replace('\n', '\n# ')}",
    "Source (String)": lambda p: 'exploit_payload = """' + p.replace('"""', '\\"\\"\\"') + '"""',
    "Source (Function)": lambda p: f"def verify():\n    {p.replace('\n', '\n    ')}"
}

def determine_outcome(suite_name, verdict):
    """
    Categorizes the verification outcome into one of four confidence/severity states:
    1. Complete Block: Blocked by the correct, category-specific signature rules.
    2. Partial Block: Blocked, but by generic rules or unrelated threat categories.
    3. Partial Leak: Allowed to execute, but encountered system warnings/API errors.
    4. Full Bypass: Completely allowed execution with no security alarms triggered.
    """
    if not verdict:
        return "Full Bypass"
        
    status = verdict.get("status", "CLEAN")
    analysis = verdict.get("analysis", "")
    
    if status == "BLOCKED":
        analysis_upper = analysis.upper()
        aligned = False
        
        # Check alignment between taxonomy suite and detection rule
        if suite_name == "SSRF":
            aligned = "CRITICAL_NET" in analysis_upper or "SSRF" in analysis_upper
        elif suite_name == "Traversal":
            aligned = "CRITICAL_RCE" in analysis_upper or "TRAVERSAL" in analysis_upper
        elif suite_name == "Command Injection":
            aligned = "CRITICAL_RCE" in analysis_upper or "COMMAND" in analysis_upper or "OBFUSCATION" in analysis_upper
        elif suite_name == "Prompt Injection":
            aligned = "SUSPICIOUS_OBFUSCATION" in analysis_upper or "PROMPT" in analysis_upper
        elif suite_name == "Secrets":
            aligned = "SUSPICIOUS_OBFUSCATION" in analysis_upper or "SECRET" in analysis_upper
        elif suite_name == "MITRE":
            aligned = "CRITICAL_RCE" in analysis_upper or "CRITICAL_NET" in analysis_upper or "MITRE" in analysis_upper or "OBFUSCATION" in analysis_upper
            
        return "Complete Block" if aligned else "Partial Block"
        
    elif status in ["API_ERROR", "ERROR", "SKIPPED", "OFFLINE"]:
        return "Partial Leak"
    else:
        # status is CLEAN
        return "Full Bypass"

def run_regression_tests(iron_dome_class, lobster_path=None):
    """Runs the suite of test cases wrapped in various contexts and determines if they are blocked by IronDome."""
    results = {}
    total_run = 0
    total_passed = 0  # Passed means blocked if expected, or clean if expected

    # If dynamic loading failed, compile patterns from the local file if accessible
    local_iron_dome = None
    if iron_dome_class is None and lobster_path:
        iron_dome_file = os.path.join(lobster_path, "src", "iron_dome.py")
        if os.path.exists(iron_dome_file):
            print(f"[*] Reading rules statically from {iron_dome_file}...")
            try:
                sys.path.insert(0, os.path.dirname(iron_dome_file))
                from iron_dome import IronDome
                local_iron_dome = IronDome
            except Exception as ex:
                print(f"[-] Static load error: {ex}")

    scanner = iron_dome_class or local_iron_dome

    for suite_name, cases in TEST_CASES.items():
        suite_results = []
        for case in cases:
            base_payload = case["payload"]
            expected = case["expected"]
            description = case["description"]
            severity = case.get("severity", "Medium")
            
            for ctx_name, wrapper in CONTEXT_TEMPLATES.items():
                payload = wrapper(base_payload)
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
                    
                outcome = determine_outcome(suite_name, verdict)
                
                suite_results.append({
                    "payload": payload,
                    "description": f"{description} ({ctx_name})",
                    "expected": expected,
                    "actual": status,
                    "passed": passed,
                    "severity": severity,
                    "outcome": outcome,
                    "analysis": verdict.get("analysis", "") if verdict else "None"
                })
        results[suite_name] = suite_results

    return results, total_run, total_passed

def generate_hardening_recommendations(results):
    """Analyzes test failures and generates specific WAF regex hardening recommendations."""
    recommendations = []
    
    # 1. SSRF check
    ssrf_failed = [c for c in results.get("SSRF", []) if not c["passed"]]
    if ssrf_failed:
        recommendations.append({
            "target": "SSRF (Server-Side Request Forgery)",
            "findings": f"{len(ssrf_failed)} SSRF bypasses allowed execution.",
            "remediation_regex": [
                r"127\.\d+\.\d+\.\d+",
                r"0\.0\.0\.0",
                r"\[::1\]|::1",
                r"localhost\.?[a-zA-Z0-9_-]*",
                r"169\.254\.\d+\.\d+",
                r"\[::ffff:a9fe:a9fe\]"
            ],
            "structural_fix": "Perform host resolution using socket.gethostbyname() and validate the resolved IP before routing outbound requests. Filter out decimal and octal URL patterns or parse IP strings strictly with ipaddress.ip_address() before scanning."
        })
        
    # 2. Traversal check
    traversal_failed = [c for c in results.get("Traversal", []) if not c["passed"]]
    if traversal_failed:
        recommendations.append({
            "target": "Directory Traversal Safeguards",
            "findings": f"{len(traversal_failed)} directory traversal patterns allowed execution.",
            "remediation_regex": [
                r"/etc/passwd",
                r"/proc/self/",
                r"(?:\.\./){2,}|(?:\.\.\\){2,}"
            ],
            "structural_fix": "Audit file read paths to ensure they stay confined inside the designated workspace base path using os.path.commonpath()."
        })

    # 3. Command Injection check
    cmd_failed = [c for c in results.get("Command Injection", []) if not c["passed"]]
    if cmd_failed:
        recommendations.append({
            "target": "Command Injection Obfuscation",
            "findings": f"{len(cmd_failed)} command injection bypasses allowed execution.",
            "remediation_regex": [
                r"\\x[0-9a-fA-F]{2}",
                r"\$IFS"
            ],
            "structural_fix": "Add a pre-decoder middleware to unescape character codes (such as unicode, URL encodings, or byte escapes) before scanning."
        })

    # 4. Prompt Injection check
    prompt_failed = [c for c in results.get("Prompt Injection", []) if not c["passed"]]
    if prompt_failed:
        recommendations.append({
            "target": "Prompt Injection / Output Handling",
            "findings": f"{len(prompt_failed)} prompt injection or output handling vulnerabilities allowed execution.",
            "remediation_regex": [
                r"(?i)ignore\s+previous\s+instructions",
                r"<script>.*</script>"
            ],
            "structural_fix": "Implement a semantic prompt validator and use schema-enforced output checks to intercept injections before rendering."
        })

    # 5. Secrets check
    secrets_failed = [c for c in results.get("Secrets", []) if not c["passed"]]
    if secrets_failed:
        recommendations.append({
            "target": "Secrets & Sensitive Information Disclosure",
            "findings": f"{len(secrets_failed)} sensitive environment variables or secrets leaked.",
            "remediation_regex": [
                r"VERTEX_API_KEY|GEMINI_API_KEY"
            ],
            "structural_fix": "Implement regular scanning for high-entropy strings and environment variable names in LLM inputs and outputs."
        })

    # 6. MITRE check
    mitre_failed = [c for c in results.get("MITRE", []) if not c["passed"]]
    if mitre_failed:
        recommendations.append({
            "target": "MITRE ATT&CK Compliance (T1003, T1070, T1059, T1548)",
            "findings": f"{len(mitre_failed)} threat technique simulations executed successfully without detection.",
            "remediation_regex": [
                r"/etc/shadow",
                r"shred\s+",
                r"/var/log/(syslog|auth\.log)",
                r"nc\s+.*-e\s+",
                r"chmod\s+\+s"
            ],
            "structural_fix": "Incorporate system auditing plugins and block administrative command prefixes in non-privileged context files."
        })

    return recommendations

def get_severity_emoji(severity):
    """Returns a visual indicator emoji corresponding to severity level."""
    if severity == "Critical":
        return "🔴"
    elif severity == "High":
        return "🟠"
    elif severity == "Medium":
        return "🟡"
    elif severity == "Low":
        return "🟢"
    return "⚪"

def get_outcome_emoji(outcome):
    """Returns a visual indicator emoji corresponding to outcome confidence state."""
    if outcome == "Complete Block":
        return "🛡️"
    elif outcome == "Partial Block":
        return "⚠️"
    elif outcome == "Partial Leak":
        return "🔓"
    elif outcome == "Full Bypass":
        return "❌"
    return "❓"

def write_report(results, total_run, total_passed, recommendations, target_path, output_dir):
    """Writes a clean, formatted Markdown report detailing test execution, severities, and confidence outcomes."""
    os.makedirs(output_dir, exist_ok=True)
    
    current_utc = datetime.now(timezone.utc)
    report_file = os.path.join(output_dir, f"octopus_report_{current_utc.strftime('%Y%m%d_%H%M%S')}.md")
    
    passed_percentage = (total_passed / total_run * 100) if total_run > 0 else 0
    
    # Track statistics per severity and outcome
    stats_severity = {
        "Critical": {"run": 0, "passed": 0, "failed": 0},
        "High": {"run": 0, "passed": 0, "failed": 0},
        "Medium": {"run": 0, "passed": 0, "failed": 0},
        "Low": {"run": 0, "passed": 0, "failed": 0}
    }
    
    stats_outcome = {
        "Complete Block": 0,
        "Partial Block": 0,
        "Partial Leak": 0,
        "Full Bypass": 0
    }
    
    # Grouped structures
    grouped_by_severity = {"Critical": [], "High": [], "Medium": [], "Low": []}
    
    for suite, cases in results.items():
        for c in cases:
            sev = c.get("severity", "Medium")
            outc = c.get("outcome", "Full Bypass")
            c["suite"] = suite
            
            # Severity accumulation
            if sev in grouped_by_severity:
                grouped_by_severity[sev].append(c)
                stats_severity[sev]["run"] += 1
                if c["passed"]:
                    stats_severity[sev]["passed"] += 1
                else:
                    stats_severity[sev]["failed"] += 1
                    
            # Outcome accumulation
            if outc in stats_outcome:
                stats_outcome[outc] += 1
                
    with open(report_file, "w") as f:
        f.write("# 🐙 Project Octopus (v0.0.9): Security Control & Compliance Report\n\n")
        f.write(f"**Date (UTC):** {current_utc.strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"**Target System:** `{target_path}`  \n")
        f.write(f"**Overall Compliance Rating:** {passed_percentage:.2f}% ({total_passed}/{total_run} tests blocked)  \n\n")
        
        f.write("## 🎯 Confidence & Outcome Summary\n\n")
        f.write("| Outcome | Count | Percentage | Description |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        for outc in ["Complete Block", "Partial Block", "Partial Leak", "Full Bypass"]:
            cnt = stats_outcome[outc]
            pct = (cnt / total_run * 100) if total_run > 0 else 0.0
            desc = ""
            if outc == "Complete Block":
                desc = "Blocked cleanly by aligned, category-specific security rules."
            elif outc == "Partial Block":
                desc = "Blocked successfully, but by generic rules or unrelated threat categories."
            elif outc == "Partial Leak":
                desc = "Execution allowed (CLEAN/ERROR) due to WAF API limits, offline fallbacks, or warnings."
            elif outc == "Full Bypass":
                desc = "Execution completely allowed with no security indicators raised."
            f.write(f"| {get_outcome_emoji(outc)} **{outc}** | {cnt} | {pct:.1f}% | {desc} |\n")
        f.write("\n")
        
        f.write("## 📊 Severity Compliance Summary\n\n")
        f.write("| Severity | Total Scenarios | Blocked (Passed) | Bypassed (Failed) | Success Rate |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")
        for sev in ["Critical", "High", "Medium", "Low"]:
            s = stats_severity[sev]
            rate = (s["passed"] / s["run"] * 100) if s["run"] > 0 else 0.0
            rate_str = f"{rate:.1f}%" if s["run"] > 0 else "N/A"
            f.write(f"| {get_severity_emoji(sev)} {sev} | {s['run']} | {s['passed']} | {s['failed']} | {rate_str} |\n")
        f.write("\n")
        
        f.write("## 📊 Test Suite Execution Details (Grouped by Severity)\n\n")
        for sev in ["Critical", "High", "Medium", "Low"]:
            cases_in_sev = grouped_by_severity[sev]
            if not cases_in_sev:
                continue
                
            f.write(f"### {get_severity_emoji(sev)} {sev} Severity Findings ({stats_severity[sev]['passed']}/{stats_severity[sev]['run']} Blocked)\n\n")
            f.write("| Suite | Payload | Description | Expected | Actual | Outcome | Verdict |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
            for c in cases_in_sev:
                verdict_str = "✅ Passed (Blocked)" if c["passed"] else "❌ Failed (Bypassed)"
                escaped_payload = c["payload"].replace("'", "`").replace('"', '`').replace("\n", " [NL] ")
                f.write(f"| {c['suite']} | `{escaped_payload}` | {c['description']} | `{c['expected']}` | `{c['actual']}` | {get_outcome_emoji(c['outcome'])} {c['outcome']} | {verdict_str} |\n")
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
    parser = argparse.ArgumentParser(description="🐙 Project Octopus (v0.0.9): Security Regression & Confidence Scoring")
    parser.add_argument("--target", default="/root/home/projects/project-lobster/v0.6.5", help="Path to project codebase to scan/verify")
    parser.add_argument("--output-dir", default="./reports", help="Directory where reports are written")
    args = parser.parse_args()

    print("======================================================================")
    print("🐙 PROJECT OCTOPUS (v0.0.9): SECURITY REGRESSION & COMPLIANCE RUNNING")
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
    
    # 6. Extract Statistics for stdout Breakdown
    stats_severity = {
        "Critical": {"run": 0, "passed": 0},
        "High": {"run": 0, "passed": 0},
        "Medium": {"run": 0, "passed": 0},
        "Low": {"run": 0, "passed": 0}
    }
    stats_outcome = {
        "Complete Block": 0,
        "Partial Block": 0,
        "Partial Leak": 0,
        "Full Bypass": 0
    }
    
    for suite, cases in results.items():
        for c in cases:
            sev = c.get("severity", "Medium")
            outc = c.get("outcome", "Full Bypass")
            if sev in stats_severity:
                stats_severity[sev]["run"] += 1
                if c["passed"]:
                    stats_severity[sev]["passed"] += 1
            if outc in stats_outcome:
                stats_outcome[outc] += 1
                    
    print("\n======================================================================")
    print(f"RUN COMPLETED: {total_passed}/{total_run} tests successfully blocked ({total_passed/total_run*100:.1f}%)")
    
    print("Severity Compliance Breakdown:")
    for sev in ["Critical", "High", "Medium", "Low"]:
        run = stats_severity[sev]["run"]
        passed = stats_severity[sev]["passed"]
        if run > 0:
            print(f"  - {get_severity_emoji(sev)} {sev}: {passed}/{run} blocked ({passed/run*100:.1f}%)")
        else:
            print(f"  - {get_severity_emoji(sev)} {sev}: {passed}/{run} blocked (N/A)")
            
    print("\nOutcome Confidence Breakdown:")
    for outc in ["Complete Block", "Partial Block", "Partial Leak", "Full Bypass"]:
        cnt = stats_outcome[outc]
        pct = (cnt / total_run * 100) if total_run > 0 else 0.0
        print(f"  - {get_outcome_emoji(outc)} {outc}: {cnt}/{total_run} ({pct:.1f}%)")
        
    print(f"\nReport saved at: {report_path}")
    print("======================================================================")

if __name__ == "__main__":
    main()
