# 🐙 Project Octopus

Project Octopus is a security regression and firewall rule validation framework designed to test, audit, and harden security controls in local application environments. Inspired by **Project Mantis** (transparency, detailed logging, and deterministic auditing) and **Project Hermit** (modular code target scanning), it operates as a central harness to ensure security controls (like **Project Lobster's** Iron Dome proxy) are not bypassed by regression or novel evasion techniques.

## 🗺️ Architectural Concept
Think of an Octopus and its limbs:
*   **Limbs (Detection Vectors):** Each limb represents a specific suite of tests checking for known classes of evasion/bypass techniques (e.g., SSRF loopback subnets, metadata decimal IP encodings, command separator obfuscation, nested directory traversal).
*   **The Brain (Determinism & Logging):** Everything is logged transparently, producing structured markdown verification reports detailing exact bypass findings and recommended remediation regexes.

---

## 🚀 Getting Started

### Running the Regression Verifier
To run the verifier against a project containing an `IronDome` shield (such as Project Lobster):
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.x
```

By default, the script scans the target, executes the regression test suites, logs each result, and writes a compliance audit report inside the `./reports/` folder.

---

## 📂 Project Structure
*   `octopus_verifier.py`: The core regression runner and defensive pattern evaluator.
*   `test_ssrf_standalone.py`: Individual standalone SSRF validation script copied from the baseline tests.
*   `red_team_test.py`: Unit-test validation suite checking RCE, network extraction, env exfiltration, and rate-limiting fail-closed behaviors.
*   `novel_red_team.py`: Diagnostic tester targeting dynamic Model Context Protocol (MCP) or LLM endpoints.
*   `reports/`: Generated markdown audit logs containing pass/fail metrics and rule suggestions.

---

## 🛡️ Hardening Project Lobster's Iron Dome
When `octopus_verifier.py` detects bypassed payloads, it automatically generates recommended rules (regular expressions) that you can copy and append directly to Project Lobster's `src/iron_dome.py` under the appropriate categories.
