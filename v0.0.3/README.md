# 🐙 Project Octopus (v0.0.3)

Project Octopus (v0.0.3) is the third major release of the security regression and compliance validation suite. It focuses on **Payload Taxonomy Refactoring** and **Decoupled Architecture**, moving the test data definitions out of code and into externalized configurations, and standardizing the 24 regression tests into six industry-standard suites.

---

## 🆕 New in v0.0.3

### 1. 📂 Decoupled Test Architecture
Test suites and cases are no longer hardcoded inside Python script dictionaries. They are externalized to [test_cases.json](file:///root/home/projects/project-octopus/v0.0.3/test_cases.json) for neat separation of concerns, decoupling configuration from runtime logic.

### 2. 🗂️ Reorganized Taxonomy Suites
The original 24 regression tests are structured into six key security suites:
*   **SSRF**: Combines loopback subnet variations, cloud metadata obfuscation (IPv6/decimal/octal), and plugin SSRF.
*   **Traversal**: Standard and nested traversal payloads (`/etc/passwd`, `/proc/self/environ`, etc.).
*   **Command Injection**: Space obfuscations using hexadecimal escapes or shell environment variables (e.g. `$IFS`).
*   **Prompt Injection**: Generative AI instructions overrides (LLM01) and output handling bypasses like XSS (LLM02).
*   **Secrets**: High-entropy sensitive variable exposure (LLM06).
*   **MITRE**: Techniques targeting administrative or elevated operations (T1003 OS Credential Dumping, T1070 indicator removal, T1059 command interpretation, T1548 SUID Escalation).

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the refactored regression suite against your security controls (e.g., Project Lobster's latest version):
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.5.6
```

The verifier reads [test_cases.json](file:///root/home/projects/project-octopus/v0.0.3/test_cases.json), executes the scanner, evaluates the verdict, and saves a markdown compliance report inside the `./reports/` directory.

---

## 📈 Version Changelog
*   **v0.0.1:** Initial release. Included baseline regression tests for loopback SSRF, cloud metadata SSRF, command separator injections, and basic directory traversals.
*   **v0.0.2:** Expanded validation coverage to include MITRE ATT&CK threat tactics and OWASP LLM security vulnerabilities, updating remediation rule advice.
*   **v0.0.3:** Payload taxonomy refactor. Externalized test cases into JSON format and standardized test groups (SSRF, Traversal, Command Injection, Prompt Injection, Secrets, MITRE).
