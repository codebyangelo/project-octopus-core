# 🐙 Project Octopus (v0.0.8)

Project Octopus (v0.0.8) is the eighth release of the security regression and compliance validation suite. It focuses on the **Severity Engine**, organizing test cases and generated findings by severity tiers (`Critical`, `High`, `Medium`, and `Low`) to provide more informative, risk-prioritized reports.

---

## 🆕 New in v0.0.8

### 1. 🎚️ Severity Rating System
All 54 base payloads defined in [test_cases.json](file:///root/home/projects/project-octopus/v0.0.8/test_cases.json) are classified with specific severity ratings:
*   **Critical Severity:** Associated with high-impact RCE (Command Injection), environment secret disclosure (Secrets), high-value target file reading (MITRE shadow access, nc listeners, SUID chmod), and cloud metadata retrieval SSRF.
*   **High Severity:** Associated with standard SSRF loopbacks, system credential traverses (/etc/passwd, /proc/self/environ), output handling bypasses (XSS/script tags), and MITRE log manipulation tactics.
*   **Medium Severity:** Associated with LLM prompt instruction overrides.
*   **Low Severity:** Reserved for low-risk non-exploitable diagnostics.

### 2. 📊 Risk-Based Grouped Reporting
*   The execution logic in [octopus_verifier.py](file:///root/home/projects/project-octopus/v0.0.8/octopus_verifier.py) maps and tracks findings under individual severity headers rather than flat lists.
*   Compliance reports produced in the `./reports/` directory present a breakdown highlighting success rates per severity tier alongside overall percentages.
*   Standard output provides a CLI visual summary of severity coverage.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the severity-grouped compliance scan against your security controls (e.g., Project Lobster's latest version):
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.6.5
```

---

## 📈 Version Changelog
*   **v0.0.1:** Initial release. Included baseline regression tests for loopback SSRF, cloud metadata SSRF, command separator injections, and basic directory traversals.
*   **v0.0.2:** Expanded validation coverage to include MITRE ATT&CK threat tactics and OWASP LLM security vulnerabilities, updating remediation rule advice.
*   **v0.0.3:** Payload taxonomy refactor. Externalized test cases into JSON format and standardized test groups (SSRF, Traversal, Command Injection, Prompt Injection, Secrets, MITRE).
*   **v0.0.4:** Encoding Suite I. Added URL-encoded, double URL-encoded, and hexadecimal payload variants.
*   **v0.0.5:** Encoding Suite II. Added Unicode, homoglyph, UTF-8, and mixed-encoding payload variants.
*   **v0.0.6:** Context Suite I. Executed payloads inside Markdown, HTML, and JSON contexts (432 scenarios).
*   **v0.0.7:** Context Suite II. Added YAML, XML, CSV, and source-code contexts (756 scenarios).
*   **v0.0.8:** Severity Engine. Classified findings as Critical, High, Medium, or Low with risk-grouped compliance score summaries and reporting.
