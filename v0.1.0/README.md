# 🐙 Project Octopus (v0.0.9)

Project Octopus (v0.0.9) is the ninth release of the security regression and compliance validation suite. It focuses on the **Confidence Scoring Engine**, introducing multi-state outcome tracking to categorize how security rules block payloads (identifying direct vs. generic matches).

---

## 🆕 New in v0.0.9

### 1. 🎯 Confidence & Outcome Classification
Verdicts are no longer classified as simple binary PASS/FAIL block checks. The engine records four distinct outcomes:
*   🛡️ **Complete Block:** The payload was blocked by an aligned, category-specific security rule (e.g. `CRITICAL_NET` for loopback/metadata SSRF). This indicates high confidence.
*   ⚠️ **Partial Block:** The payload was blocked, but by a generic ruleset or an unrelated category rule (e.g. an SSRF bypass blocked because it triggered a general character obfuscation or encoding alarm).
*   🔓 **Partial Leak:** The security control allowed the payload to pass (status `CLEAN` or `ERROR`) because it encountered API timeouts, quota limits, or fell back to offline modes.
*   ❌ **Full Bypass:** The payload was fully allowed by safety controls with no suspicion raised whatsoever.

### 2. 📊 Detailed Compliance Matrix
*   The execution script in [octopus_verifier.py](file:///root/home/projects/project-octopus/v0.0.9/octopus_verifier.py) performs aligned analysis matching for all 756 scenarios.
*   Reports in `./reports/` feature a **Confidence & Outcome Summary** table highlighting overall percentages for each outcome type.
*   CLI standard output displays the full outcome breakdown.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the confidence-scored regression validation suite:
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
*   **v0.0.9:** Confidence Scoring. Implemented outcomes (Complete Block, Partial Block, Partial Leak, Full Bypass) based on alignment between payload intent and active trigger signatures.
