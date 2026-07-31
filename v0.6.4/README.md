# 🐙 Project Octopus (v0.5.5)

Project Octopus (v0.5.5) is the fifty-fifth release of the security regression and compliance validation suite. It continues the **`v0.5.x` Reporting & Evidence series** by introducing **Version Comparisons & Delta**.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.5.5` corresponds to the 55th iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.5.5

### 1. 📊 Version Comparisons & Delta
*   Added WAF filters for:
    *   Timing sleep commands
    *   Temporal ISO timestamp manipulation
    *   Recursion limit overrides
*   Integrated automated delta comparison tables to analyze differences against prior reports.
*   The regression corpus has expanded to **3808 test scenarios**.
*   **Last Validation Result:** 100.0% (3808/3808 scenarios blocked) when running `v0.5.5` against `Project Lobster v1.0.5`.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the validation suite against the latest target:
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v1.0.5
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.9:** Core regression engines, context wrappers, severity metrics, and confidence scopes.
*   **v0.1.0 - v0.1.9:** Conversation-state compliance series, cache namespace isolation, and multi-turn threat sequence correlation flows.
*   **v0.2.0 - v0.2.9:** MITRE ATT&CK Coverage Expansion (Credential Access, Discovery, Collection, Persistence, Execution, Defense Evasion, Lateral Movement, Exfiltration, Privilege Escalation).
*   **v0.3.0 - v0.3.9:** OWASP LLM Validation (LLM01 through LLM10 coverage).
*   **v0.4.0 - v0.4.9:** Validation Corpus Expansion (SSRF, Path Traversal, Command Injection, Prompt Injection, Secrets Exposure, Template Injection).
*   **v0.5.0 - v0.5.5:** Reporting & Evidence Series (HTML/SARIF/Markdown injections, Heatmaps, Risk Scoring, Compliance Badges, JSON summaries, and Version Comparisons).
