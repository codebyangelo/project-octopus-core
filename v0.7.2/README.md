# 🐙 Project Octopus (v0.7.2)

Project Octopus (v0.7.2) is the seventy-second release of the security regression and compliance validation suite. It continues the **`v0.7.x` Standards Alignment series** by establishing traceability to the OWASP ASVS requirement controls schema.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.7.2` corresponds to the 72nd iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.7.2

### 1. 🗺️ OWASP ASVS Requirement Traceability & Reporting
*   Added dynamic mapping of test cases and threat categories to corresponding **ASVS ID and Requirement Names** (such as ASVS V5.2.6 for SSRF, ASVS V12.4.1 for Path Traversal, ASVS V5.3.8 for Command Injection, ASVS V5.3.10 for Prompt Injection, ASVS V6.2.1 for Secrets Exposure, etc.).
*   Integrated a dedicated **OWASP ASVS Coverage Matrix** section into Markdown and SARIF reports.
*   Added a regression validation suite for **ASVS alignment overrides** (`asvs_alignment_override=true`).
*   The regression corpus has expanded to **4102 test scenarios** (4088 + 14 context wrappers).
*   **Last Validation Result:** TBD.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the validation suite against the latest target WAF:
```bash
python3 octopus_verifier.py --target /root/home/projects/project-lobster/v1.2.1
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.9:** Core regression engines, context wrappers, severity metrics, and confidence scopes.
*   **v0.1.0 - v0.1.9:** Conversation-state compliance series, cache namespace isolation, and multi-turn threat sequence correlation flows.
*   **v0.2.0 - v0.2.9:** MITRE ATT&CK Coverage Expansion (TA0006, TA0007, TA0009, TA0003, TA0002).
*   **v0.3.0 - v0.3.9:** OWASP LLM Validation (LLM01 through LLM10 coverage).
*   **v0.4.0 - v0.4.9:** Validation Corpus Expansion (SSRF, Path Traversal, Command Injection, Prompt Injection, Secrets Exposure, Template Injection).
*   **v0.5.0 - v0.5.9:** Reporting & Evidence Series (SARIF, badge generation, trends comparisons).
*   **v0.6.0 - v0.6.9:** Framework Integration Series (Rule engine adapters, Config, Policy, API, CLI, Plugins, External Rule Packs, Parallel, Benchmark, Stable Release).
*   **v0.7.0:** Standards Alignment Series (CAPEC attack pattern mappings and coverage reporting).
*   **v0.7.1:** Standards Alignment Series (CWE weakness mappings and coverage reporting).
*   **v0.7.2:** Standards Alignment Series (OWASP ASVS requirement mappings and coverage reporting).
