# 🐙 Project Octopus (v0.7.0)

Project Octopus (v0.7.0) is the seventieth release of the security regression and compliance validation suite. It introduces the **`v0.7.x` Standards Alignment series** by establishing traceability to the CAPEC attack patterns schema.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.7.0` corresponds to the 70th iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.7.0

### 1. 🗺️ CAPEC Attack Pattern Traceability & Reporting
*   Added dynamic mapping of test cases and threat categories to corresponding **CAPEC ID and Pattern Names** (such as CAPEC-664 for SSRF, CAPEC-126 for Path Traversal, CAPEC-248 for Command Injection, CAPEC-672 for Adversarial Input, etc.).
*   Integrated a dedicated **CAPEC Coverage Matrix** section into Markdown and SARIF reports.
*   Added a regression validation suite for **CAPEC alignment overrides** (`capec_alignment_override=true`).
*   The regression corpus has expanded to **4074 test scenarios**.
*   **Last Validation Result:** 100.0% (4074/4074 scenarios blocked) when running `v0.7.0` against `Project Lobster v1.2.0`.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the validation suite against the latest target WAF:
```bash
python3 octopus_verifier.py --target /root/home/projects/project-lobster/v1.2.0
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
