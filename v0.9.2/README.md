# 🐙 Project Octopus (v0.9.2)

Project Octopus (v0.9.2) is the ninety-second release of the security regression and compliance validation suite. It continues the **`v0.9.x` Production Readiness series** by introducing **Incremental Regression Execution**.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.9.2` corresponds to the 92nd iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.9.2

### 1. 📈 Incremental Regression Execution
*   Validates LLM security proxy alignment for incremental validation execution runs, verifying that partial test runs and delta hashes track overall compliance states accurately without permitting override payloads to escape validation scope.
*   Added a regression validation suite for **Incremental Regression validation overrides** (`incremental_regression_override=true`).
*   The regression corpus has expanded to **4382 test scenarios** (4368 + 14 context wrappers).
*   **Last Validation Result:** TBD.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the validation suite against the latest target WAF:
```bash
python3 octopus_verifier.py --target /root/home/projects/project-lobster/v1.4.1
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.9:** Core regression engines, context wrappers, severity metrics, and confidence scopes.
*   **v0.1.x - v0.5.x:** State compliance, MITRE ATT&CK family, OWASP LLM validation, corpus expansion, and reporting engine.
*   **v0.6.x - v0.7.x:** Framework integration and Standards alignment (CAPEC, CWE, OWASP ASVS, NIST AI RMF, NIST SSDF).
*   **v0.8.x:** Advanced Defensive Validation Series (Extended conversations, RAG, Tool invocation, Agent workflow, Memory integrity, Multi-agent, Cross-session, Sandbox, Adversarial scenario packs, Stable release).
*   **v0.9.0:** Production Readiness Series (Plugin SDK validation).
*   **v0.9.1:** Production Readiness Series (Validation pack format).
*   **v0.9.2:** Production Readiness Series (Incremental regression execution).
