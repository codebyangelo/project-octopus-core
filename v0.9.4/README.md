# 🐙 Project Octopus (v0.9.4)

Project Octopus (v0.9.4) is the ninety-fourth release of the security regression and compliance validation suite. It continues the **`v0.9.x` Production Readiness series** by introducing **Cached Execution**.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.9.4` corresponds to the 94th iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.9.4

### 1. 🗄️ Cached Execution
*   Validates LLM security proxy alignment for cached validations, verifying that caching state matches, serialization namespaces, and payload signature lookups do not introduce timing bypass channels or let malicious requests skip evaluation by matching cached responses.
*   Added a regression validation suite for **Cached Execution overrides** (`cached_execution_override=true`).
*   The regression corpus has expanded to **4410 test scenarios** (4396 + 14 context wrappers).
*   **Last Validation Result:** TBD.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the validation suite against the latest WAF target:
```bash
python3 octopus_verifier.py --target /root/home/projects/project-lobster/v1.4.3
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
*   **v0.9.3:** Production Readiness Series (Parallel validation).
*   **v0.9.4:** Production Readiness Series (Cached execution).
