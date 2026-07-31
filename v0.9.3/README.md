# 🐙 Project Octopus (v0.9.3)

Project Octopus (v0.9.3) is the ninety-third release of the security regression and compliance validation suite. It continues the **`v0.9.x` Production Readiness series** by introducing **Parallel Validation**.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.9.3` corresponds to the 93rd iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.9.3

### 1. ⚡ Parallel Validation
*   Validates LLM security proxy alignment for parallelized test executions, verifying that multi-threaded scan threads and parallel HTTP packets do not cause race conditions or permit override parameters to slip through WAF evaluation checks.
*   Added a regression validation suite for **Parallel Validation overrides** (`parallel_validation_override=true`).
*   The regression corpus has expanded to **4396 test scenarios** (4382 + 14 context wrappers).
*   **Last Validation Result:** TBD.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the validation suite against the latest WAF target:
```bash
python3 octopus_verifier.py --target /root/home/projects/project-lobster/v1.4.2
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
