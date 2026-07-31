# 🐙 Project Octopus (v0.6.6)

Project Octopus (v0.6.6) is the sixty-sixth release of the security regression and compliance validation suite. It continues the **`v0.6.x` Framework Integration series** by expanding regression checks for third-party integrations and extensibility features.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.6.6` corresponds to the 66th iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.6.6

### 1. 🔌 Framework Integration & Extensibility Validation
*   Added regression and bypass checks for:
    *   `v0.6.0`: Generic rule engine adapters (custom test adapters)
    *   `v0.6.1`: Configuration validation (JSON config override schemes)
    *   `v0.6.2`: Policy validation (enforcement level downgrades)
    *   `v0.6.3`: API validation (validation/auth route bypass flags)
    *   `v0.6.4`: CLI validation (security disable CLI parameters)
    *   `v0.6.5`: Plugin architecture (shared dynamic link libraries .so/.dll/.dylib loading)
    *   `v0.6.6`: External rule packs (remote rule pack HTTP/HTTPS URLs)
*   The regression corpus has expanded to **4018 test scenarios**.
*   **Last Validation Result:** 100.0% (4018/4018 scenarios blocked) when running `v0.6.6` against `Project Lobster v1.1.6`.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the validation suite against the latest target WAF:
```bash
python3 octopus_verifier.py --target /root/home/projects/project-lobster/v1.1.6
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.9:** Core regression engines, context wrappers, severity metrics, and confidence scopes.
*   **v0.1.0 - v0.1.9:** Conversation-state compliance series, cache namespace isolation, and multi-turn threat sequence correlation flows.
*   **v0.2.0 - v0.2.9:** MITRE ATT&CK Coverage Expansion (TA0006, TA0007, TA0009, TA0003, TA0002).
*   **v0.3.0 - v0.3.9:** OWASP LLM Validation (LLM01 through LLM10 coverage).
*   **v0.4.0 - v0.4.9:** Validation Corpus Expansion (SSRF, Path Traversal, Command Injection, Prompt Injection, Secrets Exposure, Template Injection).
*   **v0.5.0 - v0.5.9:** Reporting & Evidence Series (SARIF, badge generation, trends comparisons).
*   **v0.6.0 - v0.6.6:** Framework Integration Series (Rule engine adapters, Config, Policy, API, CLI, Plugins, External Rule Packs).
