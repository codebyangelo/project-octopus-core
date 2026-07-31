# 🐙 Project Octopus (v0.9.1)

Project Octopus (v0.9.1) is the ninety-first release of the security regression and compliance validation suite. It continues the **`v0.9.x` Production Readiness series** by introducing the **Validation Pack Format**.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.9.1` corresponds to the 91st iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.9.1

### 1. 📦 Validation Pack Format
*   Validates LLM security proxy alignment for custom packaged validation rulesets, verifying that import schemas, execution scopes, and security levels defined within validation packs do not allow parameter injections or format hijacking.
*   Added a regression validation suite for **Validation Pack Format validation overrides** (`validation_pack_override=true`).
*   The regression corpus has expanded to **4368 test scenarios** (4354 + 14 context wrappers).
*   **Last Validation Result:** TBD.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the validation suite against the latest target WAF:
```bash
python3 octopus_verifier.py --target /root/home/projects/project-lobster/v1.4.0
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.9:** Core regression engines, context wrappers, severity metrics, and confidence scopes.
*   **v0.1.x - v0.5.x:** State compliance, MITRE ATT&CK family, OWASP LLM validation, corpus expansion, and reporting engine.
*   **v0.6.x - v0.7.x:** Framework integration and Standards alignment (CAPEC, CWE, OWASP ASVS, NIST AI RMF, NIST SSDF).
*   **v0.8.x:** Advanced Defensive Validation Series (Extended conversations, RAG, Tool invocation, Agent workflow, Memory integrity, Multi-agent, Cross-session, Sandbox, Adversarial scenario packs, Stable release).
*   **v0.9.0:** Production Readiness Series (Plugin SDK validation).
*   **v0.9.1:** Production Readiness Series (Validation pack format).
