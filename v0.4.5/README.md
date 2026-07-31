# 🐙 Project Octopus (v0.4.5)

Project Octopus (v0.4.5) is the 45th release of the security regression and compliance validation suite. It continues the **v0.4.x Validation Corpus Expansion series** by introducing **Prompt Injection Coverage Expansion**.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.4.5` corresponds to the 45th iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.4.5

### 1. ⚡ Prompt Injection Coverage Expansion
*   Implemented regression tests and security validations focusing on Prompt Injection Coverage Expansion.
*   Expanded validation corpus context and verification bounds to protect against edge cases mapped to this release.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the state, persistence, and chained regression validation suite:
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/latest
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.9:** Core regression engines, context wrappers, severity metrics, and confidence scopes.
*   **v0.1.0 - v0.1.9:** Conversation-state compliance series, cache namespace isolation, and multi-turn threat sequence correlation flows.
*   **v0.2.0 - v0.2.9:** MITRE ATT&CK Coverage Expansion (Credential Access, Discovery, Collection, Persistence, Execution, Defense Evasion, Lateral Movement, Exfiltration, Privilege Escalation).
*   **v0.3.0 - v0.3.9:** OWASP LLM Validation (LLM01 through LLM10 coverage).
*   **v0.4.0 - v0.4.9:** Validation Corpus Expansion (SSRF, Path Traversal, Command Injection, Prompt Injection, Secrets Exposure, Template Injection).
*   **v0.5.0 - v0.5.5:** Reporting & Evidence Series (HTML/SARIF/Markdown injections, Heatmaps, Risk Scoring, Compliance Badges, JSON summaries, and Version Comparisons).
