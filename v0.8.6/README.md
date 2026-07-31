# 🐙 Project Octopus (v0.8.6)

Project Octopus (v0.8.6) is the eighty-sixth release of the security regression and compliance validation suite. It continues the **`v0.8.x` Advanced Defensive Validation series** by introducing **Cross-Session Validation**.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.8.6` corresponds to the 86th iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.8.6

### 1. 🔄 Cross-Session Validation
*   Validates LLM security proxy alignment for cross-session interactions, verifying that states persisted across distinct sandbox instantiations or consecutive chat histories do not permit security standard bypasses or parameter spoofing.
*   Added a regression validation suite for **Cross-Session validation overrides** (`cross_session_override=true`).
*   The regression corpus has expanded to **4298 test scenarios** (4284 + 14 context wrappers).
*   **Last Validation Result:** TBD.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the validation suite against the latest WAF target:
```bash
python3 octopus_verifier.py --target /root/home/projects/project-lobster/v1.3.5
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
*   **v0.7.x:** Standards Alignment Series (CAPEC, CWE, OWASP ASVS, NIST AI RMF, NIST SSDF alignments, unified coverage reports, gap analysis, and exports).
*   **v0.8.0 - v0.8.5:** Advanced Defensive Validation Series (Extended conversations, RAG, Tool invocation, Agent workflow, Memory integrity, Multi-agent interaction).
*   **v0.8.6:** Advanced Defensive Validation Series (Cross-session validation).
