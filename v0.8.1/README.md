# 🐙 Project Octopus (v0.8.1)

Project Octopus (v0.8.1) is the eighty-first release of the security regression and compliance validation suite. It continues the **`v0.8.x` Advanced Defensive Validation series** by introducing **RAG Validation**.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.8.1` corresponds to the 81st iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.8.1

### 1. 📂 Retrieval-Augmented Generation (RAG) Validation
*   Validates LLM security proxy alignment for RAG-augmented applications where security filters must inspect retrieved document contexts and vector store payloads to block indirect prompt injections.
*   Added a regression validation suite for **RAG validation overrides** (`rag_validation_override=true`).
*   The regression corpus has expanded to **4228 test scenarios** (4214 + 14 context wrappers).
*   **Last Validation Result:** TBD.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the validation suite against the latest target WAF:
```bash
python3 octopus_verifier.py --target /root/home/projects/project-lobster/v1.3.0
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
*   **v0.8.0:** Advanced Defensive Validation Series (Extended conversations).
*   **v0.8.1:** Advanced Defensive Validation Series (RAG validation).
