# 🐙 Project Octopus (v0.1.7)

Project Octopus (v0.1.7) is the seventeenth release of the security regression and compliance validation suite. It focuses on auditing **Attack Graph Visualizations in Compliance Reports** to map overall security pipeline transitions visually.

---

## 🆕 New in v0.1.7

### 1. 🛡️ Target Security Pipeline & Attack Graph
*   The generated compliance reports now include a **Mermaid state-transition flowchart** showing how request payloads transition between detection nodes and outcomes:
    *   **Context Scoping (Input History hashes)**
    *   **Tier 0 Heuristics check (IronDome)**
    *   **Tier 1 Cache Lookup (RUNTIME_CACHE)**
    *   **Tier 2 Rate Limiter check (RateLimiter)**
    *   **Tier 3 AI Sentinel check (Gemini API Sentinel)**
    *   **Outcomes:** `BLOCKED` states, `API_ERROR` rate limits, and `CLEAN` execution routes.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the state, persistence, and chained regression validation suite:
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.6.6
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.7:** Regression baselines, taxonomy refactors, encoding checks, and context boundary tests (Markdown, HTML, YAML, CDATA XML, CSV, Source scopes).
*   **v0.0.8:** Severity Engine. Grouped findings by risk levels (`Critical`, `High`, `Medium`, `Low`).
*   **v0.0.9:** Confidence Scoring. Implemented outcomes (`Complete Block`, `Partial Block`, `Partial Leak`, `Full Bypass`).
*   **v0.1.0:** Conversation State Compliance. Verified multi-turn context propagation, cache isolation, and rate-limiting limits.
*   **v0.1.1:** Conversation State Persistence. Verified threat database parsing, forensic report generation, and cache serialization format rules.
*   **v0.1.2:** Chained Transaction Context. Verified sliding context history window parsing and mapped the cache context scoping vulnerability.
*   **v0.1.3:** Prompt Injection → SSRF Chained Validation. Added multi-turn correlation tests checking for staged prompt override SSRF chains.
*   **v0.1.4:** Prompt Injection → Secret Leakage Chained Validation. Added multi-turn correlation tests checking for staged prompt override secret exfiltration chains.
*   **v0.1.5:** Prompt Injection → Command Execution Chained Validation. Added multi-turn correlation tests checking for staged prompt override OS command execution chains.
*   **v0.1.6:** Compound Attack Reporting. Integrated Mermaid visualization flows mapping multi-stage context threats in security reports.
*   **v0.1.7:** Attack Graph Visualizations. Embedded unified state transition flowchart detailing the target protection pipeline levels.
