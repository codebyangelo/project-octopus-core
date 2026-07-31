# 🐙 Project Octopus (v0.1.2)

Project Octopus (v0.1.2) is the twelfth release of the security regression and compliance validation suite. It focuses on the **Chained Transaction Context Validation Engine**, auditing multi-turn history shifts and evaluating cache memory vulnerability mappings under state-dependent bypass conditions.

---

## 🆕 New in v0.1.2

### 1. 🔗 Chained Context Validation
The verifier runs compliance test scenarios to inspect sequential multi-turn state correlation:
*   **FIFO Context Window:** Validates that as user dialogue turns scale, preceding packet objects correctly shift within the sliding context history buffer (up to Lobster's limits of 3 packets).
*   **Cache Context Scoping (State cache poisoning):** Validates if unique context histories with identical payloads correctly isolate cache lookups. This test exposes context-independent cache poisoning vulnerabilities (e.g. executing a clean payload which is cached, and then exploiting it under a staged malicious state chain).

### 2. 🛡️ Context Remediation Recommendations
*   When a cache context bypass is detected, the verifier automatically appends exact code remediation patterns to incorporate context history hashes into the `RUNTIME_CACHE` lookup schema inside `src/core.py`.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the state, persistence, and chained regression validation suite:
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.6.5
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.7:** Regression baselines, taxonomy refactors, encoding checks, and context boundary tests (Markdown, HTML, YAML, CDATA XML, CSV, Source scopes).
*   **v0.0.8:** Severity Engine. Grouped findings by risk levels (`Critical`, `High`, `Medium`, `Low`).
*   **v0.0.9:** Confidence Scoring. Implemented outcomes (`Complete Block`, `Partial Block`, `Partial Leak`, `Full Bypass`).
*   **v0.1.0:** Conversation State Compliance. Verified multi-turn context propagation, cache isolation, and rate-limiting limits.
*   **v0.1.1:** Conversation State Persistence. Verified threat database parsing, forensic report generation, and cache serialization format rules.
*   **v0.1.2:** Chained Transaction Context. Verified sliding context history window parsing and mapped the cache context scoping vulnerability.
