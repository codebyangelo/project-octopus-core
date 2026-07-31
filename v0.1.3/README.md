# 🐙 Project Octopus (v0.1.3)

Project Octopus (v0.1.3) is the thirteenth release of the security regression and compliance validation suite. It focuses on auditing **Prompt Injection → SSRF Chained Attack Vectors** to verify that multi-turn prompt overrides leading to subsequent Server-Side Request Forgery triggers are correctly flagged and blocked.

---

## 🆕 New in v0.1.3

### 1. ⛓️ Prompt Injection → SSRF Chained Validation
The verifier runs compliance test scenarios verifying multi-turn instruction override sequence defenses:
*   **Prompt Injection → SSRF Chain:** Simulates Turn 1 where an attacker injects command instructions to ignore safety controls and stage a cloud metadata IP pull on the next turn. Turn 2 runs a trigger query request (`fetch_cloud_ip()`).
*   The test validates that the AI Sentinel's combined multi-turn context formatting correctly isolates and intercepts the staged exploit chain, returning `BLOCKED` with appropriate category flags.

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
