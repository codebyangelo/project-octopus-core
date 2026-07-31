# 🐙 Project Octopus (v0.1.5)

Project Octopus (v0.1.5) is the fifteenth release of the security regression and compliance validation suite. It focuses on auditing **Prompt Injection → Command Execution Chained Attack Vectors** to verify that multi-turn prompt overrides leading to subsequent malicious OS command execution triggers are correctly flagged and blocked.

---

## 🆕 New in v0.1.5

### 1. ⛓️ Prompt Injection → Command Execution Chained Validation
The verifier runs compliance test scenarios verifying multi-turn instruction override sequence defenses against remote code/command execution:
*   **Prompt Injection → Command Execution Chain:** Simulates Turn 1 where an attacker injects command instructions to ignore safety controls and stage a command execution trigger. Turn 2 runs a trigger query requesting a custom command run (e.g. `custom_execute('whoami')`).
*   The test validates that the AI Sentinel's combined multi-turn context formatting correctly isolates and intercepts the staged command run, returning `BLOCKED` with appropriate category flags.

### 2. ⚡ Rate Limiter Bypass in Chained Suite
*   To prevent token bucket rate exhaustion when running consecutive dynamic chained scans, the verifier temporarily bypasses the target's limiter allow checks during context-correlation tests.

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
