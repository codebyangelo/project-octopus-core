# 🐙 Project Octopus (v0.2.1)

Project Octopus (v0.2.1) is the twenty-first release of the security regression and compliance validation suite. It continues the **`v0.2.x` ATT&CK Expansion series** by introducing **Discovery (TA0007)**.

---

## 🆕 New in v0.2.1

### 1. 🔍 Discovery Suite (MITRE ATT&CK TA0007)
*   Introduced 8 new post-exploitation enumeration payloads verifying:
    *   **T1082:** System Information Discovery (`uname -a`, `hostname`).
    *   **T1049:** Network Connection Discovery (`netstat -ant`, `arp -a`).
    *   **T1057:** Process Discovery (`ps aux`).
*   Included complete context suite mappings (Markdown, HTML, YAML, CDATA XML, CSV, Source scopes) and encoding variations (URL, Double URL, hex, unicode/homoglyph escapes) for all new payloads, expanding the regression corpus by **56 test scenarios** (totaling **980 regression checks**).

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the state, persistence, and chained regression validation suite:
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.6.8
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.9:** Core regression engines, context wrappers, severity metrics, and confidence scopes.
*   **v0.1.0 - v0.1.9:** Conversation-state compliance series, cache namespace isolation, and multi-turn threat sequence correlation flows.
*   **v0.2.0:** Credential Access Suite. Expanded MITRE ATT&CK regression coverage to detect OS credential harvesting, private key exposures, and browser credential database lookups.
*   **v0.2.1:** Discovery Suite. Expanded regression coverage to detect system enumeration, process status scans, and network service scans.
