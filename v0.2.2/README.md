# 🐙 Project Octopus (v0.2.2)

Project Octopus (v0.2.2) is the twenty-second release of the security regression and compliance validation suite. It continues the **`v0.2.x` ATT&CK Expansion series** by introducing **Collection (TA0009)**.

---

## 🆕 New in v0.2.2

### 1. 📦 Collection Suite (MITRE ATT&CK TA0009)
*   Introduced 8 new local data collection and archiving payloads verifying:
    *   **T1560:** Archive Collected Data (`tar`, `zip`, `gzip` commands).
    *   **T1113:** Screen Capture (`screencapture`, `scrot` commands).
*   Included complete context suite mappings (Markdown, HTML, YAML, CDATA XML, CSV, Source scopes) and encoding variations (URL, Double URL, hex, unicode/homoglyph escapes) for all new payloads, expanding the regression corpus by **56 test scenarios** (totaling **1,092 regression checks**).

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the state, persistence, and chained regression validation suite:
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.6.9
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.9:** Core regression engines, context wrappers, severity metrics, and confidence scopes.
*   **v0.1.0 - v0.1.9:** Conversation-state compliance series, cache namespace isolation, and multi-turn threat sequence correlation flows.
*   **v0.2.0:** Credential Access Suite. Expanded MITRE ATT&CK regression coverage to detect OS credential harvesting, private key exposures, and browser credential database lookups.
*   **v0.2.1:** Discovery Suite. Expanded regression coverage to detect system enumeration, process status scans, and network service scans.
*   **v0.2.2:** Collection Suite. Expanded regression coverage to detect local archive staging and screen frame captures.
