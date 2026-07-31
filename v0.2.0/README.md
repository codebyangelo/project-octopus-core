# 🐙 Project Octopus (v0.2.0)

Project Octopus (v0.2.0) is the twentieth release of the security regression and compliance validation suite. It introduces the **`v0.2.x` ATT&CK Expansion series**, beginning with **Credential Access (TA0006)**.

---

## 🆕 New in v0.2.0

### 1. 🔑 Credential Access Suite (MITRE ATT&CK TA0006)
*   Introduced 8 new credential harvesting threat payloads verifying:
    *   **T1552.004:** Private SSH Key extraction (`id_rsa`).
    *   **T1552.001:** Cloud provider access config extraction (`.aws/credentials`).
    *   **T1003:** OS level password database access (`opasswd`).
    *   **T1555.003:** Web browser stored sqlite database access (`Login Data`).
*   Included complete context suite mappings (Markdown, HTML, YAML, CDATA XML, CSV, Source scopes) and encoding variations (URL, Double URL, hex, unicode/homoglyph escapes) for all new payloads, expanding the regression corpus by **56 test scenarios**.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the state, persistence, and chained regression validation suite:
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.6.7
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.9:** Core regression engines, context wrappers, severity metrics, and confidence scopes.
*   **v0.1.0 - v0.1.9:** Conversation-state compliance series, cache namespace isolation, and multi-turn threat sequence correlation flows.
*   **v0.2.0:** Credential Access Suite. Expanded MITRE ATT&CK regression coverage to detect OS credential harvesting, private key exposures, and browser credential database lookups.
