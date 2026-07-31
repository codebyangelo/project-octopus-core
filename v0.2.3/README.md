# 🐙 Project Octopus (v0.2.3)

Project Octopus (v0.2.3) is the twenty-third release of the security regression and compliance validation suite. It continues the **`v0.2.x` ATT&CK Expansion series** by introducing **Persistence (TA0003)**.

---

## 🆕 New in v0.2.3

### 1. 🔄 Persistence Suite (MITRE ATT&CK TA0003)
*   Introduced 8 new account manipulation and execution persistence payloads verifying:
    *   **T1053.003:** Scheduled Task/Job: Cron (`crontabs`, `cron.d` additions).
    *   **T1098.004:** Account Manipulation: SSH Key Authorized (`authorized_keys` modification).
    *   **T1546.004:** Event Triggered Execution: Startup profiles configuration (`.bashrc` write).
    *   **T1037.004:** Boot or Logon Initialization Scripts: rc.local manipulation (`rc.local` write).
*   Included complete context suite mappings (Markdown, HTML, YAML, CDATA XML, CSV, Source scopes) and encoding variations (URL, Double URL, hex, unicode/homoglyph escapes) for all new payloads, expanding the regression corpus by **56 test scenarios** (totaling **1,204 regression checks**).

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the state, persistence, and chained regression validation suite:
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.7.0
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.9:** Core regression engines, context wrappers, severity metrics, and confidence scopes.
*   **v0.1.0 - v0.1.9:** Conversation-state compliance series, cache namespace isolation, and multi-turn threat sequence correlation flows.
*   **v0.2.0:** Credential Access Suite. Expanded MITRE ATT&CK regression coverage to detect OS credential harvesting, private key exposures, and browser credential database lookups.
*   **v0.2.1:** Discovery Suite. Expanded regression coverage to detect system enumeration, process status scans, and network service scans.
*   **v0.2.2:** Collection Suite. Expanded regression coverage to detect local archive staging and screen frame captures.
*   **v0.2.3:** Persistence Suite. Expanded regression coverage to detect crontab persistence configurations, profile shell hooks, and SSH backdoor modifications.
