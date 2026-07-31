# 🐙 Project Octopus (v0.2.4)

Project Octopus (v0.2.4) is the twenty-fourth release of the security regression and compliance validation suite. It continues the **`v0.2.x` ATT&CK Expansion series** by introducing **Execution (TA0002)**.

> [!NOTE]
> **Versioning Scheme:** Version names directly represent the absolute iteration sequence number (e.g., `v0.2.4` corresponds to the 24th iteration/release). This is why the release sequence transitions directly from `v0.0.9` (9th iteration) to `v0.1.0` (10th iteration), rather than using a standard decimal overflow (such as `v0.0.10`).

---

## 🆕 New in v0.2.4

### 1. ⚡ Execution Suite (MITRE ATT&CK TA0002)
*   Introduced 8 new command and scripting interpreter execution payloads verifying:
    *   **T1059.004:** Command and Scripting Interpreter: Bash shell command injection (`bash -c`).
    *   **T1059.006:** Command and Scripting Interpreter: Interpreter shell invocation (`python -c`, `perl -e` scripts).
    *   **T1059:** Script Downloading and Piping (`curl | bash`, `wget | sh` patterns).
*   Included complete context suite mappings (Markdown, HTML, YAML, CDATA XML, CSV, Source scopes) and encoding variations (URL, Double URL, hex, unicode/homoglyph escapes) for all new payloads, expanding the regression corpus by **56 test scenarios** (totaling **1,316 regression checks**).

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the state, persistence, and chained regression validation suite:
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.7.1
```

---

## 📈 Version Changelog
*   **v0.0.1 - v0.0.9:** Core regression engines, context wrappers, severity metrics, and confidence scopes.
*   **v0.1.0 - v0.1.9:** Conversation-state compliance series, cache namespace isolation, and multi-turn threat sequence correlation flows.
*   **v0.2.0:** Credential Access Suite. Expanded MITRE ATT&CK regression coverage to detect OS credential harvesting, private key exposures, and browser credential database lookups.
*   **v0.2.1:** Discovery Suite. Expanded regression coverage to detect system enumeration, process status scans, and network service scans.
*   **v0.2.2:** Collection Suite. Expanded regression coverage to detect local archive staging and screen frame captures.
*   **v0.2.3:** Persistence Suite. Expanded regression coverage to detect crontab persistence configurations, profile shell hooks, and SSH backdoor modifications.
*   **v0.2.4:** Execution Suite. Expanded regression coverage to detect scripting interpreter commands and pipes to execution.
