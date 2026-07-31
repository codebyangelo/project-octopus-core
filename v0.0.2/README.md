# 🐙 Project Octopus (v0.0.2)

Project Octopus (v0.0.2) is the second major release of the security regression and compliance validation suite. It extends the baseline regression checks from v0.0.1 (focused on basic SSRF, command injection, and directory traversal) by introducing structured compliance validations for **MITRE ATT&CK Techniques** and **OWASP Top 10 for LLM Vulnerabilities**.

---

## 🆕 New in v0.0.2

### 1. 🛡️ MITRE ATT&CK Techniques Coverage
The validator now checks if security filters can intercept system exploits mapping to core MITRE ATT&CK tactics:
*   **T1003 (OS Credential Dumping):** Simulates access to `/etc/shadow` representing dumping of account hashes.
*   **T1070 (Indicator Removal / Anti-Forensics):** Simulates log file deletion and file shredding (`shred -u`).
*   **T1059 (Command and Scripting Interpreter):** Validates detection of active reverse shell listeners (`nc -lvnp`).
*   **T1548 (Abuse Elevation Control Mechanism):** Evaluates detection of SUID bit configuration escalations (`chmod +s`).

### 2. 🤖 OWASP Top 10 for LLMs Coverage
Adds simulation inputs targeting generative AI deployment vulnerabilities:
*   **LLM01 (Prompt Injection):** Tests instruction overrides (`Ignore previous instructions...`).
*   **LLM02 (Insecure Output Handling):** Validates filtering of malicious script tags (`<script>alert(...)`) that bypass backend sanitization.
*   **LLM06 (Sensitive Information Disclosure):** Tests for the exposure of environment variables holding API tokens (e.g. `VERTEX_API_KEY`, `GEMINI_API_KEY`).
*   **LLM07 (Insecure Plugin Design):** Checks plugin API calls targeting link-local metadata addresses (SSRF).

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the expanded regression suite against your security controls (e.g., Project Lobster's latest version):
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.5.6
```

The verifier outputs a detailed breakdown of which MITRE and OWASP vulnerabilities were successfully contained or bypassed, generating a markdown compliance log inside the `./reports/` directory.

---

## 📈 Version Changelog
*   **v0.0.1:** Initial release. Included baseline regression tests for loopback SSRF, cloud metadata SSRF, command separator injections, and basic directory traversals.
*   **v0.0.2:** Expanded validation coverage to include MITRE ATT&CK threat tactics and OWASP LLM security vulnerabilities, updating remediation rule advice.
