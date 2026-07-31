# 🐙 Project Octopus (v0.0.4)

Project Octopus (v0.0.4) is the fourth major release of the security regression and compliance validation suite. It focuses on **Encoding Suite I**, expanding the decoupled payload database with URL-encoded, double URL-encoded, and hexadecimal bypass variants across all six standard taxonomy suites.

---

## 🆕 New in v0.0.4

### 1. 🌐 Encoding Suite I Payload Expansion
Decoupled [test_cases.json](file:///root/home/projects/project-octopus/v0.0.4/test_cases.json) now contains 18 additional obfuscated payloads (bringing the total to 42 tests):
*   **URL-encoded Bypass Variants:** Simulates payload execution wrapped in standard percent encoding (e.g. `%20` for spaces, `%2f` for paths, `%3a` for colons).
*   **Double URL-encoded Bypass Variants:** Simulates nested percent encoding (e.g. `%2520` or `%253c`) designed to slip past single-pass pre-decoders.
*   **Hexadecimal Bypass Variants:** Simulates inline hexadecimal byte string replacements (e.g. `\x2e\x2e\x2f` for traversal, or completely hex-encoded administrative operations).

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the expanded encoding regression suite against your security controls (e.g., Project Lobster's latest version):
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.6.4
```

The verifier reads [test_cases.json](file:///root/home/projects/project-octopus/v0.0.4/test_cases.json), executes the scanner, evaluates the verdict, and saves a markdown compliance report inside the `./reports/` directory.

---

## 📈 Version Changelog
*   **v0.0.1:** Initial release. Included baseline regression tests for loopback SSRF, cloud metadata SSRF, command separator injections, and basic directory traversals.
*   **v0.0.2:** Expanded validation coverage to include MITRE ATT&CK threat tactics and OWASP LLM security vulnerabilities, updating remediation rule advice.
*   **v0.0.3:** Payload taxonomy refactor. Externalized test cases into JSON format and standardized test groups (SSRF, Traversal, Command Injection, Prompt Injection, Secrets, MITRE).
*   **v0.0.4:** Encoding Suite I. Added URL-encoded, double URL-encoded, and hexadecimal payload variants.

