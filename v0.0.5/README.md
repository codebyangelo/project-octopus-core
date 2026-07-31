# 🐙 Project Octopus (v0.0.5)

Project Octopus (v0.0.5) is the fifth major release of the security regression and compliance validation suite. It focuses on **Encoding Suite II**, expanding the decoupled payload database with Unicode, homoglyph, UTF-8, and mixed-encoding bypass variants across all six standard taxonomy suites.

---

## 🆕 New in v0.0.5

### 1. 🌐 Encoding Suite II Payload Expansion
Decoupled [test_cases.json](file:///root/home/projects/project-octopus/v0.0.5/test_cases.json) now contains 16 additional obfuscated payloads (bringing the total to 58 tests):
*   **Unicode/Fullwidth Bypass Variants:** Simulates payload execution wrapped in wide/fullwidth Unicode characters (e.g. `ｌｏｃａｌｈｏｓｔ` or `．．／`).
*   **Homoglyph Obfuscation Variants:** Simulates character-spoofing attacks (e.g. using Cyrillic `а` or Greek Alpha `Α` in `GEMINI_API_KEY` or `/etc/shadow`) that appear identical but bypass Latin-specific regex filters.
*   **Overlong UTF-8 & Zero-Width Spaces:** Uses overlong UTF-8 sequences (like `%c0%ae`) or zero-width spacing (like `\u200b` in `shred​`) to disrupt regex tokenization.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the expanded encoding regression suite against your security controls (e.g., Project Lobster's latest version):
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.6.4
```

The verifier reads [test_cases.json](file:///root/home/projects/project-octopus/v0.0.5/test_cases.json), executes the scanner, evaluates the verdict, and saves a markdown compliance report inside the `./reports/` directory.

---

## 📈 Version Changelog
*   **v0.0.1:** Initial release. Included baseline regression tests for loopback SSRF, cloud metadata SSRF, command separator injections, and basic directory traversals.
*   **v0.0.2:** Expanded validation coverage to include MITRE ATT&CK threat tactics and OWASP LLM security vulnerabilities, updating remediation rule advice.
*   **v0.0.3:** Payload taxonomy refactor. Externalized test cases into JSON format and standardized test groups (SSRF, Traversal, Command Injection, Prompt Injection, Secrets, MITRE).
*   **v0.0.4:** Encoding Suite I. Added URL-encoded, double URL-encoded, and hexadecimal payload variants.
*   **v0.0.5:** Encoding Suite II. Added Unicode, homoglyph, UTF-8, and mixed-encoding payload variants.


