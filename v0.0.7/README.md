# 🐙 Project Octopus (v0.0.7)

Project Octopus (v0.0.7) is the seventh major release of the security regression and compliance validation suite. It focuses on **Context Suite II**, expanding context-wrapping variations to test how security controls handle payloads nested inside YAML literal blocks, XML CDATA sections, CSV records, and various Source Code structures (comments, multiline strings, and function frames).

---

## 🆕 New in v0.0.7

### 1. 🔀 Context Suite I & II Integration
The runner executes all 54 base payloads inside **14 distinct syntax context wrappers**, resulting in **756 individual test scenarios**:
*   **Raw Context:** The payload executes directly as-is.
*   **Markdown Contexts:** Fenced python code blocks, inline backticks, and markdown URL link arguments.
*   **HTML Contexts:** Embedded inside a `<div>`, within input tag attributes (`value=""`), and hidden inside HTML comments (`<!-- ... -->`).
*   **JSON Context:** Nested within JSON key-value pairs (properly double-quote and escape sanitized).
*   **YAML Context:** Nested within multi-line literal block variables (`payload: |`).
*   **XML Context:** Encapsulated inside XML nodes using character CDATA structures (`<![CDATA[...]]>`).
*   **CSV Context:** Injected as cell values inside standard double-quoted fields (escaping quotes using double-quote RFC 4180 delimiters).
*   **Source Code Contexts:** Embedded inside Python comments, assigned inside multiline python string variables, or parsed as code lines inside function scopes.

---

## 🚀 Execution & Usage

### Verify Target Codebase
To run the full multi-context regression suite against your security controls (e.g., Project Lobster's latest version):
```bash
python3 octopus_verifier.py --target /path/to/project-lobster/v0.6.5
```

The verifier reads [test_cases.json](file:///root/home/projects/project-octopus/v0.0.7/test_cases.json), applies the 14 context wrappers, executes the target scanner, and saves a markdown compliance report inside the `./reports/` directory.

---

## 📈 Version Changelog
*   **v0.0.1:** Initial release. Included baseline regression tests for loopback SSRF, cloud metadata SSRF, command separator injections, and basic directory traversals.
*   **v0.0.2:** Expanded validation coverage to include MITRE ATT&CK threat tactics and OWASP LLM security vulnerabilities, updating remediation rule advice.
*   **v0.0.3:** Payload taxonomy refactor. Externalized test cases into JSON format and standardized test groups (SSRF, Traversal, Command Injection, Prompt Injection, Secrets, MITRE).
*   **v0.0.4:** Encoding Suite I. Added URL-encoded, double URL-encoded, and hexadecimal payload variants.
*   **v0.0.5:** Encoding Suite II. Added Unicode, homoglyph, UTF-8, and mixed-encoding payload variants.
*   **v0.0.6:** Context Suite I. Executed payloads inside Markdown, HTML, and JSON contexts (432 scenarios).
*   **v0.0.7:** Context Suite II. Added YAML, XML, CSV, and source-code contexts (756 scenarios).
