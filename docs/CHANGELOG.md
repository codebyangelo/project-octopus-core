# CHANGELOG.md
## Release Changelog for Project Octopus

All notable changes, architectural pivots, and platform capabilities of Project Octopus are documented in this file.

---

### [v1.0.6] - 2026-07-30 (Current Release)
#### Added
* **Phase C: Validation Profiles**: Introduced 8 fine-grained Validation Profiles (`generic`, `security_proxy`, `ai_agent`, `optimizer`, `dfir`, `cli`, `rest_api`, `plugin_framework`) via `--profile`.
* **Dynamic Sandbox AST Fallback Scanner (`SandboxScannerWrapper`)**: Added wrap-import hooks for local AST code safety analyzers (e.g., Hermit's `analyze_code_safety`) to evaluate code safety at parse time when network security proxies are offline.
* **Consolidated Multi-Format Reporting**: Streamlined SARIF 2.1.0, JSON, Markdown, and SVG compliance badge output generators.

---

### [v1.0.5] - 2026-07-30
#### Added
* Profile selection CLI flags (`--profile auto|all|<list>`) and profile listing utility (`--list-profiles`).
* Automated fallback engine selection between WAF proxy interfaces and sandbox AST analyzers.

---

### [v1.0.4] - 2026-07-29
#### Added
* Dynamic Capability Verification (active database, sandbox runtime, and CLI interactive select tests).

---

### [v1.0.3] - 2026-07-28
#### Added
* Capability Mapping Registry and Mermaid capability topology graph generation.

---

### [v1.0.2] - 2026-07-27
#### Added
* Third-party package requirement extraction (`requirements.txt`, `setup.py`, `pyproject.toml`) and static import dependency graph generation.

---

### [v1.0.1] - 2026-07-26
#### Added
* Foundational Repository Profiling engine (`ProjectProfiler`) and static risk inspection (`os.system`, `eval`, `exec`).

---

### [v1.0.0] - 2026-07-25
#### Milestone Release
* Production release of WAF security verifier validating 4,494 test cases across state compliance and persistence checks.

---

### [v0.8.0 - v0.8.9] - 2026-06-28
#### Added
* OWASP Top 10 for LLMs test suites, prompt injection, RAG validation, tool invocation, and multi-agent interaction checks.

---

### [v0.7.0 - v0.7.9] - 2026-06-25
#### Added
* Security standards alignment: CAPEC, CWE, OWASP ASVS, NIST AI RMF, and NIST SSDF.

---

### [v0.5.0 - v0.5.9] - 2026-06-20
#### Added
* SARIF 2.1.0 schema generation, JSON summary database outputs, and SVG compliance status badges.
