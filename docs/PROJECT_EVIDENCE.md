# PROJECT_EVIDENCE.md
## Pass A - Evidence Extraction Log for Project Octopus

This document contains raw factual quotes, file structures, table schemas, and empirical metrics extracted directly from `project-octopus-git` without inference or speculation.

---

### 1. General Project Inventory & Root Structure

* **Root Path:** `/root/home/projects/project-octopus-git`
* **Total Version Directories:** 106 directories (`v0.0.1` through `v1.0.6`).
* **Total File Count:** 11,297 files.
* **File Breakdown by Extension:**
  * `.md`: 7,381 documentation files (Version changelogs, execution plans, compliance reports)
  * `.sarif`: 3,272 SARIF 2.1.0 machine-readable security reports
  * `.py`: 425 Python source files (Verification engines, AST wrappers, red-team suites)
  * `.json`: 163 JSON files (Test case databases, repository profile outputs)
  * `.svg`: 54 SVG files (Compliance badges, topology graphs)
  * `.pyc`: 2 compiled Python bytecode files

---

### 2. Core Verification Modules (`v1.0.6`)

Direct extraction of primary executable Python files in `v1.0.6`:
* `octopus_verifier.py`: Core verification engine supporting repository profiling (`ProjectProfiler`), validation profiles (`generic`, `security_proxy`, `ai_agent`, `optimizer`, `dfir`, `cli`, `rest_api`, `plugin_framework`), sandbox AST wrappers (`SandboxScannerWrapper`), and multi-format report generation (Markdown, JSON, SARIF 2.1.0, SVG compliance badges).
* `test_cases.json`: Centralized regression test case payload database (containing test cases for SSRF, Path Traversal, Shell Interaction, Command Injection, Prompt Injection, MITRE ATT&CK families, OWASP Top 10 LLM risks, and ASVS/NIST standards).
* `novel_red_team.py`: Red-team verification script for testing novel adversarial payload variants.
* `red_team_test.py`: Standalone execution harness for evaluating target scanner responses against high-severity shell command payloads.
* `test_ssrf_standalone.py`: Standalone SSRF verification suite for checking network boundary defenses.

---

### 3. Verification Profile Taxonomy (v1.0.6 Evidence)

Direct extraction of `VALIDATION_PROFILES` dictionary from `v1.0.6/octopus_verifier.py`:
1. **`generic`**: Baseline checks for common code patterns, SSRF, path traversal, secrets, and environment exposure.
2. **`security_proxy`**: Validation for input/output firewalls, WAF rules, and security proxies.
3. **`ai_agent`**: Validation for LLM safety boundaries, prompt injection, and excessive agency.
4. **`optimizer`**: Validation for codebase skill optimization, resource limits, and cache databases.
5. **`dfir`**: Forensics capabilities validation (disk/memory carving, incident response reporting).
6. **`cli`**: Interactive TUI/CLI shell parsing and keyboard polling validations.
7. **`rest_api`**: Network boundaries, socket isolation, and concurrent API request validation.
8. **`plugin_framework`**: Plugin SDK, validation pack packaging, and dynamic hook loading checks.

---

### 4. Direct Empirical Benchmark Findings

* **Verified Verification Suites (v1.0.0 baseline)**: 4,494 test cases evaluated across state compliance, persistence validations, and chained transaction contexts.
* **SARIF Compliance**: Outputs standard SARIF 2.1.0 schema reports containing URI targets, rule IDs, taxonomy references (CWE, CAPEC, OWASP), and severity scores.
* **AST Fallback Integration**: Dynamic integration wrapper (`SandboxScannerWrapper`) hooks directly into target AST analyzers (such as Project Hermit's `analyze_code_safety`) to verify code safety at parse time when network proxies are inactive.
