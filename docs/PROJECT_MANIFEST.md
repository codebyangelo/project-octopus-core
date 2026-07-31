# PROJECT_MANIFEST.md
## Phase 0 - Project Inventory Manifest

This document records the repository structure, file counts, module components, verification profiles, and technology stack of **Project Octopus** (`project-octopus-git`).

---

### 1. General Project Information

* **Project Name:** Project Octopus
* **Target Directory:** `project-octopus-git`
* **Current Version:** `v1.0.6` (Phase C: Validation Profiles & Agnostic Verification)
* **Architecture Style:** Agnostic Security Verification & Profile-Based Compliance Platform
* **Primary Language:** Python 3.10+ (tested with Python 3.13)
* **Output Standards:** SARIF 2.1.0, JSON, Markdown Reports, SVG Badges

---

### 2. File & Extension Distribution

| Metric / Extension | Details / Count |
| :--- | :--- |
| **Total Root Files** | 11,297 |
| **Total Version Directories** | 106 (`v0.0.1` through `v1.0.6`) |
| `.md` Documentation Files | 7,381 files |
| `.sarif` SARIF 2.1.0 Security Reports | 3,272 files |
| `.py` Python Source Files | 425 files |
| `.json` Test & Profile JSON Files | 163 files |
| `.svg` Compliance Badges | 54 files |
| `.pyc` Python Bytecode Files | 2 files |

---

### 3. Key Subdirectory & Release Manifest

| Directory Name | Purpose / Milestone |
| :--- | :--- |
| `v1.0.6/` | Active release (Phase C Validation Profiles, AST sandbox fallback, SARIF reporting) |
| `v1.0.5/` | Validation profiles rollout and multi-engine fallback scanner integration |
| `v1.0.4/` | Dynamic capability verification (database, sandbox, CLI select tests) |
| `v1.0.3/` to `v1.0.1/` | Project discovery profiling, static risk analysis, and topology graph generation |
| `v1.0.0/` | Production WAF verifier release (4,494 test cases evaluated) |
| `v0.9.0/` to `v0.9.9/` | Plugin SDK, validation pack format, signed reports, and release readiness |
| `v0.8.0/` to `v0.8.9/` | OWASP Top 10 for LLMs, prompt injection, RAG, and multi-agent interaction suites |
| `v0.7.0/` to `v0.7.9/` | Standards alignment (CAPEC, CWE, ASVS, NIST AI RMF, NIST SSDF) |
| `v0.6.0/` to `v0.6.9/` | Generic rule engine adapters, CLI/API validation, and parallel execution |
| `v0.5.0/` to `v0.5.9/` | Risk scoring, compliance badges, SARIF machine-readable JSON outputs |
| `v0.4.0/` to `v0.4.9/` | Extended regression suites (SSRF, Traversal, Command Patterns, Secrets) |
| `v0.1.0/` to `v0.3.9/` | Foundational security rule development and initial verifier iterations |

---

### 4. Code Base Components (v1.0.6)

* [octopus_verifier.py](file:///root/home/projects/project-octopus-git/v1.0.6/octopus_verifier.py): Primary profile-based verification and compliance platform.
* `test_cases.json`: Test payload database containing rule definitions across security taxonomy families.
* [novel_red_team.py](file:///root/home/projects/project-octopus-git/v1.0.6/novel_red_team.py): Red-team verification harness.
* [red_team_test.py](file:///root/home/projects/project-octopus-git/v1.0.6/red_team_test.py): Standalone shell command injection test runner.
* [test_ssrf_standalone.py](file:///root/home/projects/project-octopus-git/v1.0.6/test_ssrf_standalone.py): Standalone network boundary SSRF verifier.

---

### 5. Dependency Inventory

* **Built-in Standard Modules**: `os`, `sys`, `re`, `json`, `argparse`, `datetime`, `hashlib`
* **Optional / Extension Integrations**: `rich` (for CLI terminal formatting), `requests` (for network boundary verification), target AST safety interfaces (`analyze_code_safety`).
