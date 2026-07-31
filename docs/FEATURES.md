# FEATURES.md
## Phase 5 - Comprehensive Feature Inventory

This document details the functional capabilities, validation profile suites, reporting engines, and static code inspection features of **Project Octopus** (`v1.0.6`).

---

### 1. Platform Features Overview

#### Feature 1: Agnostic Repository Profiler (`ProjectProfiler`)
* **Purpose**: Automatically scans target codebase directories, extracts file distributions, identifies Python import graphs, inspects third-party package dependencies, and infers project architecture styles.
* **Inputs**: Target directory path (`--target`).
* **Outputs**: `project_profile.json`, `project_profile.md`, Mermaid module dependency graphs, and Mermaid capability topology graphs.
* **Dependencies**: `octopus_verifier.py`, `re`, `json`, `os`.
* **Current Maturity**: Production Ready (v1.0.6).

#### Feature 2: Validation Profiles Engine (`VALIDATION_PROFILES`)
* **Purpose**: Partitions verification test cases into 8 targeted domain profiles, allowing developers to execute specific tests or run auto-profile matching based on discovered capabilities.
* **Inputs**: Profile selection string (`--profile generic,optimizer,ai_agent`).
* **Outputs**: Executed profile test suite results and capability compliance status.
* **Dependencies**: `octopus_verifier.py`, `test_cases.json`.
* **Current Maturity**: Production Ready (v1.0.6).

#### Feature 3: Dynamic Sandbox AST Fallback Scanner (`SandboxScannerWrapper`)
* **Purpose**: Wraps local sandbox code safety interfaces (such as Hermit's `analyze_code_safety`) to verify if security regression payloads are intercepted at the AST parse layer when network WAF proxies are offline.
* **Inputs**: Test payload string.
* **Outputs**: `status` (`BLOCKED` / `CLEAN`), `analysis` description.
* **Dependencies**: `octopus_verifier.py`, target sandbox AST module.
* **Current Maturity**: Production Ready (v1.0.6).

#### Feature 4: Standardized Multi-Format Reporting Engine
* **Purpose**: Converts test verification verdicts into enterprise-standard machine-readable SARIF 2.1.0 schemas, flat JSON summaries, detailed Markdown reports, and visual SVG compliance status badges.
* **Inputs**: Regression test results, capability status, severity breakdown.
* **Outputs**: `.sarif`, `.json`, `.md`, `compliance_badge.svg`.
* **Dependencies**: `octopus_verifier.py`, `json`, `datetime`.
* **Current Maturity**: Production Ready (v1.0.6).

---

### 2. Validation Profile Catalog (v1.0.6)

| Profile ID | Profile Name | Target Test Suites / Capabilities | Primary Focus |
| :--- | :--- | :--- | :--- |
| `generic` | Generic Validation | SSRF, Traversal, Command Injection, Secrets, Env Exposure | Baseline code security & path traversal |
| `security_proxy` | Security Proxy / WAF | MITRE ATT&CK families, Defense Evasion, Exfiltration | Firewall rules & WAF regression testing |
| `ai_agent` | AI Agent | OWASP Top 10 for LLMs, Prompt Injection, RAG, Tool Invocation | LLM safety boundaries & prompt injection |
| `optimizer` | Optimizer | Sandboxed Execution, Incremental Regression, Cache Databases | Resource limits, SQLite caches, sandboxing |
| `dfir` | DFIR Tool | Forensic Log Export, Inode Carving Verification | Digital forensics & incident response tools |
| `cli` | CLI Interactive Shell | Terminal TUI parsing, Argparse, Shell interaction | Terminal user interfaces & CLI parsing |
| `rest_api` | REST API Boundary | API validation, Parallel execution, Socket boundary | Network boundaries & socket isolation |
| `plugin_framework` | Plugin Framework | Rule engine adapters, Plugin SDK, Signed reports | Dynamic plugin packaging & CI/CD hooks |
