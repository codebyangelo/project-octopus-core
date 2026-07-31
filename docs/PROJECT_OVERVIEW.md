# PROJECT_OVERVIEW.md
## Phase 1 - Universal Project Purpose & Architectural Core

This document outlines the core purpose, problem statement, engineering goals, target users, scope, non-goals, and design philosophy of **Project Octopus** (`v1.0.6`).

---

### 1. Project Purpose

**Project Octopus** is an agnostic security verification, compliance profiling, and defensive regression testing platform. It provides automated, profile-based verification of target software systems across 8 validation domains (`generic`, `security_proxy`, `ai_agent`, `optimizer`, `dfir`, `cli`, `rest_api`, `plugin_framework`). Octopus dynamically inspects a target codebase, maps its capabilities, hooks into active or fallback scanner interfaces (such as WAF firewalls or sandbox AST code safety analyzers), and generates machine-readable SARIF 2.1.0, JSON, Markdown, and SVG compliance badge reports.

---

### 2. Problem Statement

Modern software architectures—ranging from AI agent frameworks to security proxies and developer tools—face critical verification challenges:

1. **Rigid, Monolithic Verifiers**: Hardcoded verification suites fail when applied to diverse software types (e.g. attempting to run WAF HTTP payload tests against a CLI tool or code optimizer).
2. **Lack of Agnostic Capability Mapping**: Security tooling often requires manual configuration instead of dynamically inferring target architecture capabilities (database, CLI, network API, AI agent, sandbox).
3. **Inflexible Fallback Scanners**: Static security verifiers break when a primary network proxy is offline, rather than dynamically fallback-wrapping local AST code safety interfaces.
4. **Unstandardized Compliance Output**: Non-standard verification outputs prevent integration into enterprise CI/CD pipelines and security dashboards.

---

### 3. Engineering Goals

Project Octopus addresses these challenges through five foundational engineering pillars:

* **Profile-Based Verification Taxonomy**: Partition validation suites into fine-grained profiles (`generic`, `security_proxy`, `ai_agent`, `optimizer`, `dfir`, `cli`, `rest_api`, `plugin_framework`) allowing targeted verification runs (`--profile`).
* **Automated Project Profiling & Topology Discovery**: Automatically inspect target repositories (`ProjectProfiler`), map file extension distributions, infer architecture styles, and construct Mermaid capability topology graphs.
* **Dynamic Multi-Engine Fallback Scanning**: Auto-select active scanners (e.g. WAF proxy engines) or fallback-wrap local AST code safety analyzers (`SandboxScannerWrapper`) to verify input safety at parse time.
* **Standardized Machine-Readable Output**: Generate standard SARIF 2.1.0 security reports, consolidated JSON databases, human-readable Markdown summaries, and SVG compliance badges.
* **Responsible Defensive Scope**: Ensure verification suites maintain a strict defense-first posture without embedding actionable exploit chains or bypass hints in public documentation.

---

### 4. Target Users

* **DevSecOps & CI/CD Engineers**: Developers seeking automated, standardized SARIF 2.1.0 security compliance checks in continuous integration pipelines.
* **AI Safety & Agent Systems Developers**: Engineers verifying LLM prompt injection boundaries, output handling, and tool invocation safety.
* **Software Security Auditors & Compliance Teams**: Auditors requiring automated cross-reference mapping against NIST AI RMF, NIST SSDF, OWASP Top 10 for LLMs, MITRE ATT&CK, and ASVS standards.

---

### 5. Scope & Non-Goals

#### In-Scope:
* Profile-driven verification execution (`octopus_verifier.py --target <path> --profile <list>`).
* Automated capability mapping and Mermaid topology graph generation.
* Fallback wrapper scanning for sandbox AST safety interfaces (`analyze_code_safety`).
* Generating SARIF 2.1.0 reports, JSON summaries, and SVG compliance badges.
* Defensive regression testing against standard security taxonomies.

#### Non-Goals:
* Functioning as an offensive attack framework or publishing actionable zero-day exploit chains.
* Providing real-time inline network packet filtering (Project Octopus is the *verifier*, whereas systems like Project Lobster act as the *proxy*).
* Modifying target source code during verification runs.

---

### 6. Design Philosophy & Architectural Principles

1. **Agnostic & Profile-Driven**: Verification should adapt to the target codebase's capabilities rather than forcing a single rigid test harness.
2. **Defense-First Transparency**: Security verification outputs must clearly articulate compliance gaps without providing actionable offensive bypass instructions to external threat actors.
3. **Interoperability & Standards Compliance**: Output formats must seamlessly integrate into industry-standard IDEs and security tooling via SARIF 2.1.0 and JSON schemas.
