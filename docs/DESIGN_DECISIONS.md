# DESIGN_DECISIONS.md
## Phase 4 - Engineering Rationale & Architecture Trade-Offs

This document records the architectural trade-offs, rejected design alternatives, security reporting standards, and optimization decisions made during the development of **Project Octopus** (`v1.0.6`).

---

### 1. Key Engineering Rationale & Trade-Offs

#### Decision 1: Validation Profiles vs. Monolithic Suite Execution
* **Context**: Different software targets expose completely different attack surfaces. Running network WAF HTTP payloads against an offline optimizer daemon creates noise and invalid failure reports.
* **Trade-Off**:
  * *Option A (Monolithic Execution)*: Run all 4,400+ test cases against every target directory.
  * *Option B (Profile-Driven Execution)*: Partition test cases into 8 Validation Profiles (`generic`, `security_proxy`, `ai_agent`, `optimizer`, `dfir`, `cli`, `rest_api`, `plugin_framework`) and allow auto-selection or CLI specification (`--profile`).
* **Rationale**: Option B was selected in `v1.0.5`. Profile selection reduces verification execution time from minutes to seconds for targeted runs and eliminates irrelevant test failures.

#### Decision 2: Multi-Engine Fallback Scanning (`SandboxScannerWrapper`)
* **Context**: When verifying software targets that lack an active HTTP security proxy (WAF), a static verifier fails to test input security.
* **Trade-Off**:
  * *Option A (Fail/Skip Verification)*: Mark verification as skipped if no WAF proxy is running.
  * *Option B (Dynamic Fallback Sandbox Wrapper)*: Wrap-import the target's local AST code safety interface (e.g. Hermit's `analyze_code_safety`) to verify if security payloads are intercepted at the AST layer.
* **Rationale**: Option B was selected. It allows Octopus to verify security compliance even when target network proxies are offline.

#### Decision 3: Standardizing Output on SARIF 2.1.0 and SVG Badges
* **Context**: Security verification results must be consumed by both automated CI/CD pipelines (GitHub Actions, IDEs) and human stakeholders.
* **Trade-Off**:
  * *Option A (Plain text logs only)*: Simple implementation, but unparseable by automated tooling.
  * *Option B (Multi-Format Reporting)*: Output SARIF 2.1.0 JSON schemas, flat JSON summaries, detailed Markdown reports, and visual SVG status badges.
* **Rationale**: Option B was selected to maximize tool interoperability and provide immediate visual status indicators.

---

### 2. Rejected Alternatives & Design Decisions

| Problem Area | Considered Approach | Why Rejected | Final Implemented Solution |
| :--- | :--- | :--- | :--- |
| **Repository Profiling** | Manual configuration files (`octopus.toml`) | Required developers to manually write capability descriptors for every target project. | Automated profiling (`ProjectProfiler`) inferring package dependencies, imports, and capabilities. |
| **Verdict Alignment** | Binary Pass / Fail scoring | Ignored context-specific security nuances (e.g. blocking a command via RCE rule vs. generic obfuscation rule). | Four-tier outcome confidence alignment (*Complete Block*, *Partial Block*, *Partial Leak*, *Full Bypass*). |
| **Test Case Storage** | Hardcoded Python lists | Hard to maintain, update, or share across different release versions. | Centralized JSON test case databases (`test_cases.json`) and versioned validation packs. |
