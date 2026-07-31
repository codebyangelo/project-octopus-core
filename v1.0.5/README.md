# 🐙 Project Octopus (v1.0.5)

Project Octopus (v1.0.5) is the iteration release implementing **Phase C (Validation Profiles)** under the `v2.0` roadmap (transitioning from a hardcoded WAF verifier to a project-agnostic verification platform).

It partitions validation sets into fine-grained profiles (Generic, Security Proxy, AI Agent, Optimizer, DFIR, CLI, REST API, Plugin Framework), dynamically configures verification targets based on active profiles, hooks into fallback scanning interfaces (like Sandbox AST analyzers), and outputs consolidated compliance reports.

---

## 🆕 New in v1.0.5 (Phase C: Validation Profiles)

### 1. 🗂️ Fine-Grained Validation Profiles
*   **Agnostic Profiling:** Replaces the rigid single-suite runner with 8 distinct Validation Profiles.
*   **Targeted Matching:** Run profile validations specific to the target system's claims (e.g. running the `optimizer` and `sandbox` suites on Hermit without loading WAF payloads).
*   **CLI Selection:** Control executed suites using `--profile` (values: `auto`, `all`, or comma-separated lists) and inspect options using `--list-profiles`.

### 2. 🔌 Dynamic Fallback Scanners
*   **AST Safety Scanner Wrapper:** If the target lacks a network security proxy (WAF) but exposes code sandbox execution capabilities (e.g. Hermit's `sandbox.py`), Octopus wrap-imports its `analyze_code_safety` interface to dynamically check if regression payloads are intercepted at the AST layer.
*   **Multi-Engine Support:** Auto-selects WAF (IronDome) or Sandbox AST filters as the active scanner engine.

### 3. 📊 Consolidated Unified Reporting
*   **Unified MD Reports:** Combines repository profiling topology, dynamic capability findings, and detailed regression test results into a single report (`reports/octopus_report_<timestamp>.md`).
*   **Consolidated JSON & SARIF:** Single JSON database output for regression tracking.

---

## 🚀 Execution & Usage

To run Project Octopus against any target codebase directory:

```bash
# List available profiles and their descriptions
python3 octopus_verifier.py --list-profiles

# Verify Lobster WAF using auto-profile selection (runs Generic & Security Proxy profiles)
python3 octopus_verifier.py --target /root/home/projects/project-lobster/v1.5.0

# Verify Hermit Optimizer using auto-profile selection (runs Generic, Optimizer, CLI, and Sandbox profiles)
python3 octopus_verifier.py --target /root/home/projects/project-hermit/v0.1.9

# Run only a specific profile (e.g., Generic and Optimizer) on any target
python3 octopus_verifier.py --target /root/home/projects/project-hermit/v0.1.9 --profile generic,optimizer
```

---

## 📈 Version Changelog
*   **v1.0.5:** Validation Profiles (Phase C), AST filter fallback wrapper scans, and consolidated reporting.
*   **v1.0.4:** Dynamic Capability Verification (active database, sandbox runtime, and CLI select tests).
*   **v1.0.3:** Capability Mapping Registry and capability topology graph generation.
*   **v1.0.2:** Third-party package parsing, Mermaid dependency graphing, and architectural style inference.
*   **v1.0.1:** Foundational Project Discovery profiling and static risk analysis.
*   **v1.0.0:** Production Release of WAF verifier (4494 test cases, state compliance, persistence validations).
*   **v0.1.0 - v0.9.9:** Progressive security enhancements covering OWASP Top 10 for LLMs, MITRE ATT&CK families, standards alignment, and parallel validation execution.

