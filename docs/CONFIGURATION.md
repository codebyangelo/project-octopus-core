# CONFIGURATION.md
## Phase 9 - System Configuration & Profile Reference

This document details all configuration structures, command-line arguments, Validation Profile definitions, and report output schemas in **Project Octopus** (`v1.0.6`).

---

### 1. Command-Line Arguments Reference

| Argument | Type | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `--target` | `str` | `"."` (Current dir) | Target codebase directory path to profile, discover, and verify. |
| `--profile` | `str` | `"auto"` | Validation profiles to execute (`auto`, `all`, or comma-separated list like `generic,optimizer`). |
| `--list-profiles` | `flag` | N/A | Displays all 8 Validation Profiles, descriptions, and included test suites, then exits. |

---

### 2. Validation Profile Configuration (`VALIDATION_PROFILES`)

The `VALIDATION_PROFILES` dictionary in `octopus_verifier.py` defines suite memberships and capability requirements:

```json
{
  "generic": {
    "name": "Generic Validation",
    "description": "Baseline checks for common code patterns, SSRF, path traversal, secrets, and environment exposure.",
    "test_suites": ["SSRF", "Traversal", "Command Injection", "Secrets", "v0.4.0: SSRF", "v0.4.1: Path Traversal", "v0.4.2: Shell Interaction", "v0.4.3: Windows Command Patterns", "v0.4.4: Linux Command Patterns", "v0.4.6: Sensitive Information Exposure", "v0.4.7: Template Injection", "v0.4.8: Environment Variable Exposure", "v0.4.9: Regression Maintenance", "v1.0.0: Production Release"],
    "capability_tests": []
  },
  "security_proxy": {
    "name": "Security Proxy / WAF",
    "description": "Deep validation for input/output firewalls, WAF rules, and security proxies.",
    "test_suites": ["MITRE", "Credential Access", "Discovery", "Collection", "Persistence", "Execution", "Defense Evasion", "Lateral Movement", "Exfiltration", "Privilege Escalation", "v0.5.0: Reporting & Evidence", "v0.5.1: Coverage Heatmaps", "v0.5.2: Risk Scoring", "v0.5.3: Compliance Badges", "v0.5.4: Machine-Readable JSON", "v0.5.5: Version Comparisons", "v0.5.6: Matrix and Summary Attacks", "v0.5.7: Coverage Percentage Attacks", "v0.5.8: Compliance Badge and Severity Attacks", "v0.5.9: Outcome Confidence Spoofing", "v0.6.1: Configuration validation", "v0.6.2: Policy validation", "v0.6.6: External rule packs", "v0.6.9: Stable release", "v0.7.0: CAPEC", "v0.7.1: CWE", "v0.7.2: ASVS", "v0.7.3: NIST_AI_RMF", "v0.7.4: NIST_SSDF", "v0.7.5: Coverage Reports", "v0.7.6: Cross-Reference Matrices", "v0.7.7: Gap Analysis", "v0.7.8: Export Enhancements", "v0.7.9: Stable Release"],
    "capability_tests": ["state_compliance", "persistence_compliance", "chained_compliance"]
  },
  "ai_agent": {
    "name": "AI Agent",
    "description": "Validation for LLM safety boundaries, prompt injection, and excessive agency.",
    "test_suites": ["Prompt Injection", "LLM01: Prompt Injection", "LLM02: Insecure Output Handling", "LLM03: Training Data Poisoning", "LLM04: Model Denial of Service", "LLM05: Supply Chain Vulnerabilities", "LLM06: Sensitive Information Disclosure", "LLM07: Insecure Plugin Design", "LLM08: Excessive Agency", "LLM09: Overreliance", "LLM10: Model Theft", "v0.4.5: Prompt Injection", "v0.8.0: Extended Conversations", "v0.8.1: RAG Validation", "v0.8.2: Tool Invocation", "v0.8.3: Agent Workflow", "v0.8.4: Memory Integrity", "v0.8.5: Multi-Agent Interaction", "v0.8.6: Cross-Session", "v0.8.8: Adversarial Scenario Packs", "v0.8.9: Stable Release"],
    "capability_tests": []
  },
  "optimizer": {
    "name": "Optimizer",
    "description": "Validation for codebase skill optimization, resource limits, and cache databases.",
    "test_suites": ["v0.8.7: Sandboxed Execution", "v0.9.2: Incremental Regression", "v0.9.4: Cached Execution"],
    "capability_tests": ["database", "sandbox"]
  }
}
```

---

### 3. Report Output Schemas & Paths

Outputs are automatically saved to `./reports/`:
* `project_profile.json`: Repository fingerprint, file extension counts, package requirements, inferred architecture, and capability registry.
* `project_profile.md`: Discovery topology report and Mermaid dependency graphs.
* `octopus_report_<timestamp>.sarif`: SARIF 2.1.0 JSON schema containing URI targets, rule IDs, severity levels, and taxonomy references.
* `octopus_summary.json`: Flat JSON summary containing total run counts, passed counts, severity compliance breakdowns, and confidence outcomes.
* `compliance_badge.svg`: Visual SVG status badge.
