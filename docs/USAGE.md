# USAGE.md
## Phase 7 - Usage & Operations Guide

This document provides a developer guide for operating, configuring, and inspecting **Project Octopus** (`v1.0.6`).

---

### 1. Quick Start Guide

To run Project Octopus against any software target:

1. **Navigate to the Version Directory**:
   ```bash
   cd project-octopus-git/v1.0.6
   ```

2. **List Available Validation Profiles**:
   ```bash
   python3 octopus_verifier.py --list-profiles
   ```
   *Expected Output*: Displays descriptions and included test suites for all 8 profiles (`generic`, `security_proxy`, `ai_agent`, `optimizer`, `dfir`, `cli`, `rest_api`, `plugin_framework`).

3. **Verify Target Repository with Auto-Profile Matching**:
   ```bash
   python3 octopus_verifier.py --target /path/to/target/repository
   ```
   *Octopus will automatically inspect the target repository, build its capability registry, generate a Mermaid topology graph, and execute matching profile validation suites.*

4. **Target Specific Profiles**:
   ```bash
   python3 octopus_verifier.py --target /path/to/target/repository --profile generic,optimizer,ai_agent
   ```

---

### 2. Output Deliverables Directory (`./reports/`)

Every verification run automatically generates five report artifacts in `./reports/`:

* **`project_profile.md`**: Human-readable repository discovery report containing file extension breakdowns, imported package dependencies, inferred architecture style, and Mermaid topology graphs.
* **`project_profile.json`**: Machine-readable repository capability database.
* **`octopus_report_<timestamp>.md`**: Comprehensive security regression report detailing severity breakdowns, test outcomes (*Complete Block*, *Partial Block*, *Partial Leak*, *Full Bypass*), and rule alignment.
* **`octopus_report_<timestamp>.sarif`**: Standard SARIF 2.1.0 security report schema.
* **`compliance_badge.svg`**: Visual SVG badge showing pass/fail status and compliance percentages.

---

### 3. CLI Command-Line Arguments Reference

| Argument | Options / Values | Description |
| :--- | :--- | :--- |
| `--target` | Absolute or relative directory path | Target codebase directory to profile and verify. |
| `--profile` | `auto`, `all`, or comma-separated list | Specifies which Validation Profiles to execute during the verification run. |
| `--list-profiles` | None | Displays descriptions and suite memberships for all 8 Validation Profiles. |
