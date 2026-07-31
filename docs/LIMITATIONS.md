# LIMITATIONS.md
## Phase 14 - Technical Debt & System Limitations

This document catalogs known limitations, technical debt, dependencies, and unsupported features in **Project Octopus** (`v1.0.6`).

---

### 1. Known Technical Debt & Performance Limitations

1. **Dependency Inferences on Non-Standard Modules**:
   * *Observation*: `ProjectProfiler` extracts import declarations (`import foo`) to construct Mermaid dependency graphs. Highly dynamic imports (`__import__('foo')`, `importlib.import_module`) or deep sub-module aliases may not be reflected in static graph outputs.
   * *Impact*: Dependency graph visualization may omit dynamically imported modules.

2. **Module Path Dependencies for Target State Compliance Tests**:
   * *Observation*: Capability verification suites (e.g. `run_state_compliance_tests`) attempt dynamic imports (`from src.core import scan_packet`). If the target codebase structure differs from standard directory layouts (or lacks a `src/` directory), state compliance checks report import fallback errors.
   * *Mitigation in v1.0.6*: Added try/except fallback handling to report capability test skips without aborting overall profile verification.

3. **Memory Overhead during Monolithic Run SARIF Serialization**:
   * *Observation*: Executing monolithic runs (`--profile all`) against targets produces SARIF 2.1.0 report files containing over 3,000 detailed rule evaluation objects, generating SARIF files up to **~15 MB** in size.
   * *Mitigation*: DevSecOps pipelines should specify targeted profiles (`--profile generic,optimizer`) to generate compact SARIF outputs.

---

### 2. Current Unsupported Features

* **Inline Network Packet Interception**: Project Octopus is strictly a verification and profiling platform; it does not act as an inline network WAF proxy.
* **Offensive Exploit Generation**: Octopus does not generate weaponized exploit binaries or active attack payloads.
* **Non-Python Source Inspection**: Language profiling (`ProjectProfiler`) is optimized for Python repositories; AST safety fallback wrappers require target Python AST interfaces.
