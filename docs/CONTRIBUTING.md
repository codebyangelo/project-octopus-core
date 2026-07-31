# CONTRIBUTING.md
## Contributing Guidelines for Project Octopus

Thank you for contributing to **Project Octopus**! This document provides guidelines for contributing test suites, validation profiles, and code enhancements following our defense-first posture.

---

### 1. Code of Conduct & Defensive Scope

All contributors must adhere to our **Defense-First Policy**:
* Contributions must focus on **verification capabilities, SARIF 2.1.0 output enrichment, AST safety wrappers, and profile definitions**.
* **Do NOT submit actionable zero-day exploit payloads, weaponized exploit binaries, or evasive bypass tools**.
* All submissions are subject to security review and responsible disclosure practices (`SECURITY_DISCLAIMER.md`).

---

### 2. Development Workflow & Testing Requirements

1. **Fork or Create a Feature Branch**:
   ```bash
   git checkout -b feature/new-validation-profile
   ```

2. **Verify Code Changes**:
   Before submitting pull requests, run verification tests against target repositories to ensure zero regression failures:
   ```bash
   python3 octopus_verifier.py --target /root/home/projects/project-octopus-git/v1.0.6
   ```

3. **Follow Standard Formatting**:
   * Ensure code conforms to PEP 8 standards.
   * Maintain defensive exception handling around dynamic import checks.
