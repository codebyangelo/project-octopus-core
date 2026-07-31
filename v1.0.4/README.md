# 🐙 Project Octopus (v1.0.4)

Project Octopus (v1.0.4) is the iteration release implementing **Phase A (Project Discovery)** and **Phase B (Capability Mapping & Verification)** under the `v2.0` roadmap (transitioning from a hardcoded WAF verifier to a project-agnostic verification platform).

It profiles target codebases, maps active capabilities (Databases, CLIs, Sandboxes, Network APIs, AI Agents, and Security Proxies), and runs targeted compliance validations matching the codebase's active capabilities.

---

## 🆕 New in v1.0.1 - v1.0.4

### 1. 🔍 Repository Discovery & Fingerprinting (v1.0.1 - v1.0.2)
*   **Static Profiling:** Automatically extracts file structure counts, file extensions, and key framework assets.
*   **Package Inspection:** Parses third-party dependencies from `requirements.txt`, `setup.py`, or `pyproject.toml`.
*   **Local Dependency Flow:** Generates valid **Mermaid dependency flowcharts** showing file import linkages.
*   **Architectural Inference:** Infers the system architecture style based on fingerprint analysis (e.g. Sidecar WAF vs. Dual-process WAL Optimizer).

### 2. 🗺️ Capability Mapping Registry (v1.0.3)
*   Compiles active vs. inactive capabilities mapping target codebases to target verification suites and logs evidence lists.
*   Constructs a visual **Mermaid Capability Topology Graph** showing project capability nodes.

### 3. ⚙️ Dynamic Capability Verification (v1.0.4)
*   **Database Capability Suite:** Checks SQLite database integrity, confirms Write-Ahead Logging (`WAL` mode) concurrency setups, and validates busy timeouts (expected `>= 5000ms`).
*   **Sandbox Capability Suite:** Audits virtual memory limits (`RLIMIT_AS`) and RAM disk mounts (`tmpfs`), and dynamically runs AST pre-checks and subprocess isolation/timeout containment validations.
*   **CLI Capability Suite:** Validates arguments parsing flags and non-blocking key keyboard select polling drivers.

---

## 🚀 Execution & Usage

To run Project Octopus against any target codebase directory:

```bash
# Verify Lobster WAF (Profiles capabilities, executes 3 capability checks + 4494 WAF scenarios)
python3 octopus_verifier.py --target /root/home/projects/project-lobster/v1.5.0

# Verify Hermit Optimizer (Profiles capabilities, executes 29 capability checks, skips WAF checks)
python3 octopus_verifier.py --target /root/home/projects/project-hermit/v0.1.9
```

---

## 📈 Version Changelog
*   **v1.0.4:** Dynamic Capability Verification (active database, sandbox runtime, and CLI select tests).
*   **v1.0.3:** Capability Mapping Registry and capability topology graph generation.
*   **v1.0.2:** Third-party package parsing, Mermaid dependency graphing, and architectural style inference.
*   **v1.0.1:** Foundational Project Discovery profiling and static risk analysis.
*   **v1.0.0:** Production Release of WAF verifier (4494 test cases, state compliance, persistence validations).
*   **v0.1.0 - v0.9.9:** Progressive security enhancements covering OWASP Top 10 for LLMs, MITRE ATT&CK families, standards alignment, and parallel validation execution.

