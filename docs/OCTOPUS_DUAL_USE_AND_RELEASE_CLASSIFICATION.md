# Project Octopus: Dual-Use Threat Model & Public Release Classification

## 1. Executive Summary

As Project Octopus matures from an internal testing harness into a universal upstream security verification platform, establishing a strict classification boundary between **benign verification infrastructure** and **dual-use threat-bearing offensive assets** is mandatory.

This classification ensures that any public open-source release provides high defensive utility to software engineers and maintainers while preventing the leakage of weaponized exploit dictionaries, cloud metadata theft payloads, proprietary agent defenses, and LLM jailbreaks.

---

## 2. Category A: Benign & Safe to Push Publicly (Green List)

The components in Project Octopus v2.0.0 represent defensive, non-weaponized software testing infrastructure. They contain zero exploit payloads, command-and-control logic, or bypass dictionaries, making them entirely safe for public open-source release under standard permissive licensing (e.g., Apache 2.0 or MIT):

1. **Polyglot Profiling Engine ([`v2.0.0/core/profiler.py`](file:///root/home/projects/project-octopus/v2.0.0/core/profiler.py)):**
   - Passive static scanner analyzing project languages, build systems (Make, CMake, Meson, Cargo), and architectural capabilities.
   - Operates strictly in read-only mode with zero code execution.

2. **Universal Engine & Taxonomy ([`v2.0.0/core/models.py`](file:///root/home/projects/project-octopus/v2.0.0/core/models.py), [`v2.0.0/core/engine.py`](file:///root/home/projects/project-octopus/v2.0.0/core/engine.py)):**
   - 5-state verdict taxonomy (`SAFE_BLOCK`, `SAFE_ALLOW`, `CRASH_FAIL`, `BYPASS_FAIL`, `NOT_APPLICABLE`, `SKIPPED`).
   - Standard test dispatching and adapter lifecycle management.

3. **Standardized Reporting Engine ([`v2.0.0/core/reporter.py`](file:///root/home/projects/project-octopus/v2.0.0/core/reporter.py)):**
   - Exports findings into OASIS SARIF 2.1.0, JSON, and Markdown formats.
   - Integrates natively with GitHub Advanced Security and CI/CD pipelines without exposing proprietary heuristics.

4. **Decoupled Verification Adapters ([`v2.0.0/adapters/`](file:///root/home/projects/project-octopus/v2.0.0/adapters/)):**
   - `NativeBinaryAdapter`: Runs compiled binaries inside localized sandboxes with POSIX signal trapping (`SIGSEGV`, `SIGABRT`), process memory limits (`RLIMIT_AS`), and timeouts.
   - `PythonLibraryAdapter`: Evaluates Python module imports and state transitions in isolated subshells.
   - `CSourceSemanticAdapter`: Performs static source code auditing for unhandled return values, missing switch `break;` statements, and unbounded `strcpy()` calls.
   - `CLIStateIntegrityAdapter`: Verifies whether command-line interfaces preserve state invariants and return compliant exit codes.
   - `StaticRuleAdapter`: General-purpose static regex pattern auditor.

5. **Upstream Defensive Boundary Corpora ([`v2.0.0/test_cases/`](file:///root/home/projects/project-octopus/v2.0.0/test_cases/)):**
   - `upstream_native.json`: Standard boundary math checks (`?v 100/0`, `?v 0x10000000000000000`), seek limits (`s -0x8000000000000000`), and help dispatcher formatting (`so?`).
   - `upstream_python.json`: Symbolic state regression checks (such as angr `UltraPage` 4096-byte memory split clamping).
   - `upstream_c_source.json`: Source code boundary patterns (`r_num_math_err`).
   - *Safety Justification:* These cases are standard unit test inputs indistinguishable from existing open-source regression suites (e.g. `r2r` in radare2 or `pytest` in angr). They test whether software crashes or handles boundaries gracefully; they cannot be weaponized.

---

## 3. Category B: Threat-Bearing Assets (Red / Restricted List)

The following components represent dual-use offensive capabilities, weaponized attack dictionaries, or confidential agent architecture disclosures. **These components must never be pushed to a public repository:**

1. **Cloud SSRF & Metadata Exfiltration Dictionaries ([`v1.0.6/test_cases.json`](file:///root/home/projects/project-octopus/v1.0.6/test_cases.json)):**
   - *Contents:* Extensive lists of obfuscated IP formats (octal `0251.0376.0251.0376`, decimal `2852039166`, IPv4-mapped IPv6 `[::ffff:a9fe:a9fe]`, wildcard binds `0.0.0.0`, alternative loopbacks `127.0.0.2`) engineered specifically to bypass enterprise Cloud WAFs and pivot into `http://169.254.169.254/latest/meta-data/`.
   - *Threat Level:* **Critical**. In the hands of an attacker, this represents an automated payload dictionary for stealing AWS/GCP/Azure IAM credentials, STS session tokens, and kubelet credentials from vulnerable web services.

2. **System Compromise & Reverse Shell Payloads ([`v1.0.6/red_team_test.py`](file:///root/home/projects/project-octopus/v1.0.6/red_team_test.py)):**
   - *Contents:* Operational reverse shell strings (`/bin/bash -i >& /dev/tcp/...`, `/dev/udp/`, `mkfifo`, base64-encoded bash execution), container escape attempts, and destructive payloads (`rm -rf /`).
   - *Threat Level:* **High**. These are weaponized execution strings designed to achieve interactive remote shell access or perform denial-of-service destruction.

3. **Data Vault Exfiltration Payloads ([`v1.0.6/red_team_test.py`](file:///root/home/projects/project-octopus/v1.0.6/red_team_test.py)):**
   - *Contents:* Scripts targeting local database files (`red_team_test_hermit.db`), extracting authentication tokens, dumping master key vaults, and abusing process environment variables.
   - *Threat Level:* **High**. Can be directly reused by adversaries to target local agent daemons and steal encrypted vaults.

4. **Adversarial Prompt Injections & LLM Guardrail Bypasses ([`v1.0.6/novel_red_team.py`](file:///root/home/projects/project-octopus/v1.0.6/novel_red_team.py), [`v1.0.6/test_cases.json`](file:///root/home/projects/project-octopus/v1.0.6/test_cases.json)):**
   - *Contents:* 60+ sophisticated prompt injection attacks, role confusion triggers, and guardrail bypasses (such as string stitching to evade static keyword filters: `globals()['__builtins__']['ex' + 'ec']`).
   - *Threat Level:* **High**. Adversaries targeting AI agent ecosystems can deploy these payloads to compromise autonomous agents, induce unauthorized tool invocations, and breach enterprise security guardrails.

5. **Proprietary Agent Architecture & Ecosystem Packs ([`packs/marine_ecosystem/`](file:///root/home/projects/project-octopus/packs/marine_ecosystem/)):**
   - *Contents:* Internal integration logic, private threat database schemas (`threat_db.json`), and defensive heuristics specifically tailored to `project-lobster`, `project-hermit`, and `project-mantis`.
   - *Threat Level:* **Medium/Proprietary**. Public release exposes the internal defensive mechanisms and detection thresholds of Angelo's private agent stack, granting adversaries blueprint knowledge to develop tailored evasion bypasses.

---

## 4. Upstream Sanitization & Release Architecture

To safely prepare Project Octopus for public release while retaining internal offensive validation capabilities, the project should be divided into a dual-repository structure:

1. **Public Repository (`octopus-core`):**
   - Contains exclusively `v2.0.0/` (Universal Engine, decoupled adapters, SARIF reporter, documentation) and `test_cases/upstream_*.json`.
   - All references to legacy `v1.0.x`, `marine_ecosystem`, `red_team_test.py`, `novel_red_team.py`, and `test_cases.json` are excluded.

2. **Private Repository (`octopus-enterprise` or `octopus-internal`):**
   - Houses the complete history, the weaponized `v1.0.6/test_cases.json` attack corpus, red-team harnesses, and the proprietary `packs/marine_ecosystem/`.
   - Utilized privately by Angelo to validate defense agents (`Hermit`, `Lobster`, `Mantis`) under confidential conditions.
