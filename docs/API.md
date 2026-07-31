# API.md
## Phase 8 - Core API & Module Reference

This document provides a technical API reference for the primary Python classes, methods, and functions in **Project Octopus** (`v1.0.6`).

---

### 1. `ProjectProfiler` Class (`octopus_verifier.py`)

The repository profiling engine responsible for fingerprinting target directories, parsing dependencies, mapping capabilities, and generating topology graphs.

#### `__init__(target_path: str)`
* **Description**: Initializes the profiler instance with the target directory path.
* **Parameters**: `target_path` (`str`) — Path to target codebase.

#### `profile() -> Dict[str, Any]`
* **Description**: Executes repository inspection:
  1. Fingerprints files and extensions.
  2. Parses Python imports and static risk indicators (`os.system`, `eval`, `exec`).
  3. Extracts third-party dependencies from `requirements.txt`, `setup.py`, `pyproject.toml`.
  4. Infers architectural style and builds capability registries (`capabilities`).
  5. Generates local dependency graphs and Mermaid topology definitions (`dependency_graph`).
* **Returns**: `Dict[str, Any]` — Comprehensive repository profiling data dictionary.

---

### 2. `SandboxScannerWrapper` Class (`octopus_verifier.py`)

The dynamic fallback wrapper providing AST safety scanning when network WAF proxies are offline.

#### `__init__(target_sandbox: Any)`
* **Description**: Initializes the wrapper with a target sandbox instance (e.g. Hermit's `sandbox`).

#### `scan(payload: str) -> Dict[str, str]`
* **Description**: Passes `payload` to `target_sandbox.analyze_code_safety(payload)`.
* **Parameters**: `payload` (`str`) — Security payload to evaluate.
* **Returns**: `Dict[str, str]` — `{"status": "BLOCKED" | "CLEAN" | "ERROR", "analysis": "<description>"}`.

---

### 3. Core Operational Functions (`octopus_verifier.py`)

#### `determine_outcome(suite_name: str, verdict: Dict[str, Any]) -> str`
* **Description**: Evaluates test verdicts against taxonomy suite names to categorize outcomes into four confidence states.
* **Parameters**:
  * `suite_name` (`str`): Name of the test suite (e.g. `SSRF`, `Command Injection`, `LLM01: Prompt Injection`).
  * `verdict` (`Dict[str, Any]`): Verdict dictionary returned by scanner.
* **Returns**: `str` — `"Complete Block"`, `"Partial Block"`, `"Partial Leak"`, or `"Full Bypass"`.

#### `run_regression_tests(scanner: Any, test_cases_to_run: Dict[str, Any], lobster_path: Optional[str] = None) -> Tuple[Dict[str, Any], int, int]`
* **Description**: Wraps test payloads in 14 syntax templates (Raw, Markdown, HTML, JSON, YAML, CSV) and executes them against the active scanner interface.
* **Parameters**:
  * `scanner`: Active scanner instance (`IronDome`, `SandboxScannerWrapper`, or `None`).
  * `test_cases_to_run`: Subset of test cases filtered by active profiles.
  * `lobster_path`: Optional path to WAF proxy.
* **Returns**: `Tuple[Dict, int, int]` — `(results_dict, total_run_count, total_passed_count)`.

#### `write_profile_reports(profile_results: Dict[str, Any], output_dir: str)`
* **Description**: Outputs `project_profile.json` and `project_profile.md` containing discovery topology and capability matrices.
* **Parameters**:
  * `profile_results`: Profiler output dictionary.
  * `output_dir`: Output directory path (e.g. `./reports/`).
