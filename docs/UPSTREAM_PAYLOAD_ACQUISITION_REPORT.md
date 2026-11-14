# Upstream Payload & Adapter Acquisition Report: Project Octopus v2.0.0

## 1. Executive Summary

This report documents the acquisition, implementation, and verification of upstream security boundary payloads and specialized scanner adapters in Project Octopus v2.0.0. 

The primary objective was to expand Project Octopus beyond generic or ecosystem-dependent checks, empowering it to surface and audit the exact classes of real-world vulnerabilities and boundary failures recently addressed in upstream repositories, including radare2 (PRs #26606, #26617, #26771, #26852, #26862, commit `704e2e853e`) and angr (PR #7353 / Issues #6314 and #3807, PR #6723).

---

## 2. Acquired Scanner Adapters

Project Octopus v2.0.0 provides five decoupled adapters, each tailored to specific upstream execution environments and inspection modalities:

1. **`CSourceSemanticAdapter` ([`c_source.py`](file:///root/home/projects/project-octopus/v2.0.0/adapters/c_source.py)):**
   - Purpose: Performs semantic AST and regex auditing on C/C++ source trees without requiring dynamic compilation or shared library resolution.
   - Target Rules:
     - Detects calls to legacy `r_num_math()` that lack error pointers, preventing silent `0x0` fallback corruptions.
     - Detects missing `break;` statements in command dispatchers that cause command fallthrough into execution handlers.
     - Detects unbounded memory primitives such as `strcpy()` and unsafe inputs such as `gets()`.
     - Confirms adoption of hardened boundary APIs like `r_num_math_err()`.

2. **`CLIStateIntegrityAdapter` ([`cli_state.py`](file:///root/home/projects/project-octopus/v2.0.0/adapters/cli_state.py)):**
   - Purpose: Executes multi-turn command sequences against native binaries to verify CLI state preservation across invalid inputs.
   - Target Invariants:
     - Address preservation: Verifies that an invalid seek expression (e.g. `s 0x1000; s nonexistent; ?v $$`) preserves the current program counter rather than resetting to `0x00000000`.
     - Help dispatcher separation: Verifies that queries like `so?` or `sa?` cleanly print help text rather than treating `?` as an operand or opcode argument.
     - Exit status compliance: Verifies that malformed expressions return appropriate non-zero error codes.

3. **`PythonLibraryAdapter` ([`python_library.py`](file:///root/home/projects/project-octopus/v2.0.0/adapters/python_library.py)):**
   - Purpose: Executes isolated subshell evaluations of Python frameworks (e.g., `angr`, `scapy`) with memory clamping and process timeout protection (25.0 seconds).
   - Invariants: Automatically aligns and indents multiline test payloads into isolated `try/except` execution blocks, catching both unhandled runtime crashes and verifying boundary exception trapping.

4. **`NativeBinaryAdapter` ([`native_binary.py`](file:///root/home/projects/project-octopus/v2.0.0/adapters/native_binary.py)):**
   - Purpose: Dynamic binary executor with POSIX signal trapping (`SIGSEGV`, `SIGABRT`, `SIGFPE`), 512 MB memory clamping (`RLIMIT_AS`), and automated `LD_LIBRARY_PATH` discovery for uninstalled local shared libraries.

5. **`StaticRuleAdapter` ([`static_rule.py`](file:///root/home/projects/project-octopus/v2.0.0/adapters/static_rule.py)):**
   - Purpose: Universal fallback scanner supporting regex and semantic token matching across polyglot projects without execution.

---

## 3. Acquired Upstream Test Corpora

### A. C Source & Semantic Invariants ([`upstream_c_source.json`](file:///root/home/projects/project-octopus/v2.0.0/test_cases/upstream_c_source.json))
- `R2_C_SEMANTIC_LEGACY_MATH_01` (High): Audits for legacy `r_num_math()` calls missing error pointers.
- `R2_C_SEMANTIC_MATH_ERR_USAGE_02` (High): Verifies widespread adoption of hardened `r_num_math_err()` API.
- `R2_C_SEMANTIC_HELP_BREAK_03` (High): Scans for switch-case help queries missing `break;` statements.
- `R2_C_SEMANTIC_UNBOUNDED_STRCPY_04` (Critical): Scans for unbounded `strcpy()` calls violating SVAP Tier 1 memory safety.
- `R2_C_SEMANTIC_DANGEROUS_GETS_05` (Critical): Scans for `gets()` calls.

### B. Native CLI & Dynamic Execution ([`upstream_native.json`](file:///root/home/projects/project-octopus/v2.0.0/test_cases/upstream_native.json))
- `R2_MATH_OVERFLOW_64BIT`: Tests unsigned 64-bit integer overflow expression handling (`?v 0x10000000000000000`).
- `R2_MATH_ARITHMETIC_WRAP`: Tests 64-bit addition wrap (`?v 0xFFFFFFFFFFFFFFFF + 1`).
- `R2_MATH_DIVIDE_BY_ZERO`: Verifies integer division by zero is safely trapped without crash (`?v 100 / 0`).
- `R2_MATH_MODULO_BY_ZERO`: Verifies modulo by zero is trapped (`?v 100 % 0`).
- `R2_SEEK_UNDERFLOW_SIGNED`: Tests signed underflow clamping (`s -0x8000000000000001`).
- `R2_SEEK_EXTREME_NEGATIVE`: Tests INT64_MIN seek boundary (`s -0x8000000000000000`).
- `R2_SEEK_STATE_PRESERVATION`: Multi-turn state verification (`s 0x1000; s nonexistent_symbol_xyz; ?v $$`).
- `R2_SEEK_RELATIVE_FORWARD`: Positive delta seek verification (`s+ 0x10; ?v $$`).
- `R2_SEEK_OPCODE_HELP_FALLTHROUGH`: Verifies opcode seek help does not treat `?` as an operand (`so?`).
- `R2_SEEK_ALIGN_HELP_FALLTHROUGH`: Verifies align seek help does not fall through (`sa?`).
- `R2_SEEK_ARG_WHITESPACE_TRIM`: Verifies parser leading whitespace handling (`so   0x10`).
- `R2_WRITE_INVALID_EXPR`: Error validation on invalid write expression (`w 0x100 invalid_expr`).
- `R2_CACHE_HYGIENE_LINES`: Validates line seek cache invalidation on error (`e lines.to=invalid_val; sl+1`).
- `R2_FORMAT_STRING_PRINT`: Verifies format string specifiers print literally (`?e %x%x%x%s%n`).
- `R2_PARSER_RECURSIVE_HELP`: Evaluates parser recursion limits (`???`).
- `R2_PARSER_CLEAN_EXIT`: Evaluates clean shutdown (`q`).

### C. Python Library & Symbolic State Invariants ([`upstream_python.json`](file:///root/home/projects/project-octopus/v2.0.0/test_cases/upstream_python.json))
- `PY_IMPORT_INIT_01`: Verifies clean package initialization in isolated subshell.
- `ANGR_CROSS_PAGE_MEMORY_SPLIT_02`: Tests `UltraPage` cross-boundary memory split during state merging (PR #7353 / Issues #6314 and #3807), verifying that symbolic memory objects spanning 4096-byte page boundaries do not raise `IndexError`.
- `ANGR_PAGE_CONTAINMENT_OOB_03`: Validates that `UltraPage._contains()` returns `False` for out-of-bounds offsets (`-1` and `size + 1`) rather than throwing an exception.
- `ANGR_AILMENT_EXPRESSION_RECURSION_04`: Validates AST recursion depth handling across deeply nested expressions.
- `PY_MALFORMED_SYNTAX_05`: Confirms intentional boundary exceptions are trapped gracefully without host interpreter collapse.

---

## 4. Empirical Verification Results

### radare2 Audit Execution
- Target: `/root/home/projects/radare2`
- Command: `python3 v2.0.0/octopus_verifier.py --target /root/home/projects/radare2 --adapter c_source`
- Findings:
  - `R2_C_SEMANTIC_LEGACY_MATH_01` (High): **BYPASS_FAIL** (Unchecked `r_num_math()` calls detected in 98 files, including `cmd_seek.inc.c` lines 888 and 931).
  - `R2_C_SEMANTIC_MATH_ERR_USAGE_02` (High): **SAFE_ALLOW** (Hardened `r_num_math_err()` boundary check verified in 23 files).
  - `R2_C_SEMANTIC_HELP_BREAK_03` (High): **BYPASS_FAIL** (Missing `break;` statements after help queries detected in 26 files).
  - `R2_C_SEMANTIC_UNBOUNDED_STRCPY_04` (Critical): **BYPASS_FAIL** (Direct calls to unbounded `strcpy()` detected in 72 files).
  - `R2_C_SEMANTIC_DANGEROUS_GETS_05` (Critical): **SAFE_BLOCK** (Zero instances of `gets()` found in production source).
- Result: **2/5 tests passed (40.0% compliance)**. Project Octopus surfaced actionable upstream boundary issues directly aligned with recent PRs.

### angr Audit Execution
- Target: `/root/home/projects/angr`
- Command: `python3 v2.0.0/octopus_verifier.py --target /root/home/projects/angr --adapter python`
- Findings:
  - `PY_IMPORT_INIT_01` (High): **SAFE_ALLOW** (Imported cleanly in subshell).
  - `ANGR_CROSS_PAGE_MEMORY_SPLIT_02` (Critical): **SAFE_ALLOW** (Symbolic cross-boundary merge across 4096-byte page boundary verified without `IndexError`).
  - `ANGR_PAGE_CONTAINMENT_OOB_03` (High): **SAFE_ALLOW** (`UltraPage._contains()` cleanly returned `False` for out-of-bounds queries).
  - `ANGR_AILMENT_EXPRESSION_RECURSION_04` (Medium): **SAFE_ALLOW** (Nested unary expression depth handled cleanly).
  - `PY_MALFORMED_SYNTAX_05` (Medium): **SAFE_BLOCK** (Simulated boundary exception safely trapped).
- Result: **5/5 tests passed (100.0% compliance)**. All upstream patches and invariants verified intact.

### Unit Test Suite
- Command: `python3 v2.0.0/test_v2.py`
- Result: **7/7 unit tests passed** in 0.395s, validating polyglot profiling, token boundaries, reporter generation, Marine ecosystem pack opt-in, `CSourceSemanticAdapter`, `CLIStateIntegrityAdapter`, and `PythonLibraryAdapter`.
