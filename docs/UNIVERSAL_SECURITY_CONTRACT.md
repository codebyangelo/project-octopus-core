# 🐙 Project Octopus: The Universal Security Contract

**Document Version:** `1.0.0`  
**Date:** `2026-10-27`  
**Author:** Angelo Ayton (`codebyangelo`) & Systems Architecture Layer  
**Status:** Core Architectural Standard for Universal Verification  

---

## 1. Foundation and Architectural Purpose

Software systems commonly fail not from exotic zero-days, but from permissive boundaries: accepting malformed input, allowing runaway resource consumption, failing open on transient errors, and silently coercing invalid states into benign defaults (such as converting an unparseable offset into address `0x0`).

The Universal Security Contract establishes four non-negotiable invariants that every system under audit must satisfy, and which Project Octopus itself strictly enforces across all adapters.

---

## 2. The Four Invariants of the Contract

### Invariant 1: Strict Ingestion Validation at the Boundary
All external data—including CLI arguments, HTTP headers, file formats, arithmetic expressions, and packet payloads—must be fully validated, sanitized, and clamped at the outermost boundary before reaching core execution logic or state stores.
* Internal functions must never be forced to handle unvalidated external data.
* If an input violates syntax, range, or encoding expectations, the boundary must reject it immediately with an explicit error code.

### Invariant 2: Deterministic Hard Resource Ceilings
Every verification run, parser invocation, and subprocess must operate inside hard, non-negotiable execution ceilings:
* **Memory Limits:** Hard POSIX virtual memory caps (`RLIMIT_AS` set to 512 MB) prevent runaway heap growth, fork bombs, and out-of-memory crash loops.
* **Execution Timeouts:** Immutable wall-clock timeouts (maximum 4.0 seconds for native commands, 25.0 seconds for heavy Python framework imports) prevent infinite loops, ReDoS stalls, and parser hangs.
* **Recursion Clamping:** Explicit recursion depth limits prevent stack overflow crashes on deeply nested syntax or recursive help commands.

### Invariant 3: Absolute Fail-Closed Policy on Error
Whenever an unexpected condition, resource exhaustion, quota limit (HTTP 429), syntax error, or unhandled exception occurs, the system must immediately fail closed:
* Permissive fallbacks and silent passes on error are strictly forbidden.
* In security wrappers and sandboxes, any error condition must halt execution and return an explicit denial (such as exit code `-4`).
* Under no circumstances may an error condition allow un-scanned code, malformed packets, or unauthorized actions to proceed.

### Invariant 4: Zero Tolerance for Undefined or Silent State Coercion
Invalid input must never be silently converted into a valid state.
* Arithmetic overflows must not silently wrap around or evaluate to zero.
* An invalid seek address or unknown symbol must not silently seek to offset `0x0`.
* Missing fields, failed lookups, or unparseable expressions must produce an explicit failure status and non-zero exit code.
* If the boundary returns success (`returncode 0`), the output must be provably valid. Any silent coercion of invalid input is classified as an immediate security bypass (`BYPASS_FAIL`).

---

## 3. Enforcement within Project Octopus v2.0.0

Project Octopus enforces this contract across all three verification dimensions:

1. **In `NativeBinaryAdapter`:**
   * Uses `preexec_fn` to enforce `RLIMIT_AS` virtual memory ceilings on every binary invocation.
   * Enforces process timeouts and traps SIGSEGV, SIGABRT, and memory corruptions as explicit `CRASH_FAIL` outcomes.
   * Flags silent zero-returns on malformed inputs as `BYPASS_FAIL`.

2. **In `PythonLibraryAdapter`:**
   * Isolates library inspection inside an out-of-process subshell to prevent parent heap poisoning.
   * Catches unhandled exceptions and flags them explicitly rather than swallowing tracebacks.

3. **In `StaticRuleAdapter`:**
   * Scans C and Python source code for anti-patterns that violate the contract, including unbounded copy functions (`strcpy`, `gets`), silent exception swallowing (`except: pass`), and missing arithmetic error checks (`r_num_math_err`).
