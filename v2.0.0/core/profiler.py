# -*- coding: utf-8 -*-
"""
🐙 Project Octopus v2.0.0 - Polyglot Repository Profiler
Provides multi-language discovery, toolchain detection, and strict boundary analysis.
"""

import os
import re
import ast
from typing import Dict, List, Set, Any, Tuple
from .models import TargetProfile

EXTENSION_LANGUAGE_MAP = {
    ".c": "C",
    ".h": "C/C++ Header",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++ Header",
    ".hxx": "C++ Header",
    ".rs": "Rust",
    ".py": "Python",
    ".pyi": "Python Stub",
    ".go": "Go",
    ".s": "Assembly",
    ".asm": "Assembly",
    ".S": "Assembly",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".js": "JavaScript",
    ".ts": "TypeScript",
}

BUILD_SYSTEM_MARKERS = {
    "meson.build": "Meson",
    "Makefile": "Make",
    "makefile": "Make",
    "GNUmakefile": "Make",
    "CMakeLists.txt": "CMake",
    "Cargo.toml": "Cargo (Rust)",
    "pyproject.toml": "PEP 517/518 (Python)",
    "setup.py": "Setuptools (Python)",
    "go.mod": "Go Modules",
    "configure.ac": "Autotools",
}

IGNORE_DIR_NAMES = {
    ".git", ".github", ".agents", "__pycache__", ".venv", "venv",
    ".tox", ".pytest_cache", ".mypy_cache", "node_modules", "target"
}

TEST_DIR_PATTERNS = re.compile(r'(^|[\/\\])(tests?|unit_tests?|fixtures?|subprojects|third_party|vendor)([\/\\]|$)', re.I)

class PolyglotProfiler:
    def __init__(self, target_path: str):
        self.target_path = os.path.abspath(target_path)
        self.files: List[str] = []
        self.prod_files: List[str] = []
        self.test_files: List[str] = []
        self.languages: Dict[str, int] = {}
        self.build_systems: Set[str] = set()
        self.key_files_found: Set[str] = set()
        self.imports: Set[str] = set()
        self.risk_findings: List[Dict[str, Any]] = []

    def profile(self) -> TargetProfile:
        if not os.path.exists(self.target_path):
            raise FileNotFoundError(f"Target path does not exist: {self.target_path}")

        # 1. Walk directory hierarchy with exclusion of transient/hidden trees
        for root, dirs, filenames in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIR_NAMES and not d.startswith('.')]
            
            for f in filenames:
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, self.target_path)
                self.files.append(rel_path)

                is_test = bool(TEST_DIR_PATTERNS.search(rel_path))
                if is_test:
                    self.test_files.append(rel_path)
                else:
                    self.prod_files.append(rel_path)

                # Check build systems & key files (deduplicated by root level where appropriate)
                if f in BUILD_SYSTEM_MARKERS:
                    self.build_systems.add(BUILD_SYSTEM_MARKERS[f])
                if f in ["README.md", "LICENSE", "SECURITY.md"]:
                    self.key_files_found.add(f)

                # Extension mapping
                _, ext = os.path.splitext(f)
                ext_lower = ext.lower()
                if ext_lower in EXTENSION_LANGUAGE_MAP:
                    lang = EXTENSION_LANGUAGE_MAP[ext_lower]
                    self.languages[lang] = self.languages.get(lang, 0) + 1

        # 2. Determine Primary Language
        primary_lang = self._determine_primary_language()

        # 3. Targeted Inspection: C/C++ vs Python vs Rust
        self._inspect_codebase(primary_lang)

        # 4. Strict Capability Detection
        capabilities = self._detect_capabilities(primary_lang)

        # 5. Inferred Architecture
        architecture_style = self._infer_architecture(primary_lang, capabilities)

        # 6. Component Topology Graph
        dependency_graph = self._generate_topology_graph(primary_lang)

        return TargetProfile(
            target_path=self.target_path,
            files_count=len(self.files),
            languages=dict(sorted(self.languages.items(), key=lambda x: x[1], reverse=True)),
            primary_language=primary_lang,
            build_systems=sorted(list(self.build_systems)),
            key_files=sorted(list(self.key_files_found)),
            architecture_style=architecture_style,
            capabilities=capabilities,
            risk_findings=self.risk_findings,
            dependency_graph=dependency_graph
        )

    def _determine_primary_language(self) -> str:
        # Determine language distribution specifically across production files to avoid test-suite skew
        prod_languages: Dict[str, int] = {}
        for f in self.prod_files:
            _, ext = os.path.splitext(f)
            ext_lower = ext.lower()
            if ext_lower in EXTENSION_LANGUAGE_MAP:
                lang = EXTENSION_LANGUAGE_MAP[ext_lower]
                prod_languages[lang] = prod_languages.get(lang, 0) + 1

        code_langs = {k: v for k, v in prod_languages.items() if not k.endswith("Header") and not k.endswith("Stub")}
        # Aggregate headers and stubs with their primary language family
        for k, v in prod_languages.items():
            if k == "C/C++ Header":
                if "C++" in prod_languages:
                    code_langs["C++"] = code_langs.get("C++", 0) + v
                else:
                    code_langs["C"] = code_langs.get("C", 0) + v
            elif k == "Python Stub":
                code_langs["Python"] = code_langs.get("Python", 0) + v
        if not code_langs:
            # Fallback to general file list if no production code files detected
            code_langs = {k: v for k, v in self.languages.items() if not k.endswith("Header") and not k.endswith("Stub")}
        if not code_langs:
            return "C/C++" if any("C" in k for k in self.languages) else "Polyglot"
        return max(code_langs.items(), key=lambda x: x[1])[0]

    def _inspect_codebase(self, primary_lang: str) -> None:
        """Inspects source files for language-appropriate risk patterns and imports."""
        py_files = [f for f in self.prod_files if f.endswith(".py")]
        c_files = [f for f in self.prod_files if f.endswith((".c", ".cpp", ".cc"))]

        # Inspect Python files via AST where possible to avoid false method-eval positives
        import_re = re.compile(r'^\s*(?:import|from)\s+([a-zA-Z0-9_\.]+)')
        for py in py_files[:200]:  # Cap depth to preserve 0ms local responsiveness
            full_path = os.path.join(self.target_path, py)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as pf:
                    code = pf.read()
                    
                # Regex imports
                for line in code.splitlines():
                    m = import_re.match(line)
                    if m:
                        self.imports.add(m.group(1))

                # AST node checks
                try:
                    tree = ast.parse(code, filename=py)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            # Distinguish built-in eval from method eval (e.g. self.solver.eval)
                            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                                self.risk_findings.append({
                                    "file": py,
                                    "type": f"Dangerous Built-in Call ({node.func.id})",
                                    "detail": f"Direct call to builtins.{node.func.id}() at line {node.lineno}"
                                })
                except SyntaxError:
                    # Fallback to line scanning if syntax differs from running python
                    if "os.system(" in code or "subprocess.Popen(" in code:
                        self.risk_findings.append({
                            "file": py,
                            "type": "Command Execution",
                            "detail": "subprocess/os.system invocation"
                        })
            except Exception:
                pass

        # Inspect C files for standard boundary anti-patterns
        c_risk_patterns = [
            (re.compile(r'\bgets\s*\('), "Dangerous Function (gets)", "gets() is unconstrained against stack overflow"),
            (re.compile(r'\bstrcpy\s*\('), "Unbounded Copy (strcpy)", "strcpy() lacks explicit length bounds"),
            (re.compile(r'\bsystem\s*\('), "Command Execution (system)", "system() shell invocation"),
        ]
        for c in c_files[:200]:
            full_path = os.path.join(self.target_path, c)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as cf:
                    for lineno, line in enumerate(cf, 1):
                        for pat, rtype, detail in c_risk_patterns:
                            if pat.search(line):
                                self.risk_findings.append({
                                    "file": c,
                                    "type": rtype,
                                    "detail": f"{detail} at line {lineno}: {line.strip()[:80]}"
                                })
            except Exception:
                pass

    def _detect_capabilities(self, primary_lang: str) -> Dict[str, Dict[str, Any]]:
        """Strict capability detection with word-boundary regex and test exclusions."""
        prod_set = set(self.prod_files)

        # 1. Native CLI Capability
        has_native_cli = (
            any(f.startswith(("binr/", "bin/", "src/bin/")) for f in self.prod_files) or
            any(re.search(r'\b(main|radare2|rabin2|firejail|bcc|morayd|daemon)\.c$', f) for f in self.prod_files) or
            any(re.search(r'\b(cli|dashboard|console)\.py$', f) for f in self.prod_files)
        )

        # 2. Binary Disassembly & Reverse Engineering Capability
        disasm_indicators = ["libr/core", "libr/anal", "libr/asm", "libr/bin", "angr/analyses", "angr/engines"]
        has_disasm = any(any(ind in f for ind in disasm_indicators) for f in self.prod_files)

        # 3. Real Database Capability (Strict word boundaries, excluding .sdb, .pdb, gdb.md)
        db_regex = re.compile(r'(^|[\/\._])(database|sqlite3?|mariadb|postgres)(\.|\b)', re.I)
        has_real_db = (
            any(f.endswith((".db", ".sqlite", ".sqlite3")) and not f.endswith((".sdb", ".pdb")) for f in self.prod_files) or
            any(db_regex.search(f) for f in self.prod_files) or
            "sqlite3" in self.imports
        )

        # 4. Kernel / eBPF Tracing & LSM Containment
        has_bpf = (
            any(f.endswith(".bpf.c") for f in self.prod_files) or
            any(re.search(r'(^|[\/\._])(bpf|ebpf|xdp)(\.|\b)', f, re.I) for f in self.prod_files if f.endswith((".c", ".h", ".py"))) or
            "bpf" in self.imports
        )

        # 5. Sandboxing / Isolation (Strict boundary matching or BPF-LSM kernel containment)
        has_sandbox = (
            has_bpf or
            any(re.search(r'(^|[\/\._])(sandbox|jail|seccomp|quarantine|containment|lsm)(\.|\b)', f, re.IGNORECASE) for f in self.prod_files) or
            any("lsm" in f.lower() for f in self.prod_files)
        )

        # 6. Network API / Server
        has_network_server = any(re.search(r'(^|[\/\._])(http_server|mcp_server|rest_api)(\.|\b)', f, re.I) for f in self.prod_files)

        return {
            "native_cli": {
                "active": bool(has_native_cli),
                "description": "Exposes native CLI tools or terminal command interfaces."
            },
            "binary_analysis": {
                "active": bool(has_disasm),
                "description": "Performs binary analysis, disassembly, decompilation, or symbolic execution."
            },
            "kernel_ebpf": {
                "active": bool(has_bpf),
                "description": "Attaches eBPF programs or kernel tracepoints to trace subsystem events."
            },
            "sandbox": {
                "active": bool(has_sandbox),
                "description": "Enforces execution containment via seccomp, namespaces, or virtual memory limits."
            },
            "database": {
                "active": bool(has_real_db),
                "description": "Persists state to SQLite or relational database engines."
            },
            "network_server": {
                "active": bool(has_network_server),
                "description": "Listens for remote RPC, HTTP, or network socket transactions."
            }
        }

    def _infer_architecture(self, primary_lang: str, capabilities: Dict[str, Dict[str, Any]]) -> str:
        """Derives true systems architecture rather than projecting hardcoded agent identities."""
        if capabilities["binary_analysis"]["active"]:
            if primary_lang in ("C", "C++", "C/C++ Header"):
                return "Native Multi-Architecture Binary Analysis & Reverse Engineering Framework (C/C++)"
            elif primary_lang == "Python":
                return "Python Symbolic Execution & Program Analysis Engine"

        if capabilities["kernel_ebpf"]["active"]:
            if (capabilities.get("sandbox", {}).get("active") or
                any("lsm" in f.lower() for f in self.prod_files) or
                any("xdp" in f.lower() for f in self.prod_files)):
                return "Linux Ring 0 eBPF Containment & Security Subsystem (BPF-LSM / XDP)"
            return "Kernel Tracing & eBPF Observability Platform (C/Python)"

        if capabilities["sandbox"]["active"]:
            return "Process Isolation & Security Sandboxing Subsystem"

        if primary_lang in ("C", "C++"):
            return "Native Systems Software / Library Architecture"
        elif primary_lang == "Rust":
            return "Memory-Safe Systems Architecture (Rust)"
        elif primary_lang == "Python":
            return "Modular Python Architecture"
        else:
            return f"Polyglot Software System ({primary_lang})"

    def _generate_topology_graph(self, primary_lang: str) -> str:
        """Generates dynamic architecture Mermaid graph from actual directory modules."""
        top_dirs = set()
        for f in self.prod_files:
            parts = f.split(os.sep)
            if len(parts) > 1:
                top_dirs.add(parts[0])

        target_name = os.path.basename(self.target_path)
        lines = ["graph TD", f'    Target["{target_name} ({primary_lang})"]']
        
        for d in sorted(list(top_dirs))[:10]:
            lines.append(f'    Target --> Node_{d}["{d}/"]')

        return "\n".join(lines)
