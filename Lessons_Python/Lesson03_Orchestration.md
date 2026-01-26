# 🎓 Lesson 03: Orchestration - The SecurityValidator

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- How the SecurityValidator orchestrates all 5 layers
- The validation flow from file to result
- Exit behavior on CRITICAL violations

---

## 🧠 The 5-Layer Orchestrator

The `SecurityValidator` is the brain that coordinates all security layers:

```
┌─────────────────────────────────────────────────────────────────┐
│                     SecurityValidator                            │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ ScanEngine  │  │TaintVisitor │  │ ShellGuard  │              │
│  │ (Layer 1)   │  │ (Layer 2)   │  │ (Layer 3)   │              │
│  │ Patterns    │  │ AST Taint   │  │ Shell Ops   │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         └────────────────┼────────────────┘                      │
│                          ▼                                       │
│              ┌─────────────────────┐                            │
│              │    AI Auditor       │  ← Layer 4 (Optional)      │
│              │ LLM + Pydantic      │    Requires Ollama         │
│              └──────────┬──────────┘                            │
│                         ▼                                       │
│              ┌─────────────────────┐                            │
│              │    SOC Ledger       │  ← Layer 5 (Persistence)   │
│              │ SQLite + Provenance │    Audit Trail             │
│              └──────────┬──────────┘                            │
│                         ▼                                       │
│              ┌─────────────────────┐                            │
│              │ EnhancedValidation  │                            │
│              │      Result         │                            │
│              └──────────┬──────────┘                            │
│                         ▼                                       │
│              ┌─────────────────────┐                            │
│              │ sys.exit(1) if      │                            │
│              │ CRITICAL found      │                            │
│              └─────────────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

| Layer | Component | Purpose | Required? |
|-------|-----------|---------|-----------|
| 1 | ScanEngine | Pattern matching (OWASP LLM Top 10) | Yes |
| 2 | TaintVisitor | AST-based data flow tracking | Yes |
| 3 | ShellGuard | Shell command protection | Yes |
| 4 | AIAuditor | LLM reasoning with Pydantic guardrails | Optional |
| 5 | SOCLedger | SQLite audit trail with provenance chain | Yes |

---

## 🐍 SecurityValidator Implementation

```python
# Line 1: src/security_py/core/security_validator.py
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .scan_engine import ScanEngine
from .taint_visitor import TaintVisitor
from .shell_guard import ShellGuard
from ..types.violations import (
    SecurityViolation,
    SemanticViolation,
    OperationalViolation,
    Severity,
    ScanContext,
    ValidationResult,
)

# Line 20: Configuration dataclass
@dataclass
class ValidatorConfig:
    enable_deterministic: bool = True   # Layer 1
    enable_semantic: bool = True        # Layer 2
    enable_operational: bool = True     # Layer 3
    enable_ai_auditor: bool = False     # Layer 4 (requires Ollama)
    enable_persistence: bool = True     # Layer 5
    enforcement_mode: str = "STRICT"    # STRICT, ADVISORY, DISABLED
    exit_on_critical: bool = True       # sys.exit(1) on CRITICAL
    max_scan_duration_ms: int = 60000   # Timeout
    file_extensions: tuple[str, ...] = (".py",)
    agent_id: str = "security-validator"  # For SOC Ledger attribution
    db_path: str = "security_ledger.db"   # SQLite database path

# Line 31: Layer breakdown tracking
@dataclass
class LayerBreakdown:
    deterministic: int = 0
    semantic: int = 0
    operational: int = 0

    @property
    def total(self) -> int:
        return self.deterministic + self.semantic + self.operational
```

---

## 🔧 Validator Core

```python
# Line 1: The main validator class
class SecurityValidator:
    """
    5-Layer Hybrid Governance Validator for Python code.

    Layers 1-3: Core (deterministic, semantic, operational)
    Layer 4: AI Auditor (optional, requires Ollama)
    Layer 5: Persistence (SOC Ledger with provenance)

    Returns sys.exit(1) on any CRITICAL violation.
    """

    def __init__(self, config: Optional[ValidatorConfig] = None):
        self.config = config or ValidatorConfig()
        
        # Line 12: Initialize layers based on config
        self._scan_engine = ScanEngine() if self.config.enable_deterministic else None
        self._taint_visitor = TaintVisitor() if self.config.enable_semantic else None
        self._shell_guard = ShellGuard(
            enforcement_mode=self.config.enforcement_mode
        ) if self.config.enable_operational else None

    # Line 20: Main validation method
    def validate_content(
        self,
        content: str,
        context: ScanContext,
        file_path: str = "<string>",
    ) -> EnhancedValidationResult:
        """Validate Python source through all layers."""
        start_time = time.time()
        
        deterministic_violations: list[SecurityViolation] = []
        semantic_violations: list[SemanticViolation] = []
        operational_violations: list[OperationalViolation] = []

        # Line 34: Layer 1 - Deterministic Pattern Matching
        if self._scan_engine:
            print("🔍 Layer 1: Deterministic Pattern Matching")
            deterministic_violations = self._scan_engine.scan_content(
                content, file_path, context
            )
            print(f"   Found {len(deterministic_violations)} violations")

        # Line 42: Layer 2 - Semantic AST Analysis
        if self._taint_visitor:
            print("🧠 Layer 2: Semantic AST Analysis")
            semantic_violations = self._taint_visitor.analyze(
                content, context, file_path
            )
            print(f"   Found {len(semantic_violations)} violations")

        # Line 50: Layer 3 - Operational Guardrails
        if self._shell_guard:
            print("🔒 Layer 3: Operational Guardrails")
            operational_violations = self._scan_shell_commands(content, file_path)
            print(f"   Found {len(operational_violations)} violations")

        # Line 56: Combine all violations
        all_violations = [
            *deterministic_violations,
            *semantic_violations,
            *operational_violations,
        ]

        scan_duration_ms = (time.time() - start_time) * 1000
        
        # Line 65: Build result
        has_blocking = any(
            v.severity in (Severity.CRITICAL, Severity.HIGH) 
            for v in all_violations
        )
        
        result = EnhancedValidationResult(
            passed=len(all_violations) == 0,
            violations=all_violations,
            scan_duration_ms=scan_duration_ms,
            can_proceed=not has_blocking,
            requires_override=has_blocking,
            layer_breakdown=LayerBreakdown(
                deterministic=len(deterministic_violations),
                semantic=len(semantic_violations),
                operational=len(operational_violations),
            ),
        )

        # Line 82: Exit on CRITICAL if configured
        if self.config.exit_on_critical and result.has_critical:
            self._print_critical_report(result)
            sys.exit(1)

        return result
```

---

## 🚨 Critical Violation Handling

```python
# Line 1: When CRITICAL violations are found
def _print_critical_report(self, result: EnhancedValidationResult) -> None:
    """Print report and prepare for sys.exit(1)."""
    print("\n" + "=" * 60)
    print("🚨 CRITICAL SECURITY VIOLATIONS DETECTED")
    print("=" * 60)
    
    critical = [v for v in result.violations if v.severity == Severity.CRITICAL]
    
    for i, violation in enumerate(critical, 1):
        print(f"\n{i}. [{violation.severity.value}] {violation.title}")
        print(f"   File: {violation.file}:{violation.line}")
        print(f"   {violation.description}")
        print(f"   Code: {violation.code_snippet[:60]}...")
        print(f"   Fix: {violation.recommendation}")
    
    print("\n" + "=" * 60)
    print(f"Total: {len(critical)} CRITICAL violations")
    print("Exiting with code 1 - fix violations before proceeding")
    print("=" * 60 + "\n")

# Line 23: Example output:
# ============================================================
# 🚨 CRITICAL SECURITY VIOLATIONS DETECTED
# ============================================================
# 
# 1. [CRITICAL] LLM06: LLM06-001
#    File: src/config.py:15
#    Hardcoded sensitive information detected
#    Code: api_key = "sk-1234567890abcdef"...
#    Fix: Move sensitive data to environment variables
# 
# ============================================================
# Total: 1 CRITICAL violations
# Exiting with code 1 - fix violations before proceeding
# ============================================================
```

---

## 📁 File and Directory Validation

```python
# Line 1: Validate a single file
def validate_file(
    self,
    file_path: Path | str,
    context: Optional[ScanContext] = None,
) -> EnhancedValidationResult:
    """Validate a Python file through all security layers."""
    file_path = Path(file_path)
    
    # Line 10: Create default context if not provided
    if context is None:
        context = ScanContext(
            project_path=str(file_path.parent),
            phase="SCAN",
            developer_id="system",
            modified_files=[str(file_path)],
        )

    # Line 19: Read and validate
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return EnhancedValidationResult(
            passed=False,
            violations=[SecurityViolation(...)],
            scan_duration_ms=0,
            can_proceed=True,
            requires_override=False,
        )

    return self.validate_content(content, context, str(file_path))

# Line 33: Validate entire directory
def validate_directory(
    self,
    directory: Path | str,
    context: Optional[ScanContext] = None,
) -> EnhancedValidationResult:
    """Validate all Python files in a directory."""
    directory = Path(directory)
    
    all_violations = []
    file_count = 0
    
    # Line 45: Iterate through all Python files
    for file_path in directory.rglob("*.py"):
        if any(part in file_path.parts for part in 
               ("venv", ".venv", "__pycache__", ".git")):
            continue
        
        file_count += 1
        result = self.validate_file(file_path, context)
        all_violations.extend(result.violations)
    
    print(f"\n📊 Scanned {file_count} Python files")
    return EnhancedValidationResult(...)
```

---

## 📊 Security Score Calculation

```python
# Line 1: Calculate a 0-100 security score
def get_security_score(self, result: EnhancedValidationResult) -> int:
    """
    Calculate security score based on violations.
    
    Deductions:
    - CRITICAL: 25 points
    - HIGH: 15 points
    - MEDIUM: 10 points
    - LOW: 5 points
    """
    score = 100
    deductions = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 10,
        Severity.LOW: 5,
    }
    
    for violation in result.violations:
        score -= deductions.get(violation.severity, 0)
    
    return max(0, score)

# Line 25: Example scores:
# 0 violations: 100/100 ✅
# 1 CRITICAL: 75/100
# 2 CRITICAL: 50/100
# 4 CRITICAL: 0/100 (capped at 0)
```

---

## 🖥️ CLI Entry Point

```python
# Line 1: Command-line interface
def main():
    """CLI entry point for security validation."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Python Security Validator - 5-Layer Security Mesh"
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--no-exit", action="store_true",
                        help="Don't exit on CRITICAL violations")
    parser.add_argument("--mode", choices=["STRICT", "ADVISORY", "DISABLED"],
                        default="STRICT", help="Enforcement mode")
    
    args = parser.parse_args()
    
    # Line 17: Configure and run
    config = ValidatorConfig(
        exit_on_critical=not args.no_exit,
        enforcement_mode=args.mode,
    )
    
    validator = SecurityValidator(config)
    path = Path(args.path)
    
    if path.is_file():
        result = validator.validate_file(path)
    else:
        result = validator.validate_directory(path)
    
    print(validator.generate_report(result))
    
    if not result.passed:
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Usage Examples

```bash
# Line 1: Scan a single file
python -m security_py.core.security_validator app.py

# Line 4: Scan a directory
python -m security_py.core.security_validator src/

# Line 7: Advisory mode (warn but don't exit)
python -m security_py.core.security_validator --mode ADVISORY src/

# Line 10: Don't exit on critical
python -m security_py.core.security_validator --no-exit src/
```

---

## 🎯 Check for Understanding

**Question**: Why do we use `sys.exit(1)` for CRITICAL violations instead of raising an exception?

*Think about how this integrates with CI/CD pipelines...*

---

## 📚 Interview Prep

**Q: Why is the validator designed to exit with code 1 on CRITICAL?**

**A**: Exit codes are the standard way for CLI tools to communicate with:
1. **CI/CD pipelines**: GitHub Actions, GitLab CI check `$?` for pass/fail
2. **Shell scripts**: `if security_validator src/; then deploy; fi`
3. **Pre-commit hooks**: Git hooks expect non-zero on failure

```python
# Line 1: In CI/CD (e.g., GitHub Actions)
# - name: Security Scan
#   run: python -m security_py.core.security_validator src/
# If exit code != 0, the pipeline fails
```

**Q: How would you add a new security layer (e.g., dependency scanning)?**

**A**: Follow the existing pattern:
1. Create a new class with an `analyze()` method
2. Add it to `ValidatorConfig`
3. Initialize in `__init__` based on config
4. Call in `validate_content()` and combine results

```python
# Line 1: Example: Adding Layer 4 - Dependency Scanner
class DependencyScanner:
    def analyze(self, requirements_path: Path) -> list[DependencyViolation]:
        ...

# Line 6: In SecurityValidator.__init__:
self._dep_scanner = DependencyScanner() if self.config.enable_deps else None

# Line 9: In validate_content:
if self._dep_scanner:
    dep_violations = self._dep_scanner.analyze(...)
    all_violations.extend(dep_violations)
```

**Q: Why use `time.time()` for scan duration instead of `time.perf_counter()`?**

**A**: `time.perf_counter()` is actually preferred for measuring elapsed time:
- `time.time()` can jump due to system clock adjustments (NTP sync)
- `time.perf_counter()` is monotonic and higher resolution

```python
# Line 1: Better approach:
import time
start = time.perf_counter()
# ... do work ...
elapsed_ms = (time.perf_counter() - start) * 1000
```

---

## 🚀 Ready for Lesson 04?

In the next lesson, we'll explore **Audit Logging** - how we create immutable records of all security decisions.

*Remember: The validator is the gatekeeper - it must never fail silently!* 🛡️🐍
