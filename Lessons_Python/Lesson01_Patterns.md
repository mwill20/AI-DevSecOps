# 🎓 Lesson 01: OWASP LLM Patterns - Python Dataclasses

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- How OWASP LLM Top 10 patterns are implemented as Python dataclasses
- Why compiled regex patterns provide high-speed scanning
- How to add custom security patterns

---

## 🛡️ OWASP LLM Top 10 for AI Security

The OWASP LLM Top 10 defines the most critical security risks for AI applications:

| ID | Risk | Python Detection |
|----|------|-----------------|
| LLM01 | Prompt Injection | User input in prompts |
| LLM02 | Insecure Output | `eval()`, `exec()` |
| LLM06 | Sensitive Info Disclosure | Hardcoded secrets |

---

## 🐍 Pattern Definition with Dataclasses

We use frozen dataclasses for immutable, type-safe pattern definitions:

```python
# Line 1: src/security_py/core/scan_engine.py
import re
from dataclasses import dataclass
from enum import Enum

# Line 6: Severity levels as an Enum
class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

# Line 13: Pattern definition - frozen for immutability
@dataclass(frozen=True)
class SecurityPattern:
    id: str                    # Unique identifier (LLM06-001)
    category: str              # OWASP category (LLM06)
    severity: Severity         # Risk level
    pattern: re.Pattern        # Compiled regex
    description: str           # Human-readable explanation
    recommendation: str        # How to fix
    cwe_reference: str = ""    # CWE/CAPEC reference

    # Line 24: Factory method for compiled patterns
    @classmethod
    def compile(
        cls,
        id: str,
        category: str,
        severity: Severity,
        pattern: str,           # Raw regex string
        description: str,
        recommendation: str,
        cwe_reference: str = "",
        flags: int = re.IGNORECASE | re.MULTILINE,
    ) -> "SecurityPattern":
        return cls(
            id=id,
            category=category,
            severity=severity,
            pattern=re.compile(pattern, flags),  # Compile once!
            description=description,
            recommendation=recommendation,
            cwe_reference=cwe_reference,
        )
```

### Why Frozen Dataclasses?

```python
# Line 1: Frozen = immutable after creation
pattern = SecurityPattern.compile(...)

# Line 4: This will raise FrozenInstanceError
pattern.severity = Severity.LOW  # ❌ Cannot modify!

# Line 7: Benefits:
# - Thread-safe (no race conditions)
# - Hashable (can use in sets/dicts)
# - Self-documenting (clear intent)
```

---

## 📋 OWASP LLM Pattern Catalog

Here are the Python-specific patterns we detect:

### LLM01: Prompt Injection

```python
# Line 1: Pattern for unsanitized user input in prompts
SecurityPattern.compile(
    id="LLM01-001",
    category="LLM01",
    severity=Severity.HIGH,
    pattern=r'f["\'].*\{.*input\(\).*\}.*["\']',
    description="Unsanitized user input in f-string prompt",
    recommendation="Sanitize input() values before embedding in prompts",
    cwe_reference="CWE-74",
)

# Line 12: Example violation:
prompt = f"User says: {input()}"  # ❌ DETECTED!

# Line 15: Fixed version:
user_input = sanitize(input())
prompt = f"User says: {user_input}"  # ✅ Safe
```

### LLM06: Sensitive Information Disclosure

```python
# Line 1: Pattern for hardcoded API keys
SecurityPattern.compile(
    id="LLM06-001",
    category="LLM06",
    severity=Severity.CRITICAL,
    pattern=r'(?:api_key|secret|token|password)\s*=\s*["\'][a-zA-Z0-9_\-]{10,}["\']',
    description="Hardcoded sensitive information detected",
    recommendation="Move to environment variables using os.environ",
    cwe_reference="CWE-798",
)

# Line 12: Example violation:
api_key = "sk-1234567890abcdef"  # ❌ DETECTED!

# Line 15: Fixed version:
import os
api_key = os.environ.get("API_KEY")  # ✅ Safe
```

### LLM02: Insecure Output Handling

```python
# Line 1: Pattern for dangerous eval() usage
SecurityPattern.compile(
    id="LLM02-001",
    category="LLM02",
    severity=Severity.CRITICAL,
    pattern=r'eval\s*\([^)]+\)',
    description="Use of eval() - arbitrary code execution risk",
    recommendation="Replace with ast.literal_eval() or safer alternatives",
    cwe_reference="CWE-95",
)

# Line 12: Example violation:
result = eval(user_input)  # ❌ DETECTED!

# Line 15: Fixed version:
import ast
result = ast.literal_eval(user_input)  # ✅ Safe for literals only
```

---

## 🔧 Command Injection Patterns

```python
# Line 1: os.system() - always dangerous
SecurityPattern.compile(
    id="CMD-001",
    category="COMMAND_INJECTION",
    severity=Severity.CRITICAL,
    pattern=r'os\.system\s*\([^)]+\)',
    description="Use of os.system() - command injection risk",
    recommendation="Use subprocess.run() with shell=False",
    cwe_reference="CWE-78",
)

# Line 12: Example violation:
os.system(f"cat {filename}")  # ❌ DETECTED!

# Line 15: Fixed version:
import subprocess
subprocess.run(["cat", filename], shell=False)  # ✅ Safe
```

```python
# Line 1: subprocess with shell=True
SecurityPattern.compile(
    id="CMD-002",
    category="COMMAND_INJECTION",
    severity=Severity.CRITICAL,
    pattern=r'subprocess\.(?:run|call|Popen)\s*\([^)]*shell\s*=\s*True',
    description="Subprocess with shell=True - command injection risk",
    recommendation="Use shell=False with argument list",
    cwe_reference="CWE-78",
)

# Line 12: Example violation:
subprocess.run(f"cat {filename}", shell=True)  # ❌ DETECTED!

# Line 15: Fixed version:
subprocess.run(["cat", filename], shell=False)  # ✅ Safe
```

---

## 📦 Pattern Tuple for Performance

All patterns are stored in a tuple (immutable) for iteration:

```python
# Line 1: Tuple of all OWASP patterns
OWASP_LLM_PATTERNS: tuple[SecurityPattern, ...] = (
    # LLM01: Prompt Injection
    SecurityPattern.compile(
        id="LLM01-001",
        category="LLM01",
        severity=Severity.HIGH,
        pattern=r'f["\'].*\{.*input\(\).*\}',
        description="Unsanitized input in prompt",
        recommendation="Sanitize user input",
    ),
    # LLM06: Sensitive Info
    SecurityPattern.compile(
        id="LLM06-001",
        category="LLM06",
        severity=Severity.CRITICAL,
        pattern=r'(?:api_key|secret)\s*=\s*["\'][a-zA-Z0-9]{10,}["\']',
        description="Hardcoded secret",
        recommendation="Use environment variables",
    ),
    # ... more patterns
)

# Line 23: Why tuple instead of list?
# - Immutable: patterns can't be accidentally modified
# - Slightly faster iteration
# - Clear intent: "this collection is fixed"
```

---

## 🎯 Check for Understanding

**Question**: Why do we compile regex patterns at module load time instead of per-scan?

*Think about what `re.compile()` does and when you'd want to pay that cost...*

---

## 📚 Interview Prep

**Q: Why use `@dataclass(frozen=True)` for security patterns?**

**A**: Frozen dataclasses provide:
1. **Immutability**: Patterns can't be modified after creation
2. **Thread safety**: Safe to use in concurrent scans
3. **Hashability**: Can use patterns as dict keys or set members
4. **Self-documenting**: Clear that these are constants

```python
# Line 1: With frozen=True, this fails:
pattern.severity = Severity.LOW  # FrozenInstanceError

# Line 4: Without it, accidental mutation is possible:
pattern.severity = Severity.LOW  # ⚠️ Silently succeeds
```

**Q: What's the difference between `eval()` and `ast.literal_eval()`?**

**A**:
- `eval()` executes ANY Python expression - extremely dangerous
- `ast.literal_eval()` only evaluates literals (strings, numbers, lists, dicts)

```python
# Line 1: eval() is dangerous
eval("__import__('os').system('rm -rf /')")  # Executes!

# Line 4: ast.literal_eval() is safe
import ast
ast.literal_eval("__import__('os').system('rm -rf /')")
# Raises ValueError: malformed node or string
```

**Q: Why is `CWE-78` commonly referenced for command injection?**

**A**: CWE-78 is "Improper Neutralization of Special Elements used in an OS Command." It's the standard classification for command injection vulnerabilities. Reference it to:
1. Align with industry standards (NIST, OWASP)
2. Enable vulnerability tracking across tools
3. Provide remediation guidance via CWE database

---

## 🚀 Ready for Lesson 02?

In the next lesson, we'll see how the **ScanEngine** uses these patterns for high-speed scanning of Python source code.

*Remember: Patterns catch the obvious - semantic analysis catches the clever!* 🛡️🐍
