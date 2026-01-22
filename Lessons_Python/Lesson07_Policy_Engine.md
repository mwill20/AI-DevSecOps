# 🎓 Lesson 07: Policy Engine - Business Rule Enforcement

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- How to enforce organizational policies through code
- Policy definition using Python dataclasses
- Combining AST analysis with policy rules

---

## ⚖️ What is a Policy Engine?

The Policy Engine enforces rules that go beyond security vulnerabilities:

```
┌─────────────────────────────────────────────────────┐
│  Policy Engine = "The Lawyer Layer"                 │
│                                                     │
│  • Forbidden library imports                        │
│  • Required code patterns                           │
│  • Compliance requirements (PCI-DSS, HIPAA, GDPR)   │
│  • Organizational coding standards                  │
└─────────────────────────────────────────────────────┘
```

---

## 🐍 Policy Definition

```python
# Line 1: src/security_py/core/policy_engine.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional
import ast
import re

class PolicyType(Enum):
    """Types of policy rules."""
    FORBIDDEN_IMPORT = "FORBIDDEN_IMPORT"
    REQUIRED_PATTERN = "REQUIRED_PATTERN"
    FORBIDDEN_PATTERN = "FORBIDDEN_PATTERN"
    AST_RULE = "AST_RULE"
    COMPLIANCE = "COMPLIANCE"

@dataclass(frozen=True)
class Policy:
    """Definition of a policy rule."""
    id: str
    name: str
    description: str
    policy_type: PolicyType
    severity: Severity
    pattern: Optional[str] = None          # Regex pattern
    forbidden_imports: tuple[str, ...] = field(default_factory=tuple)
    required_imports: tuple[str, ...] = field(default_factory=tuple)
    ast_check: Optional[Callable[[ast.AST], bool]] = None
    recommendation: str = ""
    compliance_framework: str = ""  # e.g., "PCI-DSS", "HIPAA"
```

---

## 📋 Policy Catalog

```python
# Line 1: Define organizational policies
ORGANIZATION_POLICIES: tuple[Policy, ...] = (
    # Forbidden Libraries
    Policy(
        id="POL-001",
        name="Forbidden Library: pickle",
        description="pickle module is forbidden due to code execution risk",
        policy_type=PolicyType.FORBIDDEN_IMPORT,
        severity=Severity.HIGH,
        forbidden_imports=("pickle", "cPickle"),
        recommendation="Use json or msgpack for serialization",
    ),
    Policy(
        id="POL-002",
        name="Forbidden Library: telnetlib",
        description="telnetlib is insecure, use SSH instead",
        policy_type=PolicyType.FORBIDDEN_IMPORT,
        severity=Severity.MEDIUM,
        forbidden_imports=("telnetlib",),
        recommendation="Use paramiko or fabric for remote connections",
    ),

    # Line 24: Required Patterns
    Policy(
        id="POL-010",
        name="Require Type Hints",
        description="All functions must have type hints",
        policy_type=PolicyType.AST_RULE,
        severity=Severity.LOW,
        ast_check=lambda node: _check_type_hints(node),
        recommendation="Add type hints: def func(x: int) -> str:",
    ),

    # Line 35: Compliance Rules
    Policy(
        id="POL-PCI-001",
        name="PCI-DSS: No Plaintext Card Numbers",
        description="Credit card numbers must not appear in code",
        policy_type=PolicyType.FORBIDDEN_PATTERN,
        severity=Severity.CRITICAL,
        pattern=r'\b(?:\d{4}[-\s]?){3}\d{4}\b',  # Card number pattern
        recommendation="Use tokenization for payment data",
        compliance_framework="PCI-DSS",
    ),
    Policy(
        id="POL-GDPR-001",
        name="GDPR: No Hardcoded PII",
        description="Personal identifiable information must not be hardcoded",
        policy_type=PolicyType.FORBIDDEN_PATTERN,
        severity=Severity.HIGH,
        pattern=r'(?:email|phone|ssn|address)\s*=\s*["\'][^"\']{5,}["\']',
        recommendation="Store PII in encrypted database, not in code",
        compliance_framework="GDPR",
    ),
)
```

---

## 🔧 Policy Engine Implementation

```python
# Line 1: Policy Engine class
class PolicyEngine:
    """
    Enforces organizational policies on Python code.
    
    Checks for:
    - Forbidden library imports
    - Required code patterns
    - Compliance requirements
    """

    def __init__(self, policies: tuple[Policy, ...] = ORGANIZATION_POLICIES):
        self._policies = policies

    def evaluate(
        self,
        source_code: str,
        context: ScanContext,
        file_path: str = "<string>",
    ) -> list[PolicyViolation]:
        """Evaluate all policies against source code."""
        violations: list[PolicyViolation] = []

        # Line 24: Parse AST for import and structure checks
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return violations  # Can't evaluate unparseable code

        # Line 30: Check each policy
        for policy in self._policies:
            if policy.policy_type == PolicyType.FORBIDDEN_IMPORT:
                violations.extend(
                    self._check_forbidden_imports(tree, policy, file_path)
                )
            elif policy.policy_type == PolicyType.FORBIDDEN_PATTERN:
                violations.extend(
                    self._check_forbidden_pattern(source_code, policy, file_path)
                )
            elif policy.policy_type == PolicyType.AST_RULE:
                violations.extend(
                    self._check_ast_rule(tree, policy, file_path)
                )

        return violations
```

---

## 🚫 Checking Forbidden Imports

```python
# Line 1: Check for forbidden library imports
def _check_forbidden_imports(
    self,
    tree: ast.AST,
    policy: Policy,
    file_path: str,
) -> list[PolicyViolation]:
    """Check for imports of forbidden libraries."""
    violations = []

    for node in ast.walk(tree):
        # Line 12: Check 'import foo' statements
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in policy.forbidden_imports:
                    violations.append(self._create_violation(
                        policy=policy,
                        file=file_path,
                        line=node.lineno,
                        code_snippet=f"import {alias.name}",
                    ))

        # Line 23: Check 'from foo import bar' statements
        if isinstance(node, ast.ImportFrom):
            if node.module in policy.forbidden_imports:
                violations.append(self._create_violation(
                    policy=policy,
                    file=file_path,
                    line=node.lineno,
                    code_snippet=f"from {node.module} import ...",
                ))

    return violations

# Line 34: Example:
# import pickle          # ❌ Forbidden!
# from pickle import load  # ❌ Also forbidden!
```

---

## 🔍 Checking Patterns

```python
# Line 1: Check for forbidden patterns (e.g., credit card numbers)
def _check_forbidden_pattern(
    self,
    source_code: str,
    policy: Policy,
    file_path: str,
) -> list[PolicyViolation]:
    """Check for forbidden regex patterns."""
    violations = []

    if not policy.pattern:
        return violations

    pattern = re.compile(policy.pattern, re.MULTILINE)
    lines = source_code.splitlines()

    for match in pattern.finditer(source_code):
        line_num = source_code[:match.start()].count('\n') + 1
        code_snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""

        violations.append(self._create_violation(
            policy=policy,
            file=file_path,
            line=line_num,
            code_snippet=code_snippet[:60],
        ))

    return violations

# Line 29: Example: PCI-DSS violation
# card_number = "4111-1111-1111-1111"  # ❌ Plaintext card number!
```

---

## 🌳 AST-Based Policy Rules

```python
# Line 1: Check AST-based policies (e.g., require type hints)
def _check_ast_rule(
    self,
    tree: ast.AST,
    policy: Policy,
    file_path: str,
) -> list[PolicyViolation]:
    """Check AST-based policy rules."""
    violations = []

    if not policy.ast_check:
        return violations

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if not policy.ast_check(node):
                violations.append(self._create_violation(
                    policy=policy,
                    file=file_path,
                    line=node.lineno,
                    code_snippet=f"def {node.name}(...):",
                ))

    return violations

# Line 26: Helper: Check if function has type hints
def _check_type_hints(node: ast.FunctionDef) -> bool:
    """Return True if function has return type annotation."""
    return node.returns is not None

# Line 31: Example:
# def process(data):      # ❌ Missing type hints
#     return data
#
# def process(data: dict) -> dict:  # ✅ Has type hints
#     return data
```

---

## 📊 Policy Violation Record

```python
# Line 1: Policy violation type
@dataclass(frozen=True)
class PolicyViolation(SecurityViolation):
    """Violation of an organizational policy."""
    policy_id: str = ""
    policy_name: str = ""
    compliance_framework: str = ""

# Line 10: Create violation from policy
def _create_violation(
    self,
    policy: Policy,
    file: str,
    line: int,
    code_snippet: str,
) -> PolicyViolation:
    return PolicyViolation(
        severity=policy.severity,
        category="POLICY",
        title=policy.name,
        description=policy.description,
        file=file,
        line=line,
        code_snippet=code_snippet,
        recommendation=policy.recommendation,
        policy_id=policy.id,
        policy_name=policy.name,
        compliance_framework=policy.compliance_framework,
    )
```

---

## 🎯 Complete Example

```python
# Line 1: Code to evaluate
code = '''
import pickle  # POL-001 violation
from telnetlib import Telnet  # POL-002 violation

card = "4111-1111-1111-1111"  # POL-PCI-001 violation

def process(data):  # POL-010 violation (no type hints)
    return pickle.loads(data)
'''

# Line 12: Evaluate policies
engine = PolicyEngine()
violations = engine.evaluate(code, context)

# Line 16: Output:
# [HIGH] POL-001: Forbidden Library: pickle
#   File: <string>:1
#   import pickle
#   Fix: Use json or msgpack for serialization
#
# [MEDIUM] POL-002: Forbidden Library: telnetlib
#   File: <string>:2
#   from telnetlib import Telnet
#   Fix: Use paramiko or fabric for remote connections
#
# [CRITICAL] POL-PCI-001: PCI-DSS: No Plaintext Card Numbers
#   File: <string>:4
#   card = "4111-1111-1111-1111"
#   Fix: Use tokenization for payment data
#   Compliance: PCI-DSS
```

---

## 🎯 Check for Understanding

**Question**: Why do we need a Policy Engine separate from pattern matching?

*Think about rules that aren't about security vulnerabilities but organizational requirements...*

---

## 📚 Interview Prep

**Q: How do you handle policy exceptions for legacy code?**

**A**: Use a policy exception mechanism:

```python
# Line 1: Policy exception configuration
@dataclass
class PolicyException:
    policy_id: str
    file_pattern: str  # Glob pattern
    reason: str
    approved_by: str
    expires: datetime

# Line 10: Check if file is exempt
def is_exempt(file_path: str, policy_id: str) -> bool:
    for exception in EXCEPTIONS:
        if exception.policy_id == policy_id:
            if fnmatch.fnmatch(file_path, exception.file_pattern):
                if exception.expires > datetime.now():
                    return True
    return False
```

**Q: How do you enforce policies in a CI/CD pipeline?**

**A**: Add a policy check step:

```yaml
# Line 1: GitHub Actions example
- name: Policy Check
  run: |
    python -m security_py.core.policy_engine src/
    exit $?  # Fail if violations found
```

**Q: What's the difference between security rules and policy rules?**

**A**:
- **Security rules**: Prevent exploitable vulnerabilities (eval, injection)
- **Policy rules**: Enforce organizational standards (approved libraries, coding style)

```python
# Line 1: Security rule - prevents exploitation
eval(user_input)  # Security violation: code execution

# Line 4: Policy rule - enforces organization standard
import requests  # Policy violation: use httpx instead
# Not exploitable, but against team standards
```

---

## 🚀 Ready for Lesson 08?

In the final lesson, we'll explore **Shell Operations** - how ShellGuard protects against command injection.

*Remember: Policies are the guardrails that keep AI (and humans) on the approved path!* 🛡️🐍
