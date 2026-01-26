"""
Policy Engine - Business Rule Enforcement for GRC Compliance

Enforces organizational policies that go beyond security vulnerabilities:
- Forbidden library imports (e.g., pickle, telnetlib)
- Required code patterns (e.g., type hints)
- Compliance requirements (PCI-DSS, HIPAA, GDPR)
- Organizational coding standards

This is separate from security scanning (Layer 1-3) because:
- Security rules prevent exploitation
- Policy rules enforce organizational standards
"""

import ast
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Optional
import fnmatch
import json

from ..types.violations import SecurityViolation, Severity, ScanContext


# =============================================================================
# POLICY TYPES
# =============================================================================

class PolicyType(Enum):
    """Types of policy rules."""
    FORBIDDEN_IMPORT = "FORBIDDEN_IMPORT"
    REQUIRED_PATTERN = "REQUIRED_PATTERN"
    FORBIDDEN_PATTERN = "FORBIDDEN_PATTERN"
    AST_RULE = "AST_RULE"
    COMPLIANCE = "COMPLIANCE"


# =============================================================================
# POLICY DEFINITION
# =============================================================================

@dataclass(frozen=True)
class Policy:
    """Definition of a policy rule."""
    id: str
    name: str
    description: str
    policy_type: PolicyType
    severity: Severity
    pattern: Optional[str] = None
    forbidden_imports: tuple[str, ...] = field(default_factory=tuple)
    required_imports: tuple[str, ...] = field(default_factory=tuple)
    ast_check: Optional[Callable[[ast.AST], bool]] = None
    recommendation: str = ""
    compliance_framework: str = ""  # e.g., "PCI-DSS", "HIPAA", "GDPR"


@dataclass(frozen=True)
class PolicyViolation(SecurityViolation):
    """Violation of an organizational policy."""
    policy_id: str = ""
    policy_name: str = ""
    compliance_framework: str = ""


@dataclass
class PolicyException:
    """Temporary exception for a policy rule."""
    policy_id: str
    file_pattern: str  # Glob pattern (e.g., "legacy/*.py")
    reason: str
    approved_by: str
    expires: datetime
    created_at: datetime = field(default_factory=datetime.now)


# =============================================================================
# AST HELPER FUNCTIONS
# =============================================================================

def _check_type_hints(node: ast.FunctionDef) -> bool:
    """Return True if function has return type annotation."""
    return node.returns is not None


def _check_docstring(node: ast.FunctionDef) -> bool:
    """Return True if function has a docstring."""
    if node.body and isinstance(node.body[0], ast.Expr):
        if isinstance(node.body[0].value, ast.Constant):
            return isinstance(node.body[0].value.value, str)
    return False


def _check_no_bare_except(node: ast.ExceptHandler) -> bool:
    """Return True if except clause has a specific exception type."""
    return node.type is not None


# =============================================================================
# DEFAULT POLICIES
# =============================================================================

ORGANIZATION_POLICIES: tuple[Policy, ...] = (
    # =========================================================================
    # FORBIDDEN LIBRARIES
    # =========================================================================
    Policy(
        id="POL-001",
        name="Forbidden Library: pickle",
        description="pickle module is forbidden due to arbitrary code execution risk",
        policy_type=PolicyType.FORBIDDEN_IMPORT,
        severity=Severity.HIGH,
        forbidden_imports=("pickle", "cPickle", "_pickle"),
        recommendation="Use json or msgpack for serialization",
    ),
    Policy(
        id="POL-002",
        name="Forbidden Library: telnetlib",
        description="telnetlib is insecure (unencrypted), use SSH instead",
        policy_type=PolicyType.FORBIDDEN_IMPORT,
        severity=Severity.MEDIUM,
        forbidden_imports=("telnetlib",),
        recommendation="Use paramiko or fabric for remote connections",
    ),
    Policy(
        id="POL-003",
        name="Forbidden Library: ftplib",
        description="FTP is insecure (unencrypted), use SFTP instead",
        policy_type=PolicyType.FORBIDDEN_IMPORT,
        severity=Severity.MEDIUM,
        forbidden_imports=("ftplib",),
        recommendation="Use paramiko for SFTP connections",
    ),

    # =========================================================================
    # COMPLIANCE RULES - PCI-DSS
    # =========================================================================
    Policy(
        id="POL-PCI-001",
        name="PCI-DSS: No Plaintext Card Numbers",
        description="Credit card numbers must not appear in code (PCI-DSS Requirement 3.4)",
        policy_type=PolicyType.FORBIDDEN_PATTERN,
        severity=Severity.CRITICAL,
        # Matches common card number formats (Visa, MC, Amex, Discover)
        pattern=r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        recommendation="Use tokenization for payment data, never store raw card numbers",
        compliance_framework="PCI-DSS",
    ),
    Policy(
        id="POL-PCI-002",
        name="PCI-DSS: No Plaintext CVV",
        description="CVV/CVC codes must never be stored (PCI-DSS Requirement 3.2)",
        policy_type=PolicyType.FORBIDDEN_PATTERN,
        severity=Severity.CRITICAL,
        pattern=r'(?:cvv|cvc|cvv2|cvc2|security_code)\s*=\s*["\']?\d{3,4}["\']?',
        recommendation="Never store CVV codes, even temporarily",
        compliance_framework="PCI-DSS",
    ),

    # =========================================================================
    # COMPLIANCE RULES - GDPR
    # =========================================================================
    Policy(
        id="POL-GDPR-001",
        name="GDPR: No Hardcoded PII",
        description="Personal identifiable information must not be hardcoded",
        policy_type=PolicyType.FORBIDDEN_PATTERN,
        severity=Severity.HIGH,
        pattern=r'(?:email|phone|ssn|social_security|address)\s*=\s*["\'][^"\']{5,}["\']',
        recommendation="Store PII in encrypted database, not in code",
        compliance_framework="GDPR",
    ),

    # =========================================================================
    # COMPLIANCE RULES - HIPAA
    # =========================================================================
    Policy(
        id="POL-HIPAA-001",
        name="HIPAA: No Hardcoded PHI",
        description="Protected health information must not be hardcoded",
        policy_type=PolicyType.FORBIDDEN_PATTERN,
        severity=Severity.CRITICAL,
        pattern=r'(?:patient_id|medical_record|diagnosis|prescription)\s*=\s*["\'][^"\']+["\']',
        recommendation="Store PHI in HIPAA-compliant encrypted storage",
        compliance_framework="HIPAA",
    ),

    # =========================================================================
    # CODE QUALITY RULES
    # =========================================================================
    Policy(
        id="POL-010",
        name="Require Type Hints on Functions",
        description="All functions should have return type annotations",
        policy_type=PolicyType.AST_RULE,
        severity=Severity.LOW,
        ast_check=_check_type_hints,
        recommendation="Add type hints: def func(x: int) -> str:",
    ),
    Policy(
        id="POL-011",
        name="No Bare Except Clauses",
        description="Except clauses must specify exception types",
        policy_type=PolicyType.AST_RULE,
        severity=Severity.MEDIUM,
        # Note: This needs special handling in the engine
        recommendation="Use specific exceptions: except ValueError: instead of except:",
    ),
)


# =============================================================================
# POLICY ENGINE
# =============================================================================

class PolicyEngine:
    """
    Enforces organizational policies on Python code.

    Checks for:
    - Forbidden library imports
    - Required code patterns
    - Compliance requirements (PCI-DSS, HIPAA, GDPR)
    - Code quality standards

    Usage:
        engine = PolicyEngine()
        violations = engine.evaluate(source_code, context)
    """

    def __init__(
        self,
        policies: tuple[Policy, ...] = ORGANIZATION_POLICIES,
        exceptions: Optional[list[PolicyException]] = None,
    ):
        self._policies = policies
        self._exceptions = exceptions or []
        # Pre-compile regex patterns for performance
        self._compiled_patterns: dict[str, re.Pattern] = {}
        for policy in policies:
            if policy.pattern:
                self._compiled_patterns[policy.id] = re.compile(
                    policy.pattern, re.IGNORECASE | re.MULTILINE
                )

    def add_exception(self, exception: PolicyException) -> None:
        """Add a policy exception."""
        self._exceptions.append(exception)

    def load_exceptions_from_file(self, path: Path) -> None:
        """Load policy exceptions from a JSON file."""
        if path.exists():
            data = json.loads(path.read_text())
            for exc in data.get("exceptions", []):
                self._exceptions.append(PolicyException(
                    policy_id=exc["policy_id"],
                    file_pattern=exc["file_pattern"],
                    reason=exc["reason"],
                    approved_by=exc["approved_by"],
                    expires=datetime.fromisoformat(exc["expires"]),
                ))

    def is_exempt(self, file_path: str, policy_id: str) -> bool:
        """Check if a file is exempt from a policy."""
        now = datetime.now()
        for exception in self._exceptions:
            if exception.policy_id == policy_id:
                if fnmatch.fnmatch(file_path, exception.file_pattern):
                    if exception.expires > now:
                        return True
        return False

    def evaluate(
        self,
        source_code: str,
        context: ScanContext,
        file_path: str = "<string>",
    ) -> list[PolicyViolation]:
        """Evaluate all policies against source code."""
        violations: list[PolicyViolation] = []

        # Parse AST for import and structure checks
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return violations  # Can't evaluate unparseable code

        # Check each policy
        for policy in self._policies:
            # Skip if file is exempt from this policy
            if self.is_exempt(file_path, policy.id):
                continue

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

    def _check_forbidden_imports(
        self,
        tree: ast.AST,
        policy: Policy,
        file_path: str,
    ) -> list[PolicyViolation]:
        """Check for imports of forbidden libraries."""
        violations = []

        for node in ast.walk(tree):
            # Check 'import foo' statements
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in policy.forbidden_imports:
                        violations.append(self._create_violation(
                            policy=policy,
                            file=file_path,
                            line=node.lineno,
                            code_snippet=f"import {alias.name}",
                        ))

            # Check 'from foo import bar' statements
            if isinstance(node, ast.ImportFrom):
                if node.module and node.module in policy.forbidden_imports:
                    names = ", ".join(a.name for a in node.names)
                    violations.append(self._create_violation(
                        policy=policy,
                        file=file_path,
                        line=node.lineno,
                        code_snippet=f"from {node.module} import {names}",
                    ))

        return violations

    def _check_forbidden_pattern(
        self,
        source_code: str,
        policy: Policy,
        file_path: str,
    ) -> list[PolicyViolation]:
        """Check for forbidden regex patterns."""
        violations = []

        if policy.id not in self._compiled_patterns:
            return violations

        pattern = self._compiled_patterns[policy.id]
        lines = source_code.splitlines()

        for match in pattern.finditer(source_code):
            line_num = source_code[:match.start()].count('\n') + 1
            code_snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""

            violations.append(self._create_violation(
                policy=policy,
                file=file_path,
                line=line_num,
                code_snippet=code_snippet[:60] + ("..." if len(code_snippet) > 60 else ""),
            ))

        return violations

    def _check_ast_rule(
        self,
        tree: ast.AST,
        policy: Policy,
        file_path: str,
    ) -> list[PolicyViolation]:
        """Check AST-based policy rules."""
        violations = []

        for node in ast.walk(tree):
            # Check functions for type hints/docstrings (POL-010)
            if isinstance(node, ast.FunctionDef) and policy.ast_check:
                # Skip private/dunder methods for type hint checks
                if policy.id == "POL-010" and node.name.startswith("_"):
                    continue
                if not policy.ast_check(node):
                    violations.append(self._create_violation(
                        policy=policy,
                        file=file_path,
                        line=node.lineno,
                        code_snippet=f"def {node.name}(...):",
                    ))

            # Check for bare except clauses (POL-011)
            if isinstance(node, ast.ExceptHandler) and policy.id == "POL-011":
                if not _check_no_bare_except(node):
                    violations.append(self._create_violation(
                        policy=policy,
                        file=file_path,
                        line=node.lineno,
                        code_snippet="except:",
                    ))

        return violations

    def _create_violation(
        self,
        policy: Policy,
        file: str,
        line: int,
        code_snippet: str,
    ) -> PolicyViolation:
        """Create a PolicyViolation from a policy match."""
        return PolicyViolation(
            severity=policy.severity,
            category="POLICY",
            title=policy.name,
            description=policy.description,
            file=file,
            line=line,
            code_snippet=code_snippet,
            recommendation=policy.recommendation,
            cwe_reference=None,
            policy_id=policy.id,
            policy_name=policy.name,
            compliance_framework=policy.compliance_framework,
        )

    def get_policies_by_framework(self, framework: str) -> list[Policy]:
        """Get all policies for a specific compliance framework."""
        return [p for p in self._policies if p.compliance_framework == framework]

    def generate_report(self, violations: list[PolicyViolation]) -> str:
        """Generate a human-readable policy violation report."""
        if not violations:
            return "✅ No policy violations found"

        lines = [
            "=" * 60,
            "📋 POLICY VIOLATION REPORT",
            "=" * 60,
            "",
        ]

        # Group by compliance framework
        by_framework: dict[str, list[PolicyViolation]] = {}
        for v in violations:
            framework = v.compliance_framework or "ORGANIZATIONAL"
            by_framework.setdefault(framework, []).append(v)

        for framework, framework_violations in by_framework.items():
            lines.append(f"\n### {framework} ###\n")
            for i, v in enumerate(framework_violations, 1):
                lines.extend([
                    f"{i}. [{v.severity.value}] {v.policy_id}: {v.policy_name}",
                    f"   File: {v.file}:{v.line}",
                    f"   Code: {v.code_snippet}",
                    f"   Fix: {v.recommendation}",
                    "",
                ])

        lines.extend([
            "=" * 60,
            f"Total: {len(violations)} policy violation(s)",
            "=" * 60,
        ])

        return "\n".join(lines)


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    """CLI entry point for policy evaluation."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Policy Engine - GRC Compliance Checker"
    )
    parser.add_argument("path", help="File or directory to evaluate")
    parser.add_argument(
        "--framework",
        choices=["PCI-DSS", "HIPAA", "GDPR", "ALL"],
        default="ALL",
        help="Compliance framework to check",
    )
    parser.add_argument(
        "--exceptions",
        help="Path to exceptions JSON file",
    )

    args = parser.parse_args()

    # Initialize engine
    engine = PolicyEngine()
    if args.exceptions:
        engine.load_exceptions_from_file(Path(args.exceptions))

    # Create context
    context = ScanContext(
        project_path=str(Path(args.path).parent),
        phase="POLICY_CHECK",
        developer_id="cli-user",
    )

    path = Path(args.path)
    all_violations: list[PolicyViolation] = []

    # Scan file or directory
    if path.is_file():
        files = [path]
    else:
        files = list(path.rglob("*.py"))
        files = [f for f in files if not any(
            part in f.parts for part in ("venv", ".venv", "__pycache__", ".git")
        )]

    for file_path in files:
        try:
            content = file_path.read_text(encoding="utf-8")
            violations = engine.evaluate(content, context, str(file_path))

            # Filter by framework if specified
            if args.framework != "ALL":
                violations = [
                    v for v in violations
                    if v.compliance_framework == args.framework
                ]

            all_violations.extend(violations)
        except Exception as e:
            print(f"Error scanning {file_path}: {e}", file=sys.stderr)

    # Print report
    print(engine.generate_report(all_violations))

    # Exit with error if critical violations found
    if any(v.severity == Severity.CRITICAL for v in all_violations):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
