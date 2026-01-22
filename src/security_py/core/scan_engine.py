"""
Deterministic Layer - Pattern-Based Security Scanning

Uses OWASP LLM Top 10 patterns as Python dataclasses with compiled RegEx
for high-speed scanning of Python source code.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator

from ..types.violations import (
    SecurityViolation,
    Severity,
    ViolationStatus,
    ScanContext,
)


@dataclass(frozen=True)
class SecurityPattern:
    """OWASP LLM security pattern definition."""
    id: str
    category: str
    severity: Severity
    pattern: re.Pattern
    description: str
    recommendation: str
    cwe_reference: str = ""

    @classmethod
    def compile(
        cls,
        id: str,
        category: str,
        severity: Severity,
        pattern: str,
        description: str,
        recommendation: str,
        cwe_reference: str = "",
        flags: int = re.IGNORECASE | re.MULTILINE,
    ) -> "SecurityPattern":
        """Create a SecurityPattern with compiled regex."""
        return cls(
            id=id,
            category=category,
            severity=severity,
            pattern=re.compile(pattern, flags),
            description=description,
            recommendation=recommendation,
            cwe_reference=cwe_reference,
        )


# OWASP LLM Top 10 Patterns - Python-Focused
OWASP_LLM_PATTERNS: tuple[SecurityPattern, ...] = (
    # LLM01: Prompt Injection
    SecurityPattern.compile(
        id="LLM01-001",
        category="LLM01",
        severity=Severity.HIGH,
        pattern=r'(?:prompt|input|query)\s*=\s*["\'][^"\']*?(?:ignore|forget|disregard|system|admin|root)',
        description="Potential prompt injection vulnerability detected",
        recommendation="Validate and sanitize all user inputs before including in prompts",
        cwe_reference="CWE-74",
    ),
    SecurityPattern.compile(
        id="LLM01-002",
        category="LLM01",
        severity=Severity.HIGH,
        pattern=r'f["\'].*\{.*input\(\).*\}.*["\']',
        description="Unsanitized user input in f-string prompt",
        recommendation="Sanitize input() values before embedding in prompts",
        cwe_reference="CWE-74",
    ),
    # LLM06: Sensitive Information Disclosure
    SecurityPattern.compile(
        id="LLM06-001",
        category="LLM06",
        severity=Severity.CRITICAL,
        pattern=r'(?:api_key|apikey|secret|token|password|pwd)\s*=\s*["\'][a-zA-Z0-9_\-]{10,}["\']',
        description="Hardcoded sensitive information detected",
        recommendation="Move sensitive data to environment variables using os.environ",
        cwe_reference="CWE-798",
    ),
    SecurityPattern.compile(
        id="LLM06-002",
        category="LLM06",
        severity=Severity.CRITICAL,
        pattern=r'(?:sk-|pk_|sk_|AIza|ghp_|gho_|glpat-)[a-zA-Z0-9_\-]{20,}',
        description="Potential API key or token detected (OpenAI, Stripe, GitHub, Google, GitLab)",
        recommendation="Remove hardcoded credentials and use secure key management",
        cwe_reference="CWE-798",
    ),
    SecurityPattern.compile(
        id="LLM06-003",
        category="LLM06",
        severity=Severity.HIGH,
        pattern=r'print\s*\([^)]*(?:password|secret|token|key|credential)',
        description="Sensitive information logged to stdout via print()",
        recommendation="Remove sensitive data from print statements",
        cwe_reference="CWE-532",
    ),
    # LLM02: Insecure Output Handling
    SecurityPattern.compile(
        id="LLM02-001",
        category="LLM02",
        severity=Severity.CRITICAL,
        pattern=r'eval\s*\([^)]+\)',
        description="Use of eval() - arbitrary code execution risk",
        recommendation="Replace eval() with ast.literal_eval() or safer alternatives",
        cwe_reference="CWE-95",
    ),
    SecurityPattern.compile(
        id="LLM02-002",
        category="LLM02",
        severity=Severity.CRITICAL,
        pattern=r'exec\s*\([^)]+\)',
        description="Use of exec() - arbitrary code execution risk",
        recommendation="Avoid exec(); use structured data processing instead",
        cwe_reference="CWE-95",
    ),
    SecurityPattern.compile(
        id="LLM02-003",
        category="LLM02",
        severity=Severity.HIGH,
        pattern=r'__import__\s*\([^)]+\)',
        description="Dynamic import with __import__() - code injection risk",
        recommendation="Use importlib.import_module() with validated module names",
        cwe_reference="CWE-95",
    ),
    # Shell/Command Injection
    SecurityPattern.compile(
        id="CMD-001",
        category="COMMAND_INJECTION",
        severity=Severity.CRITICAL,
        pattern=r'os\.system\s*\([^)]+\)',
        description="Use of os.system() - command injection risk",
        recommendation="Use subprocess.run() with shell=False and argument list",
        cwe_reference="CWE-78",
    ),
    SecurityPattern.compile(
        id="CMD-002",
        category="COMMAND_INJECTION",
        severity=Severity.CRITICAL,
        pattern=r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True',
        description="Subprocess with shell=True - command injection risk",
        recommendation="Use shell=False with argument list instead",
        cwe_reference="CWE-78",
    ),
    SecurityPattern.compile(
        id="CMD-003",
        category="COMMAND_INJECTION",
        severity=Severity.HIGH,
        pattern=r'subprocess\.(?:call|run|Popen)\s*\(\s*f["\']',
        description="Subprocess with f-string - potential command injection",
        recommendation="Use argument list instead of string interpolation",
        cwe_reference="CWE-78",
    ),
    # Coding Standards
    SecurityPattern.compile(
        id="PY-001",
        category="CODING_STANDARDS",
        severity=Severity.MEDIUM,
        pattern=r'except\s*:\s*(?:pass|\.\.\.)',
        description="Bare except with pass - silent failure",
        recommendation="Log exceptions and handle specific exception types",
        cwe_reference="CWE-390",
    ),
    SecurityPattern.compile(
        id="PY-002",
        category="CODING_STANDARDS",
        severity=Severity.MEDIUM,
        pattern=r'pickle\.(?:load|loads)\s*\(',
        description="Pickle deserialization - arbitrary code execution risk",
        recommendation="Use JSON or other safe serialization formats",
        cwe_reference="CWE-502",
    ),
    SecurityPattern.compile(
        id="PY-003",
        category="CODING_STANDARDS",
        severity=Severity.HIGH,
        pattern=r'yaml\.(?:load|unsafe_load)\s*\([^)]*\)',
        description="Unsafe YAML loading - arbitrary code execution risk",
        recommendation="Use yaml.safe_load() instead",
        cwe_reference="CWE-502",
    ),
    # SQL Injection
    SecurityPattern.compile(
        id="SQL-001",
        category="SQL_INJECTION",
        severity=Severity.CRITICAL,
        pattern=r'(?:execute|cursor\.execute)\s*\(\s*f["\'].*(?:SELECT|INSERT|UPDATE|DELETE)',
        description="SQL query with f-string - SQL injection risk",
        recommendation="Use parameterized queries with ? or %s placeholders",
        cwe_reference="CWE-89",
    ),
    SecurityPattern.compile(
        id="SQL-002",
        category="SQL_INJECTION",
        severity=Severity.CRITICAL,
        pattern=r'(?:execute|cursor\.execute)\s*\([^)]*%\s*\(',
        description="SQL query with string formatting - SQL injection risk",
        recommendation="Use parameterized queries with ? or %s placeholders",
        cwe_reference="CWE-89",
    ),
)


class ScanEngine:
    """
    Deterministic Layer: High-speed pattern matching for Python source code.
    
    Uses compiled regex patterns from OWASP LLM Top 10 to detect
    security vulnerabilities in Python files.
    """

    def __init__(self, patterns: tuple[SecurityPattern, ...] = OWASP_LLM_PATTERNS):
        self._patterns = patterns

    @property
    def patterns(self) -> tuple[SecurityPattern, ...]:
        """Get all registered patterns."""
        return self._patterns

    def scan_content(
        self,
        content: str,
        file_path: str,
        context: ScanContext,
    ) -> list[SecurityViolation]:
        """
        Scan source code content for pattern matches.
        
        Args:
            content: Source code to scan
            file_path: Path to the file being scanned
            context: Scan context with metadata
            
        Returns:
            List of SecurityViolation objects for each match
        """
        violations: list[SecurityViolation] = []
        lines = content.splitlines()

        for pattern in self._patterns:
            for match in pattern.pattern.finditer(content):
                # Calculate line number from match position
                line_num = content[:match.start()].count('\n') + 1
                
                # Get the matched line as code snippet
                if 0 < line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group(0)[:80]

                violation = SecurityViolation(
                    severity=pattern.severity,
                    category=pattern.category,
                    title=f"{pattern.category}: {pattern.id}",
                    description=pattern.description,
                    file=file_path,
                    line=line_num,
                    code_snippet=code_snippet,
                    recommendation=pattern.recommendation,
                    cwe_reference=pattern.cwe_reference,
                    agent_source=context.agent_source,
                )
                violations.append(violation)

        return violations

    def scan_file(self, file_path: Path, context: ScanContext) -> list[SecurityViolation]:
        """
        Scan a single Python file for security violations.
        
        Args:
            file_path: Path to the Python file
            context: Scan context with metadata
            
        Returns:
            List of SecurityViolation objects
        """
        try:
            content = file_path.read_text(encoding="utf-8")
            return self.scan_content(content, str(file_path), context)
        except (OSError, UnicodeDecodeError) as e:
            # Return a violation indicating scan failure
            return [
                SecurityViolation(
                    severity=Severity.LOW,
                    category="SCAN_ERROR",
                    title="File scan failed",
                    description=f"Could not scan file: {e}",
                    file=str(file_path),
                    line=0,
                    code_snippet="",
                    recommendation="Check file encoding and permissions",
                )
            ]

    def scan_directory(
        self,
        directory: Path,
        context: ScanContext,
        extensions: tuple[str, ...] = (".py",),
    ) -> Iterator[SecurityViolation]:
        """
        Recursively scan a directory for Python files.
        
        Args:
            directory: Root directory to scan
            context: Scan context with metadata
            extensions: File extensions to include
            
        Yields:
            SecurityViolation objects as they are found
        """
        for file_path in directory.rglob("*"):
            if file_path.suffix in extensions and file_path.is_file():
                # Skip virtual environments and common non-source dirs
                if any(
                    part in file_path.parts
                    for part in ("venv", ".venv", "node_modules", "__pycache__", ".git")
                ):
                    continue
                
                for violation in self.scan_file(file_path, context):
                    yield violation

    def add_pattern(self, pattern: SecurityPattern) -> None:
        """Add a custom security pattern."""
        self._patterns = (*self._patterns, pattern)

    def remove_pattern(self, pattern_id: str) -> bool:
        """Remove a pattern by ID. Returns True if removed."""
        original_len = len(self._patterns)
        self._patterns = tuple(p for p in self._patterns if p.id != pattern_id)
        return len(self._patterns) < original_len
