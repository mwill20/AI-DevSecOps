"""
Security Standards Validator - Python 3.12+ Native Implementation

A 3-layer security mesh for AI-DevSecOps:
- Layer 1: Deterministic Pattern Matching (OWASP LLM patterns)
- Layer 2: Semantic AST Analysis (Taint tracking)
- Layer 3: Operational Guardrails (Shell command protection)

Returns sys.exit(1) on any CRITICAL violation.
"""

from .core.security_validator import SecurityValidator
from .core.scan_engine import ScanEngine, OWASP_LLM_PATTERNS
from .core.taint_visitor import TaintVisitor, TaintedData
from .core.shell_guard import ShellGuard
from .types.violations import (
    SecurityViolation,
    SemanticViolation,
    OperationalViolation,
    Severity,
    ViolationStatus,
)

__version__ = "2.0.0"
__all__ = [
    "SecurityValidator",
    "ScanEngine",
    "TaintVisitor",
    "TaintedData",
    "ShellGuard",
    "SecurityViolation",
    "SemanticViolation",
    "OperationalViolation",
    "Severity",
    "ViolationStatus",
    "OWASP_LLM_PATTERNS",
]
