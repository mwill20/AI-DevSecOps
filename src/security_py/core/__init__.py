"""Core security engine modules - Hybrid Governance Platform."""

from .scan_engine import ScanEngine, OWASP_LLM_PATTERNS, SecurityPattern
from .taint_visitor import TaintVisitor, TaintedData
from .shell_guard import ShellGuard
from .security_validator import SecurityValidator, ReviewStatus
from .debugger import (
    SecurityDebugger,
    DebugLevel,
    DebugReport,
    TaintTrace,
    ScanStep,
    explain_violation,
    create_debug_context,
)
from .ai_auditor import AIAuditor, LLMVulnerabilityResponse, AuditResult, AuditDecision
from .soc_ledger import SOCLedger, ScanRecord, ProvenanceRecord, SecurityLevel
from .observability import ObservabilityDashboard, PerformanceMetrics
from .policy_engine import PolicyEngine, Policy, PolicyType, PolicyException, ORGANIZATION_POLICIES

__all__ = [
    # Deterministic Layer
    "ScanEngine",
    "OWASP_LLM_PATTERNS",
    "SecurityPattern",
    # Semantic Layer
    "TaintVisitor",
    "TaintedData",
    # Operational Layer
    "ShellGuard",
    # Orchestration
    "SecurityValidator",
    "ReviewStatus",
    # AI Auditor Layer
    "AIAuditor",
    "LLMVulnerabilityResponse",
    "AuditResult",
    "AuditDecision",
    # Persistence Layer
    "SOCLedger",
    "ScanRecord",
    "ProvenanceRecord",
    "SecurityLevel",
    # Observability
    "ObservabilityDashboard",
    "PerformanceMetrics",
    # Debugging
    "SecurityDebugger",
    "DebugLevel",
    "DebugReport",
    "TaintTrace",
    "ScanStep",
    "explain_violation",
    "create_debug_context",
    # Policy Engine (GRC Compliance)
    "PolicyEngine",
    "Policy",
    "PolicyType",
    "PolicyException",
    "ORGANIZATION_POLICIES",
]
