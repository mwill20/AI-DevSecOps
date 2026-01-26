"""
Security Violation Data Structures - Python 3.12+ Native Implementation

Uses dataclasses and Enums for type-safe, immutable violation records.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Optional
import uuid


class Severity(Enum):
    """Violation severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ViolationStatus(Enum):
    """Violation lifecycle status."""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class DataSourceType(Enum):
    """Types of data sources for taint tracking."""
    ENVIRONMENT = "ENVIRONMENT"
    DATABASE = "DATABASE"
    FILE = "FILE"
    USER_INPUT = "USER_INPUT"
    HARDCODED = "HARDCODED"


class DataSinkType(Enum):
    """Types of data sinks for taint tracking."""
    CONSOLE = "CONSOLE"
    API_RESPONSE = "API_RESPONSE"
    LOG_FILE = "LOG_FILE"
    EXTERNAL_API = "EXTERNAL_API"
    DATABASE_WRITE = "DATABASE_WRITE"
    SUBPROCESS = "SUBPROCESS"


class OperationalRisk(Enum):
    """Operational risk categories."""
    SYSTEM_MODIFICATION = "SYSTEM_MODIFICATION"
    DATA_DESTRUCTION = "DATA_DESTRUCTION"
    SECURITY_BYPASS = "SECURITY_BYPASS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"


class SemanticType(Enum):
    """Semantic violation types."""
    TAINTED_DATA_FLOW = "TAINTED_DATA_FLOW"
    BUSINESS_LOGIC_RISK = "BUSINESS_LOGIC_RISK"
    DATA_EXPOSURE = "DATA_EXPOSURE"


@dataclass(frozen=True)
class SecurityViolation:
    """Base security violation record."""
    severity: Severity
    category: str
    title: str
    description: str
    file: str
    line: int
    code_snippet: str
    recommendation: str
    id: str = field(default_factory=lambda: f"v_{uuid.uuid4().hex[:12]}")
    cwe_reference: Optional[str] = None
    agent_source: Optional[str] = None
    status: ViolationStatus = ViolationStatus.OPEN
    discovered_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_reference": self.cwe_reference,
            "agent_source": self.agent_source,
            "status": self.status.value,
            "discovered_at": self.discovered_at.isoformat(),
        }


@dataclass(frozen=True)
class TaintedData:
    """Represents tainted data flow from source to sink."""
    source_type: DataSourceType
    source_name: str
    source_line: int
    variable: str
    taint_path: tuple[str, ...]
    severity: Severity
    data_type: str  # SECRET, PERSONAL_DATA, CONFIG, USER_INPUT


@dataclass(frozen=True)
class SemanticViolation(SecurityViolation):
    """Semantic-layer violation with taint flow information."""
    taint_flow: Optional[tuple[TaintedData, ...]] = None
    sink_type: Optional[DataSinkType] = None
    sink_line: Optional[int] = None
    semantic_type: SemanticType = SemanticType.TAINTED_DATA_FLOW


@dataclass(frozen=True)
class OperationalViolation(SecurityViolation):
    """Operational-layer violation for shell command issues."""
    command: str = ""
    args: tuple[str, ...] = field(default_factory=tuple)
    working_directory: str = ""
    operational_risk: OperationalRisk = OperationalRisk.SECURITY_BYPASS
    shell_context: str = ""


@dataclass(frozen=True)
class PolicyViolation(SecurityViolation):
    """Violation of an organizational policy (GRC compliance)."""
    policy_id: str = ""
    policy_name: str = ""
    compliance_framework: str = ""  # e.g., "PCI-DSS", "HIPAA", "GDPR"


@dataclass
class ScanContext:
    """Context for a security scan."""
    project_path: str
    phase: str
    developer_id: str
    modified_files: list[str] = field(default_factory=list)
    agent_source: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of a security validation scan."""
    passed: bool
    violations: list[SecurityViolation]
    scan_duration_ms: float
    can_proceed: bool
    requires_override: bool
    layer_breakdown: dict[str, int] = field(default_factory=dict)
    
    @property
    def has_critical(self) -> bool:
        """Check if any CRITICAL violations exist."""
        return any(v.severity == Severity.CRITICAL for v in self.violations)
    
    @property
    def total_violations(self) -> int:
        """Total number of violations."""
        return len(self.violations)
