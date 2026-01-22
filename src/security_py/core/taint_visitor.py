"""
Semantic Layer - AST-Based Taint Analysis

Uses Python's ast module to track data flow from Sources (input(), os.environ)
to Sinks (print(), subprocess.run(), api responses) for detecting sensitive
data exposure that evades pattern matching.
"""

import ast
from dataclasses import dataclass, field
from typing import Optional

from ..types.violations import (
    SemanticViolation,
    TaintedData,
    Severity,
    DataSourceType,
    DataSinkType,
    SemanticType,
    ScanContext,
)


@dataclass
class DataSource:
    """Represents a source of potentially sensitive data."""
    source_type: DataSourceType
    name: str
    line: int
    col: int
    sensitivity: Severity


@dataclass
class DataSink:
    """Represents a destination where data flows."""
    sink_type: DataSinkType
    line: int
    col: int
    context: str
    args: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class TaintRecord:
    """Internal record for tracking tainted variables."""
    variable: str
    source: DataSource
    taint_path: list[str] = field(default_factory=list)


class TaintVisitor(ast.NodeVisitor):
    """
    AST visitor that performs taint analysis on Python source code.
    
    Tracks data flow from sensitive sources (input, os.environ, hardcoded secrets)
    to dangerous sinks (print, subprocess, external APIs).
    
    Example usage:
        visitor = TaintVisitor()
        violations = visitor.analyze(source_code, context)
    """

    # Known sensitive sources
    SOURCE_FUNCTIONS: dict[str, DataSourceType] = {
        "input": DataSourceType.USER_INPUT,
        "raw_input": DataSourceType.USER_INPUT,
        "open": DataSourceType.FILE,
    }

    SOURCE_ATTRIBUTES: dict[tuple[str, str], DataSourceType] = {
        ("os", "environ"): DataSourceType.ENVIRONMENT,
        ("os", "getenv"): DataSourceType.ENVIRONMENT,
    }

    # Known sinks where sensitive data should not flow
    SINK_FUNCTIONS: dict[str, DataSinkType] = {
        "print": DataSinkType.CONSOLE,
        "logging.info": DataSinkType.LOG_FILE,
        "logging.debug": DataSinkType.LOG_FILE,
        "logging.warning": DataSinkType.LOG_FILE,
        "logging.error": DataSinkType.LOG_FILE,
    }

    SINK_ATTRIBUTES: dict[tuple[str, str], DataSinkType] = {
        ("subprocess", "run"): DataSinkType.SUBPROCESS,
        ("subprocess", "call"): DataSinkType.SUBPROCESS,
        ("subprocess", "Popen"): DataSinkType.SUBPROCESS,
        ("os", "system"): DataSinkType.SUBPROCESS,
        ("requests", "get"): DataSinkType.EXTERNAL_API,
        ("requests", "post"): DataSinkType.EXTERNAL_API,
        ("httpx", "get"): DataSinkType.EXTERNAL_API,
        ("httpx", "post"): DataSinkType.EXTERNAL_API,
    }

    # Patterns that suggest hardcoded secrets
    SECRET_PATTERNS: tuple[str, ...] = (
        "api_key", "apikey", "api-key",
        "secret", "password", "pwd", "passwd",
        "token", "auth_token", "access_token",
        "private_key", "credential", "credentials",
    )

    def __init__(self):
        self._sources: dict[str, DataSource] = {}
        self._sinks: list[DataSink] = []
        self._tainted: dict[str, TaintRecord] = {}
        self._current_file: str = ""
        self._context: Optional[ScanContext] = None

    def analyze(
        self,
        source_code: str,
        context: ScanContext,
        file_path: str = "<string>",
    ) -> list[SemanticViolation]:
        """
        Analyze Python source code for tainted data flows.
        
        Args:
            source_code: Python source code to analyze
            context: Scan context with metadata
            file_path: Path to the source file
            
        Returns:
            List of SemanticViolation objects for detected issues
        """
        # Reset state
        self._sources.clear()
        self._sinks.clear()
        self._tainted.clear()
        self._current_file = file_path
        self._context = context

        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError as e:
            return [
                SemanticViolation(
                    severity=Severity.LOW,
                    category="PARSE_ERROR",
                    title="Python syntax error",
                    description=f"Could not parse file: {e.msg}",
                    file=file_path,
                    line=e.lineno or 0,
                    code_snippet=str(e.text or "")[:80],
                    recommendation="Fix syntax errors before security analysis",
                    semantic_type=SemanticType.BUSINESS_LOGIC_RISK,
                )
            ]

        # Phase 1: Identify sources
        self.visit(tree)

        # Phase 2: Track assignments and data flow
        self._track_assignments(tree)

        # Phase 3: Find tainted flows to sinks
        return self._find_tainted_flows()

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls to identify sources and sinks."""
        func_name = self._get_call_name(node)

        # Check for source functions
        if func_name in self.SOURCE_FUNCTIONS:
            source = DataSource(
                source_type=self.SOURCE_FUNCTIONS[func_name],
                name=func_name,
                line=node.lineno,
                col=node.col_offset,
                sensitivity=Severity.HIGH if func_name == "input" else Severity.MEDIUM,
            )
            self._sources[f"call_{node.lineno}_{node.col_offset}"] = source

        # Check for source attributes (os.environ, os.getenv)
        if isinstance(node.func, ast.Attribute):
            attr_key = self._get_attribute_key(node.func)
            if attr_key in self.SOURCE_ATTRIBUTES:
                source = DataSource(
                    source_type=self.SOURCE_ATTRIBUTES[attr_key],
                    name=f"{attr_key[0]}.{attr_key[1]}",
                    line=node.lineno,
                    col=node.col_offset,
                    sensitivity=Severity.HIGH,
                )
                self._sources[f"attr_{node.lineno}_{node.col_offset}"] = source

        # Check for sink functions
        if func_name in self.SINK_FUNCTIONS:
            args = tuple(ast.unparse(arg) for arg in node.args)
            sink = DataSink(
                sink_type=self.SINK_FUNCTIONS[func_name],
                line=node.lineno,
                col=node.col_offset,
                context=ast.unparse(node)[:100],
                args=args,
            )
            self._sinks.append(sink)

        # Check for sink attributes
        if isinstance(node.func, ast.Attribute):
            attr_key = self._get_attribute_key(node.func)
            if attr_key in self.SINK_ATTRIBUTES:
                args = tuple(ast.unparse(arg) for arg in node.args)
                sink = DataSink(
                    sink_type=self.SINK_ATTRIBUTES[attr_key],
                    line=node.lineno,
                    col=node.col_offset,
                    context=ast.unparse(node)[:100],
                    args=args,
                )
                self._sinks.append(sink)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignments to detect hardcoded secrets and track taint."""
        # Check for hardcoded secrets
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    # Check if variable name suggests a secret
                    if any(pattern in var_name for pattern in self.SECRET_PATTERNS):
                        # Check if value looks like a secret (long alphanumeric)
                        if len(value) >= 10 and value.isalnum():
                            source = DataSource(
                                source_type=DataSourceType.HARDCODED,
                                name=target.id,
                                line=node.lineno,
                                col=node.col_offset,
                                sensitivity=Severity.CRITICAL,
                            )
                            self._sources[target.id] = source
                            self._tainted[target.id] = TaintRecord(
                                variable=target.id,
                                source=source,
                                taint_path=[target.id],
                            )
        
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Visit subscript access (e.g., os.environ['KEY'])."""
        if isinstance(node.value, ast.Attribute):
            attr_key = self._get_attribute_key(node.value)
            if attr_key == ("os", "environ"):
                key_name = ""
                if isinstance(node.slice, ast.Constant):
                    key_name = str(node.slice.value)
                source = DataSource(
                    source_type=DataSourceType.ENVIRONMENT,
                    name=f"os.environ[{key_name}]",
                    line=node.lineno,
                    col=node.col_offset,
                    sensitivity=self._determine_sensitivity(key_name),
                )
                self._sources[f"env_{node.lineno}_{key_name}"] = source

        self.generic_visit(node)

    def _track_assignments(self, tree: ast.AST) -> None:
        """Track variable assignments to propagate taint."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Check if RHS contains tainted variables
                        rhs_vars = self._extract_names(node.value)
                        for var in rhs_vars:
                            if var in self._tainted:
                                # Propagate taint
                                original = self._tainted[var]
                                self._tainted[target.id] = TaintRecord(
                                    variable=target.id,
                                    source=original.source,
                                    taint_path=[*original.taint_path, f"→ {target.id}"],
                                )

    def _find_tainted_flows(self) -> list[SemanticViolation]:
        """Find tainted data flows from sources to sinks."""
        violations: list[SemanticViolation] = []

        for sink in self._sinks:
            for arg in sink.args:
                # Check if any tainted variable appears in the sink argument
                for var_name, taint in self._tainted.items():
                    if var_name in arg:
                        tainted_data = TaintedData(
                            source_type=taint.source.source_type,
                            source_name=taint.source.name,
                            source_line=taint.source.line,
                            variable=var_name,
                            taint_path=tuple(taint.taint_path),
                            severity=self._calculate_severity(taint.source, sink),
                            data_type=self._determine_data_type(taint.source),
                        )

                        violation = SemanticViolation(
                            severity=tainted_data.severity,
                            category="SEMANTIC_TAINT",
                            title="Tainted Data Flow Detected",
                            description=(
                                f"Sensitive data from {taint.source.source_type.value.lower()} "
                                f"flows to {sink.sink_type.value.lower()} sink"
                            ),
                            file=self._current_file,
                            line=sink.line,
                            code_snippet=sink.context[:80],
                            recommendation=self._get_recommendation(taint.source, sink),
                            cwe_reference="CWE-200",
                            agent_source=self._context.agent_source if self._context else None,
                            taint_flow=(tainted_data,),
                            sink_type=sink.sink_type,
                            sink_line=sink.line,
                            semantic_type=SemanticType.TAINTED_DATA_FLOW,
                        )
                        violations.append(violation)

        # Also check for direct source usage in sinks
        for sink in self._sinks:
            for source_key, source in self._sources.items():
                if source.name in sink.context:
                    tainted_data = TaintedData(
                        source_type=source.source_type,
                        source_name=source.name,
                        source_line=source.line,
                        variable=source.name,
                        taint_path=(source.name, "→ direct_sink"),
                        severity=self._calculate_severity(source, sink),
                        data_type=self._determine_data_type(source),
                    )

                    violation = SemanticViolation(
                        severity=tainted_data.severity,
                        category="SEMANTIC_TAINT",
                        title="Direct Sensitive Data Exposure",
                        description=(
                            f"Sensitive data from {source.source_type.value.lower()} "
                            f"directly flows to {sink.sink_type.value.lower()}"
                        ),
                        file=self._current_file,
                        line=sink.line,
                        code_snippet=sink.context[:80],
                        recommendation=self._get_recommendation(source, sink),
                        cwe_reference="CWE-200",
                        agent_source=self._context.agent_source if self._context else None,
                        taint_flow=(tainted_data,),
                        sink_type=sink.sink_type,
                        sink_line=sink.line,
                        semantic_type=SemanticType.DATA_EXPOSURE,
                    )
                    violations.append(violation)

        return violations

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the name of a function being called."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        return ""

    def _get_attribute_key(self, node: ast.Attribute) -> tuple[str, str]:
        """Get (module, attr) tuple for an attribute access."""
        if isinstance(node.value, ast.Name):
            return (node.value.id, node.attr)
        return ("", node.attr)

    def _extract_names(self, node: ast.AST) -> list[str]:
        """Extract all Name identifiers from an AST node."""
        names = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.append(child.id)
        return names

    def _determine_sensitivity(self, var_name: str) -> Severity:
        """Determine sensitivity level based on variable name."""
        var_lower = var_name.lower()
        high_sensitivity = ("password", "secret", "key", "token", "api", "credential")
        medium_sensitivity = ("config", "database", "db", "host", "user")

        if any(pattern in var_lower for pattern in high_sensitivity):
            return Severity.HIGH
        if any(pattern in var_lower for pattern in medium_sensitivity):
            return Severity.MEDIUM
        return Severity.LOW

    def _calculate_severity(self, source: DataSource, sink: DataSink) -> Severity:
        """Calculate severity based on source sensitivity and sink type."""
        if source.sensitivity == Severity.CRITICAL:
            return Severity.CRITICAL
        if source.sensitivity == Severity.HIGH:
            if sink.sink_type in (DataSinkType.CONSOLE, DataSinkType.EXTERNAL_API):
                return Severity.CRITICAL
            return Severity.HIGH
        if source.sensitivity == Severity.MEDIUM:
            return Severity.MEDIUM
        return Severity.LOW

    def _determine_data_type(self, source: DataSource) -> str:
        """Determine data type from source."""
        if source.source_type in (DataSourceType.ENVIRONMENT, DataSourceType.HARDCODED):
            return "SECRET"
        if source.source_type == DataSourceType.DATABASE:
            return "PERSONAL_DATA"
        if source.source_type == DataSourceType.USER_INPUT:
            return "USER_INPUT"
        return "CONFIG"

    def _get_recommendation(self, source: DataSource, sink: DataSink) -> str:
        """Get a recommendation for fixing the tainted flow."""
        if sink.sink_type == DataSinkType.CONSOLE:
            return "Remove sensitive data from print() statements or mask the value"
        if sink.sink_type == DataSinkType.SUBPROCESS:
            return "Validate and sanitize data before passing to subprocess"
        if sink.sink_type == DataSinkType.EXTERNAL_API:
            return "Use secure headers/auth instead of embedding secrets in requests"
        if sink.sink_type == DataSinkType.LOG_FILE:
            return "Mask or redact sensitive data in log messages"
        return "Sanitize or remove sensitive data from this flow"
