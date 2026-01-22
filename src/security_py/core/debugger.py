"""
Security Validator Debugger - Comprehensive Debugging Utilities

Provides detailed debugging information for:
- Scan pipeline visualization
- Taint flow tracing
- Pattern match inspection
- Performance profiling
- Error diagnosis

Designed for new developers learning the security validator internals.
"""

import ast
import json
import logging
import sys
import time
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Any
from contextlib import contextmanager

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree
from rich.traceback import install as install_rich_traceback

from ..types.violations import (
    SecurityViolation,
    SemanticViolation,
    Severity,
    ScanContext,
)


# =============================================================================
# DEBUG LEVELS
# =============================================================================

class DebugLevel(str, Enum):
    """Debug verbosity levels."""
    OFF = "OFF"           # No debug output
    MINIMAL = "MINIMAL"   # Errors only
    NORMAL = "NORMAL"     # Errors + warnings + summary
    VERBOSE = "VERBOSE"   # All above + detailed traces
    TRACE = "TRACE"       # Everything including internal state


# =============================================================================
# DEBUG DATA STRUCTURES
# =============================================================================

@dataclass
class ScanStep:
    """Represents a single step in the scan pipeline."""
    step_number: int
    layer_name: str
    description: str
    start_time: float
    end_time: float = 0.0
    violations_found: int = 0
    details: dict = field(default_factory=dict)
    error: Optional[str] = None
    
    @property
    def duration_ms(self) -> float:
        return (self.end_time - self.start_time) * 1000
    
    @property
    def success(self) -> bool:
        return self.error is None


@dataclass
class TaintTrace:
    """Traces a single taint flow through code."""
    source_var: str
    source_line: int
    source_type: str
    hops: list[dict] = field(default_factory=list)
    sink_var: Optional[str] = None
    sink_line: Optional[int] = None
    sink_type: Optional[str] = None
    is_violation: bool = False
    
    def add_hop(self, var: str, line: int, operation: str):
        """Add a hop in the taint propagation chain."""
        self.hops.append({
            "var": var,
            "line": line,
            "operation": operation,
            "hop_number": len(self.hops) + 1,
        })


@dataclass
class PatternMatchDebug:
    """Debug info for a single pattern match."""
    pattern_id: str
    pattern_regex: str
    matched: bool
    match_text: Optional[str] = None
    match_line: Optional[int] = None
    match_col: Optional[int] = None
    scan_time_ms: float = 0.0


@dataclass
class DebugReport:
    """Complete debug report for a scan."""
    scan_id: str
    timestamp: str
    file_path: str
    total_duration_ms: float
    steps: list[ScanStep] = field(default_factory=list)
    taint_traces: list[TaintTrace] = field(default_factory=list)
    pattern_matches: list[PatternMatchDebug] = field(default_factory=list)
    violations: list[SecurityViolation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    memory_usage_mb: float = 0.0
    ast_node_count: int = 0
    lines_scanned: int = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON export."""
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "file_path": self.file_path,
            "total_duration_ms": self.total_duration_ms,
            "steps": [asdict(s) for s in self.steps],
            "taint_traces": [asdict(t) for t in self.taint_traces],
            "pattern_matches": [asdict(p) for p in self.pattern_matches],
            "violations_count": len(self.violations),
            "errors": self.errors,
            "warnings": self.warnings,
            "memory_usage_mb": self.memory_usage_mb,
            "ast_node_count": self.ast_node_count,
            "lines_scanned": self.lines_scanned,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Export as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


# =============================================================================
# MAIN DEBUGGER CLASS
# =============================================================================

class SecurityDebugger:
    """
    Comprehensive debugger for the Security Validator.
    
    This class helps you understand:
    - What the validator is doing at each step
    - How taint flows through your code
    - Why patterns matched (or didn't match)
    - Where performance bottlenecks are
    - What errors occurred and why
    
    Example usage:
        debugger = SecurityDebugger(level=DebugLevel.VERBOSE)
        debugger.start_scan("app.py")
        
        # ... run your scan ...
        
        debugger.end_scan()
        debugger.print_report()
    """
    
    def __init__(
        self,
        level: DebugLevel = DebugLevel.NORMAL,
        output_file: Optional[str] = None,
        colorize: bool = True,
    ):
        self.level = level
        self.output_file = output_file
        self._console = Console(force_terminal=colorize)
        self._current_report: Optional[DebugReport] = None
        self._step_counter = 0
        self._scan_start_time = 0.0
        
        # Install rich traceback for better error display
        if level in (DebugLevel.VERBOSE, DebugLevel.TRACE):
            install_rich_traceback(show_locals=True)
        
        # Setup logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure logging based on debug level."""
        log_level = {
            DebugLevel.OFF: logging.CRITICAL,
            DebugLevel.MINIMAL: logging.ERROR,
            DebugLevel.NORMAL: logging.WARNING,
            DebugLevel.VERBOSE: logging.INFO,
            DebugLevel.TRACE: logging.DEBUG,
        }.get(self.level, logging.WARNING)
        
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        )
        self._logger = logging.getLogger("security_debugger")
    
    # =========================================================================
    # SCAN LIFECYCLE
    # =========================================================================
    
    def start_scan(self, file_path: str) -> None:
        """Start a new debug session for a scan."""
        self._scan_start_time = time.time()
        self._step_counter = 0
        
        self._current_report = DebugReport(
            scan_id=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            file_path=file_path,
            total_duration_ms=0.0,
        )
        
        if self.level != DebugLevel.OFF:
            self._console.print(Panel(
                f"[bold blue]🔍 DEBUG SCAN STARTED[/bold blue]\n"
                f"File: {file_path}\n"
                f"Level: {self.level.value}\n"
                f"Time: {self._current_report.timestamp}",
                title="Debug Session",
                border_style="blue"
            ))
    
    def end_scan(self) -> DebugReport:
        """End the debug session and finalize the report."""
        if self._current_report:
            self._current_report.total_duration_ms = (
                time.time() - self._scan_start_time
            ) * 1000
        
        if self.output_file and self._current_report:
            self._save_report()
        
        return self._current_report
    
    def _save_report(self):
        """Save debug report to file."""
        if self._current_report:
            output_path = Path(self.output_file)
            output_path.write_text(self._current_report.to_json())
            self._logger.info(f"Debug report saved to {output_path}")
    
    # =========================================================================
    # STEP TRACKING
    # =========================================================================
    
    @contextmanager
    def track_step(self, layer_name: str, description: str):
        """
        Context manager to track a scan step.
        
        Usage:
            with debugger.track_step("Layer 1", "Pattern Matching"):
                # ... do pattern matching ...
        """
        self._step_counter += 1
        step = ScanStep(
            step_number=self._step_counter,
            layer_name=layer_name,
            description=description,
            start_time=time.time(),
        )
        
        if self.level in (DebugLevel.VERBOSE, DebugLevel.TRACE):
            self._console.print(f"[cyan]→ Step {step.step_number}: {layer_name} - {description}[/cyan]")
        
        try:
            yield step
            step.end_time = time.time()
            
            if self.level == DebugLevel.TRACE:
                self._console.print(
                    f"  [green]✓ Completed in {step.duration_ms:.2f}ms "
                    f"({step.violations_found} violations)[/green]"
                )
        except Exception as e:
            step.end_time = time.time()
            step.error = str(e)
            self._logger.error(f"Step {step.step_number} failed: {e}")
            if self.level in (DebugLevel.VERBOSE, DebugLevel.TRACE):
                self._console.print_exception()
            raise
        finally:
            if self._current_report:
                self._current_report.steps.append(step)
    
    # =========================================================================
    # TAINT TRACING
    # =========================================================================
    
    def trace_taint_source(
        self,
        var: str,
        line: int,
        source_type: str,
    ) -> TaintTrace:
        """
        Start tracing a taint from its source.
        
        A "taint" is sensitive data that we want to track through the code.
        
        Example:
            # When we see: api_key = os.environ.get("API_KEY")
            trace = debugger.trace_taint_source("api_key", 5, "ENVIRONMENT")
        """
        trace = TaintTrace(
            source_var=var,
            source_line=line,
            source_type=source_type,
        )
        
        if self.level == DebugLevel.TRACE:
            self._console.print(
                f"  [yellow]🔶 Taint source: {var} at line {line} "
                f"(type: {source_type})[/yellow]"
            )
        
        return trace
    
    def trace_taint_hop(self, trace: TaintTrace, var: str, line: int, op: str):
        """
        Record a hop in the taint propagation.
        
        A "hop" is when tainted data moves to a new variable.
        
        Example:
            # When we see: temp = api_key
            debugger.trace_taint_hop(trace, "temp", 6, "assignment")
        """
        trace.add_hop(var, line, op)
        
        if self.level == DebugLevel.TRACE:
            self._console.print(
                f"    [dim]↓ Hop {len(trace.hops)}: {var} at line {line} ({op})[/dim]"
            )
    
    def trace_taint_sink(
        self,
        trace: TaintTrace,
        var: str,
        line: int,
        sink_type: str,
        is_violation: bool = True,
    ):
        """
        Record when tainted data reaches a sink.
        
        A "sink" is a dangerous operation like print() or subprocess.run().
        
        Example:
            # When we see: print(temp)
            debugger.trace_taint_sink(trace, "temp", 10, "CONSOLE", is_violation=True)
        """
        trace.sink_var = var
        trace.sink_line = line
        trace.sink_type = sink_type
        trace.is_violation = is_violation
        
        if self._current_report:
            self._current_report.taint_traces.append(trace)
        
        if self.level in (DebugLevel.VERBOSE, DebugLevel.TRACE):
            status = "[red]🚨 VIOLATION[/red]" if is_violation else "[green]✓ OK[/green]"
            self._console.print(
                f"    [yellow]↓ Sink: {var} at line {line} "
                f"(type: {sink_type}) {status}[/yellow]"
            )
    
    # =========================================================================
    # PATTERN MATCH DEBUGGING
    # =========================================================================
    
    def debug_pattern_match(
        self,
        pattern_id: str,
        pattern_regex: str,
        content: str,
        matched: bool,
        match_text: Optional[str] = None,
        match_line: Optional[int] = None,
        scan_time_ms: float = 0.0,
    ):
        """
        Record debug info for a pattern match attempt.
        
        Example:
            debugger.debug_pattern_match(
                pattern_id="LLM06-001",
                pattern_regex=r"sk-[a-zA-Z0-9]{20,}",
                content=code,
                matched=True,
                match_text="sk-abc123...",
                match_line=5,
            )
        """
        debug_info = PatternMatchDebug(
            pattern_id=pattern_id,
            pattern_regex=pattern_regex,
            matched=matched,
            match_text=match_text,
            match_line=match_line,
            scan_time_ms=scan_time_ms,
        )
        
        if self._current_report:
            self._current_report.pattern_matches.append(debug_info)
        
        if self.level == DebugLevel.TRACE:
            status = "[red]MATCHED[/red]" if matched else "[dim]no match[/dim]"
            self._console.print(
                f"    Pattern {pattern_id}: {status}"
                + (f" at line {match_line}" if match_line else "")
            )
    
    # =========================================================================
    # ERROR AND WARNING LOGGING
    # =========================================================================
    
    def log_error(self, message: str, exception: Optional[Exception] = None):
        """Log an error with optional exception details."""
        if self._current_report:
            self._current_report.errors.append(message)
        
        self._logger.error(message)
        
        if self.level in (DebugLevel.VERBOSE, DebugLevel.TRACE) and exception:
            self._console.print(f"[red]ERROR: {message}[/red]")
            self._console.print_exception()
    
    def log_warning(self, message: str):
        """Log a warning."""
        if self._current_report:
            self._current_report.warnings.append(message)
        
        self._logger.warning(message)
        
        if self.level in (DebugLevel.NORMAL, DebugLevel.VERBOSE, DebugLevel.TRACE):
            self._console.print(f"[yellow]WARNING: {message}[/yellow]")
    
    def log_info(self, message: str):
        """Log an informational message."""
        self._logger.info(message)
        
        if self.level in (DebugLevel.VERBOSE, DebugLevel.TRACE):
            self._console.print(f"[blue]INFO: {message}[/blue]")
    
    def log_trace(self, message: str):
        """Log a trace-level message (very verbose)."""
        self._logger.debug(message)
        
        if self.level == DebugLevel.TRACE:
            self._console.print(f"[dim]TRACE: {message}[/dim]")
    
    # =========================================================================
    # AST DEBUGGING
    # =========================================================================
    
    def debug_ast(self, code: str, highlight_lines: Optional[list[int]] = None):
        """
        Display the AST structure of code for debugging.
        
        This helps you understand how Python sees your code internally.
        """
        if self.level not in (DebugLevel.VERBOSE, DebugLevel.TRACE):
            return
        
        try:
            tree = ast.parse(code)
            
            if self._current_report:
                self._current_report.ast_node_count = sum(
                    1 for _ in ast.walk(tree)
                )
            
            self._console.print("\n[bold]AST Structure:[/bold]")
            self._print_ast_tree(tree)
            
        except SyntaxError as e:
            self.log_error(f"Failed to parse AST: {e}", e)
    
    def _print_ast_tree(self, node: ast.AST, prefix: str = ""):
        """Recursively print AST tree structure."""
        node_name = node.__class__.__name__
        
        # Get relevant node attributes
        attrs = []
        if hasattr(node, 'name'):
            attrs.append(f"name={node.name}")
        if hasattr(node, 'id'):
            attrs.append(f"id={node.id}")
        if hasattr(node, 'lineno'):
            attrs.append(f"line={node.lineno}")
        
        attr_str = f" ({', '.join(attrs)})" if attrs else ""
        self._console.print(f"{prefix}├─ {node_name}{attr_str}")
        
        for child in ast.iter_child_nodes(node):
            self._print_ast_tree(child, prefix + "│  ")
    
    # =========================================================================
    # REPORT DISPLAY
    # =========================================================================
    
    def print_report(self):
        """Print a formatted debug report."""
        if not self._current_report:
            self._console.print("[yellow]No debug report available[/yellow]")
            return
        
        report = self._current_report
        
        # Header
        self._console.print("\n")
        self._console.print(Panel(
            f"[bold]Scan ID:[/bold] {report.scan_id}\n"
            f"[bold]File:[/bold] {report.file_path}\n"
            f"[bold]Duration:[/bold] {report.total_duration_ms:.2f}ms\n"
            f"[bold]AST Nodes:[/bold] {report.ast_node_count}\n"
            f"[bold]Lines Scanned:[/bold] {report.lines_scanned}",
            title="🔍 DEBUG REPORT",
            border_style="blue"
        ))
        
        # Steps table
        if report.steps:
            self._print_steps_table(report.steps)
        
        # Taint traces
        if report.taint_traces:
            self._print_taint_traces(report.taint_traces)
        
        # Pattern matches
        if report.pattern_matches and self.level == DebugLevel.TRACE:
            self._print_pattern_matches(report.pattern_matches)
        
        # Errors and warnings
        if report.errors:
            self._console.print("\n[bold red]❌ ERRORS:[/bold red]")
            for error in report.errors:
                self._console.print(f"  • {error}")
        
        if report.warnings:
            self._console.print("\n[bold yellow]⚠️ WARNINGS:[/bold yellow]")
            for warning in report.warnings:
                self._console.print(f"  • {warning}")
        
        # Summary
        self._print_summary(report)
    
    def _print_steps_table(self, steps: list[ScanStep]):
        """Print steps as a table."""
        table = Table(title="📋 Scan Steps")
        table.add_column("#", style="dim", width=4)
        table.add_column("Layer", style="cyan")
        table.add_column("Description")
        table.add_column("Duration", justify="right")
        table.add_column("Violations", justify="right")
        table.add_column("Status", justify="center")
        
        for step in steps:
            status = "✅" if step.success else "❌"
            table.add_row(
                str(step.step_number),
                step.layer_name,
                step.description,
                f"{step.duration_ms:.2f}ms",
                str(step.violations_found),
                status,
            )
        
        self._console.print("\n")
        self._console.print(table)
    
    def _print_taint_traces(self, traces: list[TaintTrace]):
        """Print taint traces as a tree."""
        self._console.print("\n[bold]🔗 Taint Traces:[/bold]")
        
        for i, trace in enumerate(traces, 1):
            status = "[red]VIOLATION[/red]" if trace.is_violation else "[green]OK[/green]"
            tree = Tree(f"[bold]Trace {i}[/bold] {status}")
            
            # Source
            tree.add(f"[yellow]SOURCE:[/yellow] {trace.source_var} "
                    f"(line {trace.source_line}, type: {trace.source_type})")
            
            # Hops
            if trace.hops:
                hops_branch = tree.add("[cyan]HOPS:[/cyan]")
                for hop in trace.hops:
                    hops_branch.add(
                        f"#{hop['hop_number']}: {hop['var']} "
                        f"(line {hop['line']}, {hop['operation']})"
                    )
            
            # Sink
            if trace.sink_var:
                tree.add(f"[red]SINK:[/red] {trace.sink_var} "
                        f"(line {trace.sink_line}, type: {trace.sink_type})")
            
            self._console.print(tree)
    
    def _print_pattern_matches(self, matches: list[PatternMatchDebug]):
        """Print pattern match details."""
        table = Table(title="🎯 Pattern Matches")
        table.add_column("Pattern ID", style="cyan")
        table.add_column("Matched", justify="center")
        table.add_column("Line", justify="right")
        table.add_column("Time", justify="right")
        
        for match in matches:
            status = "✅" if match.matched else "❌"
            table.add_row(
                match.pattern_id,
                status,
                str(match.match_line) if match.match_line else "-",
                f"{match.scan_time_ms:.3f}ms",
            )
        
        self._console.print("\n")
        self._console.print(table)
    
    def _print_summary(self, report: DebugReport):
        """Print summary panel."""
        total_violations = sum(s.violations_found for s in report.steps)
        taint_violations = sum(1 for t in report.taint_traces if t.is_violation)
        
        self._console.print(Panel(
            f"[bold]Total Steps:[/bold] {len(report.steps)}\n"
            f"[bold]Total Violations:[/bold] {total_violations}\n"
            f"[bold]Taint Violations:[/bold] {taint_violations}\n"
            f"[bold]Errors:[/bold] {len(report.errors)}\n"
            f"[bold]Warnings:[/bold] {len(report.warnings)}",
            title="📊 Summary",
            border_style="green" if not report.errors else "red"
        ))


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def explain_violation(violation: SecurityViolation) -> str:
    """
    Generate a human-readable explanation of a violation.
    
    Designed for new developers to understand what went wrong.
    """
    explanations = {
        "LLM06": (
            "🔐 HARDCODED SECRET\n\n"
            "What happened: You have sensitive data (like an API key or password) "
            "written directly in your code.\n\n"
            "Why it's bad: Anyone who sees your code (in Git, logs, or error messages) "
            "can steal this secret.\n\n"
            "How to fix: Use environment variables instead:\n"
            "  BEFORE: api_key = 'sk-1234...'\n"
            "  AFTER:  api_key = os.environ.get('API_KEY')"
        ),
        "LLM02": (
            "⚠️ DANGEROUS FUNCTION (eval/exec)\n\n"
            "What happened: You're using eval() or exec() which can run arbitrary code.\n\n"
            "Why it's bad: If user input reaches these functions, attackers can "
            "run any code on your system.\n\n"
            "How to fix: Use safer alternatives:\n"
            "  BEFORE: result = eval(user_input)\n"
            "  AFTER:  result = ast.literal_eval(user_input)  # For simple data\n"
            "  AFTER:  result = json.loads(user_input)  # For JSON data"
        ),
        "CMD": (
            "💻 COMMAND INJECTION RISK\n\n"
            "What happened: You're running shell commands in a way that could "
            "allow injection attacks.\n\n"
            "Why it's bad: Attackers could run malicious commands on your system.\n\n"
            "How to fix:\n"
            "  BEFORE: os.system(f'cat {filename}')\n"
            "  AFTER:  subprocess.run(['cat', filename], shell=False)"
        ),
        "TAINT": (
            "🔗 TAINTED DATA FLOW\n\n"
            "What happened: Sensitive data flowed from a source (like user input) "
            "to a dangerous sink (like print or subprocess).\n\n"
            "Why it's bad: This could expose secrets or allow injection attacks.\n\n"
            "How to fix: Sanitize or validate data before using it in dangerous operations."
        ),
    }
    
    # Find matching explanation
    for key, explanation in explanations.items():
        if key in violation.category or key in violation.title:
            return explanation
    
    # Default explanation
    return (
        f"🚨 SECURITY VIOLATION: {violation.title}\n\n"
        f"Category: {violation.category}\n"
        f"Severity: {violation.severity.value}\n"
        f"Description: {violation.description}\n"
        f"Recommendation: {violation.recommendation}"
    )


def create_debug_context(
    code: str,
    file_path: str = "<string>",
    level: DebugLevel = DebugLevel.VERBOSE,
) -> tuple[SecurityDebugger, ScanContext]:
    """
    Create a debugger and context for testing.
    
    Convenience function for new developers.
    """
    debugger = SecurityDebugger(level=level)
    context = ScanContext(
        project_path=str(Path(file_path).parent),
        phase="DEBUG",
        developer_id="debug-user",
        modified_files=[file_path],
        agent_source="debug-session",
    )
    return debugger, context


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    """CLI entry point for debugging."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Security Validator Debugger"
    )
    parser.add_argument(
        "file",
        help="Python file to debug",
    )
    parser.add_argument(
        "--level",
        choices=["OFF", "MINIMAL", "NORMAL", "VERBOSE", "TRACE"],
        default="VERBOSE",
        help="Debug verbosity level",
    )
    parser.add_argument(
        "--output",
        help="Output file for debug report (JSON)",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Show detailed explanations for violations",
    )
    
    args = parser.parse_args()
    
    # Create debugger
    debugger = SecurityDebugger(
        level=DebugLevel(args.level),
        output_file=args.output,
    )
    
    # Import validator
    from .security_validator import SecurityValidator, ValidatorConfig
    
    # Create validator with debug-friendly config
    config = ValidatorConfig(
        exit_on_critical=False,  # Don't exit, we want to see all results
        enable_persistence=False,  # Skip DB for debugging
    )
    validator = SecurityValidator(config)
    
    # Run debug scan
    file_path = Path(args.file)
    debugger.start_scan(str(file_path))
    
    try:
        content = file_path.read_text()
        debugger._current_report.lines_scanned = len(content.splitlines())
        
        # Debug AST
        debugger.debug_ast(content)
        
        # Run validation
        context = ScanContext(
            project_path=str(file_path.parent),
            phase="DEBUG",
            developer_id="cli-user",
        )
        result = validator.validate_content(content, context, str(file_path))
        
        # Add violations to report
        if debugger._current_report:
            debugger._current_report.violations = result.violations
        
        # Show explanations
        if args.explain and result.violations:
            console = Console()
            console.print("\n[bold]📚 VIOLATION EXPLANATIONS:[/bold]\n")
            for v in result.violations:
                console.print(Panel(
                    explain_violation(v),
                    title=f"{v.title} (line {v.line})",
                    border_style="red" if v.severity == Severity.CRITICAL else "yellow"
                ))
        
    except Exception as e:
        debugger.log_error(f"Scan failed: {e}", e)
    
    debugger.end_scan()
    debugger.print_report()


if __name__ == "__main__":
    main()
