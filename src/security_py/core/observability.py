"""
Observability Dashboard - CLI-Based SOC Monitoring

Provides real-time visibility into:
- Scan duration and performance metrics
- Memory usage tracking
- Most frequent violator identification
- Agent behavior monitoring
"""

import os
import sys
import time
import tracemalloc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text

from .soc_ledger import SOCLedger, ScanRecord


@dataclass
class PerformanceMetrics:
    """Performance metrics for a scan."""
    scan_duration_ms: float = 0.0
    peak_memory_mb: float = 0.0
    file_count: int = 0
    violation_count: int = 0
    lines_scanned: int = 0
    ai_confidence: float = 0.0
    ai_agrees_with_ast: bool = True
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SemanticConfidenceMetrics:
    """Metrics tracking AI Auditor vs AST agreement over time."""
    total_scans: int = 0
    ai_enabled_scans: int = 0
    agreements: int = 0          # AI and AST agree
    disagreements: int = 0       # AI and AST disagree
    avg_ai_confidence: float = 0.0
    high_confidence_scans: int = 0  # confidence >= 0.7
    low_confidence_scans: int = 0   # confidence < 0.7
    
    @property
    def agreement_rate(self) -> float:
        """Percentage of scans where AI agrees with AST."""
        if self.ai_enabled_scans == 0:
            return 0.0
        return (self.agreements / self.ai_enabled_scans) * 100
    
    @property
    def reliability_score(self) -> float:
        """
        Combined reliability score (0-100).
        
        Factors:
        - Agreement rate (60% weight)
        - High confidence rate (40% weight)
        """
        if self.ai_enabled_scans == 0:
            return 0.0
        high_conf_rate = (self.high_confidence_scans / self.ai_enabled_scans) * 100
        return (self.agreement_rate * 0.6) + (high_conf_rate * 0.4)


@dataclass
class SemanticDriftMetrics:
    """
    Semantic Drift Tracker - Red Team Radar.
    
    Tracks divergence between AI Auditor and AST findings:
    - AI_ONLY: AI found threat, AST missed it (potential novel attack)
    - AST_ONLY: AST found threat, AI missed it (AI blind spot)
    
    High drift = layers are seeing different things = needs investigation.
    """
    total_scans: int = 0
    ai_only_detections: int = 0      # AI found, AST missed
    ast_only_detections: int = 0     # AST found, AI missed
    both_detected: int = 0           # Both found same threat
    neither_detected: int = 0        # Both said clean
    
    # Detailed tracking for Red Team analysis
    ai_only_categories: dict = field(default_factory=dict)  # {category: count}
    ast_only_categories: dict = field(default_factory=dict)
    
    @property
    def ai_drift_rate(self) -> float:
        """Rate at which AI sees threats AST misses (novel attack surface)."""
        if self.total_scans == 0:
            return 0.0
        return (self.ai_only_detections / self.total_scans) * 100
    
    @property
    def ast_drift_rate(self) -> float:
        """Rate at which AST sees threats AI misses (AI blind spots)."""
        if self.total_scans == 0:
            return 0.0
        return (self.ast_only_detections / self.total_scans) * 100
    
    @property
    def total_drift_rate(self) -> float:
        """Total disagreement rate between layers."""
        if self.total_scans == 0:
            return 0.0
        return ((self.ai_only_detections + self.ast_only_detections) / self.total_scans) * 100
    
    @property
    def drift_direction(self) -> str:
        """Which layer is finding more unique threats."""
        if self.ai_only_detections > self.ast_only_detections:
            return "AI_LEADING"  # AI finding novel threats
        elif self.ast_only_detections > self.ai_only_detections:
            return "AST_LEADING"  # AI has blind spots
        return "BALANCED"


@dataclass
class AgentProfile:
    """Profile of an agent's behavior."""
    agent_id: str
    total_scans: int = 0
    total_violations: int = 0
    total_critical: int = 0
    avg_duration_ms: float = 0.0
    violation_rate: float = 0.0  # violations per scan


class ObservabilityDashboard:
    """
    CLI-based observability dashboard for SOC monitoring.
    
    Features:
    - Real-time scan metrics
    - Memory usage tracking
    - Agent violation leaderboard
    - Performance trends
    """
    
    def __init__(self, ledger: Optional[SOCLedger] = None):
        self._ledger = ledger or SOCLedger()
        self._console = Console()
        self._current_metrics: Optional[PerformanceMetrics] = None
        self._memory_tracking = False
        self._semantic_confidence_history: list[tuple[float, bool]] = []  # (confidence, agrees)
        self._semantic_drift: SemanticDriftMetrics = SemanticDriftMetrics()
    
    # =========================================================================
    # MEMORY TRACKING
    # =========================================================================
    
    def start_memory_tracking(self) -> None:
        """Start tracking memory usage."""
        tracemalloc.start()
        self._memory_tracking = True
    
    def stop_memory_tracking(self) -> float:
        """Stop tracking and return peak memory in MB."""
        if self._memory_tracking:
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            self._memory_tracking = False
            return peak / (1024 * 1024)  # Convert to MB
        return 0.0
    
    def get_current_memory_mb(self) -> float:
        """Get current memory usage in MB."""
        if self._memory_tracking:
            current, _ = tracemalloc.get_traced_memory()
            return current / (1024 * 1024)
        return 0.0
    
    # =========================================================================
    # SCAN METRICS
    # =========================================================================
    
    def record_scan_metrics(
        self,
        scan_duration_ms: float,
        file_count: int = 1,
        violation_count: int = 0,
        lines_scanned: int = 0,
        ai_confidence: float = 0.0,
        ai_agrees_with_ast: bool = True,
    ) -> PerformanceMetrics:
        """Record metrics for a completed scan."""
        peak_memory = self.stop_memory_tracking() if self._memory_tracking else 0.0
        
        self._current_metrics = PerformanceMetrics(
            scan_duration_ms=scan_duration_ms,
            peak_memory_mb=peak_memory,
            file_count=file_count,
            violation_count=violation_count,
            lines_scanned=lines_scanned,
            ai_confidence=ai_confidence,
            ai_agrees_with_ast=ai_agrees_with_ast,
        )
        
        # Track semantic confidence history (if AI was used)
        if ai_confidence > 0:
            self._semantic_confidence_history.append((ai_confidence, ai_agrees_with_ast))
        
        return self._current_metrics
    
    def get_semantic_confidence_metrics(self) -> SemanticConfidenceMetrics:
        """Calculate semantic confidence metrics from history."""
        if not self._semantic_confidence_history:
            return SemanticConfidenceMetrics()
        
        total = len(self._semantic_confidence_history)
        agreements = sum(1 for _, agrees in self._semantic_confidence_history if agrees)
        disagreements = total - agreements
        avg_confidence = sum(c for c, _ in self._semantic_confidence_history) / total
        high_conf = sum(1 for c, _ in self._semantic_confidence_history if c >= 0.7)
        low_conf = total - high_conf
        
        return SemanticConfidenceMetrics(
            total_scans=total,
            ai_enabled_scans=total,
            agreements=agreements,
            disagreements=disagreements,
            avg_ai_confidence=avg_confidence,
            high_confidence_scans=high_conf,
            low_confidence_scans=low_conf,
        )
    
    # =========================================================================
    # DASHBOARD DISPLAY
    # =========================================================================
    
    def record_semantic_drift(
        self,
        ast_found_threat: bool,
        ai_found_threat: bool,
        ai_category: Optional[str] = None,
        ast_category: Optional[str] = None,
    ) -> None:
        """
        Record a semantic drift event for Red Team analysis.
        
        This tracks when AI and AST disagree on whether code is malicious.
        """
        self._semantic_drift.total_scans += 1
        
        if ai_found_threat and ast_found_threat:
            self._semantic_drift.both_detected += 1
        elif ai_found_threat and not ast_found_threat:
            self._semantic_drift.ai_only_detections += 1
            if ai_category:
                self._semantic_drift.ai_only_categories[ai_category] = (
                    self._semantic_drift.ai_only_categories.get(ai_category, 0) + 1
                )
        elif ast_found_threat and not ai_found_threat:
            self._semantic_drift.ast_only_detections += 1
            if ast_category:
                self._semantic_drift.ast_only_categories[ast_category] = (
                    self._semantic_drift.ast_only_categories.get(ast_category, 0) + 1
                )
        else:
            self._semantic_drift.neither_detected += 1
    
    def get_semantic_drift_metrics(self) -> SemanticDriftMetrics:
        """Get current semantic drift metrics."""
        return self._semantic_drift
    
    def show_dashboard(self) -> None:
        """Display the full observability dashboard."""
        self._console.clear()
        self._console.print(self._build_header())
        self._console.print()
        self._console.print(self._build_metrics_panel())
        self._console.print()
        self._console.print(self._build_semantic_confidence_panel())
        self._console.print()
        self._console.print(self._build_semantic_drift_panel())
        self._console.print()
        self._console.print(self._build_agent_table())
        self._console.print()
        self._console.print(self._build_recent_activity())
    
    def _build_header(self) -> Panel:
        """Build dashboard header."""
        header = Text()
        header.append("🛡️ ", style="bold blue")
        header.append("SOC OBSERVABILITY DASHBOARD", style="bold white")
        header.append(" 🛡️", style="bold blue")
        header.append(f"\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", style="dim")
        return Panel(header, style="blue")
    
    def _build_metrics_panel(self) -> Panel:
        """Build current metrics panel."""
        if self._current_metrics:
            m = self._current_metrics
            content = f"""
[bold]Scan Duration:[/bold] {m.scan_duration_ms:.2f} ms
[bold]Peak Memory:[/bold] {m.peak_memory_mb:.2f} MB
[bold]Files Scanned:[/bold] {m.file_count}
[bold]Lines Scanned:[/bold] {m.lines_scanned}
[bold]Violations Found:[/bold] {m.violation_count}
"""
        else:
            content = "[dim]No recent scan metrics[/dim]"
        
        return Panel(content.strip(), title="📊 Current Metrics", border_style="green")
    
    def _build_semantic_confidence_panel(self) -> Panel:
        """
        Build Semantic Confidence panel showing AI vs AST agreement.
        
        This helps human analysts understand where the AI Auditor is most reliable.
        High agreement rate = tool can be trusted for similar patterns.
        """
        metrics = self.get_semantic_confidence_metrics()
        
        if metrics.ai_enabled_scans == 0:
            content = "[dim]No AI Auditor data yet. Enable AI auditing to see confidence metrics.[/dim]"
            return Panel(content, title="🧠 Semantic Confidence", border_style="cyan")
        
        # Build ASCII bar chart for agreement rate
        agreement_bar = self._build_ascii_bar(metrics.agreement_rate, 100, width=20)
        reliability_bar = self._build_ascii_bar(metrics.reliability_score, 100, width=20)
        
        # Color coding based on reliability
        if metrics.reliability_score >= 80:
            reliability_style = "bold green"
            trust_label = "HIGH TRUST"
        elif metrics.reliability_score >= 60:
            reliability_style = "bold yellow"
            trust_label = "MODERATE TRUST"
        else:
            reliability_style = "bold red"
            trust_label = "LOW TRUST - Review Recommended"
        
        content = f"""
[bold]AI vs AST Agreement:[/bold]
  {agreement_bar} {metrics.agreement_rate:.1f}%
  Agreements: {metrics.agreements} | Disagreements: {metrics.disagreements}

[bold]Average AI Confidence:[/bold] {metrics.avg_ai_confidence:.2f}
  High Confidence (≥0.7): {metrics.high_confidence_scans}
  Low Confidence (<0.7):  {metrics.low_confidence_scans}

[bold]Reliability Score:[/bold]
  {reliability_bar} [{reliability_style}]{metrics.reliability_score:.1f}% - {trust_label}[/{reliability_style}]

[dim]Based on {metrics.ai_enabled_scans} AI-augmented scans[/dim]
"""
        return Panel(content.strip(), title="🧠 Semantic Confidence (AI Auditor Trust)", border_style="cyan")
    
    def _build_ascii_bar(self, value: float, max_value: float, width: int = 20) -> str:
        """Build an ASCII progress bar."""
        filled = int((value / max_value) * width)
        empty = width - filled
        return f"[{'█' * filled}{'░' * empty}]"
    
    def _build_semantic_drift_panel(self) -> Panel:
        """
        Build Semantic Drift panel - Red Team Radar.
        
        Shows when AI and AST see different threats, helping identify:
        - AI blind spots (AST finds, AI misses)
        - Novel attack patterns (AI finds, AST misses)
        """
        drift = self._semantic_drift
        
        if drift.total_scans == 0:
            content = "[dim]No drift data yet. Run scans with AI enabled to track semantic drift.[/dim]"
            return Panel(content, title="🎯 Semantic Drift (Red Team Radar)", border_style="magenta")
        
        # Direction indicator
        if drift.drift_direction == "AI_LEADING":
            direction_icon = "🤖→"
            direction_text = "AI finding novel threats AST misses"
            direction_style = "cyan"
        elif drift.drift_direction == "AST_LEADING":
            direction_icon = "←🌳"
            direction_text = "AI has blind spots - AST catching more"
            direction_style = "yellow"
        else:
            direction_icon = "⚖️"
            direction_text = "Layers balanced"
            direction_style = "green"
        
        # Build drift bars
        ai_drift_bar = self._build_ascii_bar(drift.ai_drift_rate, 100, width=15)
        ast_drift_bar = self._build_ascii_bar(drift.ast_drift_rate, 100, width=15)
        total_drift_bar = self._build_ascii_bar(drift.total_drift_rate, 100, width=15)
        
        # Alert level based on drift
        if drift.total_drift_rate > 30:
            alert_style = "bold red"
            alert_text = "⚠️ HIGH DRIFT - Layers seeing very different threats!"
        elif drift.total_drift_rate > 15:
            alert_style = "bold yellow"
            alert_text = "📊 Moderate drift - consider investigation"
        else:
            alert_style = "bold green"
            alert_text = "✅ Low drift - layers in sync"
        
        # Top categories for AI-only and AST-only
        ai_top = sorted(drift.ai_only_categories.items(), key=lambda x: -x[1])[:3]
        ast_top = sorted(drift.ast_only_categories.items(), key=lambda x: -x[1])[:3]
        
        ai_cats = ", ".join(f"{k}({v})" for k, v in ai_top) if ai_top else "none"
        ast_cats = ", ".join(f"{k}({v})" for k, v in ast_top) if ast_top else "none"
        
        content = f"""
[bold]Drift Direction:[/bold] [{direction_style}]{direction_icon} {direction_text}[/{direction_style}]

[bold]AI-Only Detections:[/bold] {drift.ai_only_detections}
  {ai_drift_bar} {drift.ai_drift_rate:.1f}%
  [dim]Categories: {ai_cats}[/dim]

[bold]AST-Only Detections:[/bold] {drift.ast_only_detections}
  {ast_drift_bar} {drift.ast_drift_rate:.1f}%
  [dim]Categories: {ast_cats}[/dim]

[bold]Total Drift Rate:[/bold]
  {total_drift_bar} [{alert_style}]{drift.total_drift_rate:.1f}%[/{alert_style}]

[{alert_style}]{alert_text}[/{alert_style}]

[dim]Both detected: {drift.both_detected} | Neither: {drift.neither_detected} | Total scans: {drift.total_scans}[/dim]
"""
        return Panel(content.strip(), title="🎯 Semantic Drift (Red Team Radar)", border_style="magenta")
    
    def _build_agent_table(self) -> Table:
        """Build agent violation leaderboard."""
        table = Table(title="🤖 Agent Violation Leaderboard")
        table.add_column("Rank", style="dim", width=6)
        table.add_column("Agent ID", style="cyan")
        table.add_column("Total Scans", justify="right")
        table.add_column("Violations", justify="right", style="yellow")
        table.add_column("Critical", justify="right", style="red")
        table.add_column("Avg Duration", justify="right")
        
        stats = self._ledger.get_agent_stats()
        for i, stat in enumerate(stats[:10], 1):
            table.add_row(
                f"#{i}",
                stat["agent_id"],
                str(stat["total_scans"]),
                str(stat["total_violations"] or 0),
                str(stat["total_critical"] or 0),
                f"{stat['avg_duration_ms']:.1f}ms" if stat["avg_duration_ms"] else "N/A",
            )
        
        if not stats:
            table.add_row("", "[dim]No agent data yet[/dim]", "", "", "", "")
        
        return table
    
    def _build_recent_activity(self) -> Panel:
        """Build recent activity panel."""
        recent = self._ledger.get_recent_activity(hours=24)
        
        if recent:
            lines = []
            for scan in recent[:5]:
                status = "✅" if scan.passed else "❌"
                lines.append(
                    f"{status} [{scan.timestamp[:19]}] {scan.agent_id}: "
                    f"{scan.source_file} ({scan.violation_count} violations)"
                )
            content = "\n".join(lines)
        else:
            content = "[dim]No recent activity in last 24 hours[/dim]"
        
        return Panel(content, title="📋 Recent Activity (24h)", border_style="yellow")
    
    # =========================================================================
    # QUICK REPORTS
    # =========================================================================
    
    def print_scan_summary(self, metrics: PerformanceMetrics) -> None:
        """Print a quick summary after a scan."""
        self._console.print()
        self._console.print(Panel(
            f"[bold]Scan Complete[/bold]\n"
            f"Duration: {metrics.scan_duration_ms:.2f}ms | "
            f"Memory: {metrics.peak_memory_mb:.2f}MB | "
            f"Violations: {metrics.violation_count}",
            title="📊 Scan Metrics",
            border_style="green" if metrics.violation_count == 0 else "red"
        ))
    
    def print_most_frequent_violator(self) -> None:
        """Print the most frequent violator."""
        violator = self._ledger.get_most_frequent_violator()
        
        if violator:
            self._console.print(Panel(
                f"[bold red]🚨 Most Frequent Violator[/bold red]\n\n"
                f"[bold]Agent:[/bold] {violator['agent_id']}\n"
                f"[bold]Total Violations:[/bold] {violator['total_violations']}\n"
                f"[bold]Critical:[/bold] {violator['total_critical']}\n"
                f"[bold]Scans:[/bold] {violator['total_scans']}",
                title="⚠️ Violator Alert",
                border_style="red"
            ))
        else:
            self._console.print("[dim]No violation data available[/dim]")
    
    def print_performance_report(self) -> None:
        """Print detailed performance report."""
        stats = self._ledger.get_agent_stats()
        
        if not stats:
            self._console.print("[dim]No performance data available[/dim]")
            return
        
        total_scans = sum(s["total_scans"] for s in stats)
        total_violations = sum(s["total_violations"] or 0 for s in stats)
        total_critical = sum(s["total_critical"] or 0 for s in stats)
        
        self._console.print(Panel(
            f"[bold]Aggregate Statistics[/bold]\n\n"
            f"Total Scans: {total_scans}\n"
            f"Total Violations: {total_violations}\n"
            f"Total Critical: {total_critical}\n"
            f"Unique Agents: {len(stats)}\n"
            f"Violation Rate: {total_violations/total_scans:.2f} per scan" if total_scans else "N/A",
            title="📈 Performance Report",
            border_style="blue"
        ))


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    """CLI entry point for observability dashboard."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SOC Observability Dashboard"
    )
    parser.add_argument(
        "--db", default="security_ledger.db",
        help="Path to SQLite database"
    )
    parser.add_argument(
        "--violator", action="store_true",
        help="Show most frequent violator"
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Show performance report"
    )
    
    args = parser.parse_args()
    
    with SOCLedger(args.db) as ledger:
        dashboard = ObservabilityDashboard(ledger)
        
        if args.violator:
            dashboard.print_most_frequent_violator()
        elif args.report:
            dashboard.print_performance_report()
        else:
            dashboard.show_dashboard()


if __name__ == "__main__":
    main()
