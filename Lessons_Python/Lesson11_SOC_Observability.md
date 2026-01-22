# 🎓 Lesson 11: SOC Observability - Monitoring AI Security Behavior

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- How to build a CLI-based SOC dashboard
- Memory and performance tracking with `tracemalloc`
- Identifying the "Most Frequent Violator"

---

## 📊 What is SOC Observability?

Security Operations Center (SOC) observability answers:
- **How long** do scans take?
- **How much memory** does analysis consume?
- **Which agents** introduce the most violations?
- **What's happening** right now?

```
┌─────────────────────────────────────────────────────────────────┐
│                    SOC OBSERVABILITY                             │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ Duration │  │  Memory  │  │ Violator │  │ Activity │        │
│  │  Metrics │  │ Tracking │  │ Ranking  │  │   Feed   │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
│       │             │             │             │               │
│       └─────────────┴─────────────┴─────────────┘               │
│                           ▼                                      │
│              ┌─────────────────────┐                            │
│              │  CLI DASHBOARD      │                            │
│              │  Real-time Metrics  │                            │
│              └─────────────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🐍 Memory Tracking with tracemalloc

```python
# Line 1: src/security_py/core/observability.py
import tracemalloc
from dataclasses import dataclass, field
from datetime import datetime, timezone

@dataclass
class PerformanceMetrics:
    """Performance metrics for a scan."""
    scan_duration_ms: float = 0.0
    peak_memory_mb: float = 0.0
    file_count: int = 0
    violation_count: int = 0
    lines_scanned: int = 0
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

class ObservabilityDashboard:
    """CLI-based SOC monitoring dashboard."""
    
    def __init__(self, ledger: SOCLedger):
        self._ledger = ledger
        self._memory_tracking = False
    
    # Line 26: Start memory tracking
    def start_memory_tracking(self) -> None:
        """
        Start tracking memory usage.
        
        tracemalloc is Python's built-in memory profiler.
        It tracks every memory allocation with minimal overhead.
        """
        tracemalloc.start()
        self._memory_tracking = True
    
    # Line 38: Stop and get peak memory
    def stop_memory_tracking(self) -> float:
        """Stop tracking and return peak memory in MB."""
        if self._memory_tracking:
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            self._memory_tracking = False
            return peak / (1024 * 1024)  # Convert bytes to MB
        return 0.0
    
    # Line 49: Get current memory (while tracking)
    def get_current_memory_mb(self) -> float:
        """Get current memory usage in MB."""
        if self._memory_tracking:
            current, _ = tracemalloc.get_traced_memory()
            return current / (1024 * 1024)
        return 0.0
```

---

## 📈 Recording Scan Metrics

```python
# Line 1: Record metrics after scan completion
def record_scan_metrics(
    self,
    scan_duration_ms: float,
    file_count: int = 1,
    violation_count: int = 0,
    lines_scanned: int = 0,
) -> PerformanceMetrics:
    """Record metrics for a completed scan."""
    
    # Line 12: Stop memory tracking and get peak
    peak_memory = 0.0
    if self._memory_tracking:
        peak_memory = self.stop_memory_tracking()
    
    # Line 17: Create metrics record
    self._current_metrics = PerformanceMetrics(
        scan_duration_ms=scan_duration_ms,
        peak_memory_mb=peak_memory,
        file_count=file_count,
        violation_count=violation_count,
        lines_scanned=lines_scanned,
    )
    
    return self._current_metrics

# Line 28: Usage example
dashboard = ObservabilityDashboard(ledger)
dashboard.start_memory_tracking()

start = time.perf_counter()
result = validator.validate_directory("src/")
duration_ms = (time.perf_counter() - start) * 1000

metrics = dashboard.record_scan_metrics(
    scan_duration_ms=duration_ms,
    file_count=50,
    violation_count=result.total_violations,
    lines_scanned=10000,
)

print(f"Duration: {metrics.scan_duration_ms:.2f}ms")
print(f"Peak Memory: {metrics.peak_memory_mb:.2f}MB")
```

---

## 🏆 Most Frequent Violator

```python
# Line 1: Identify agents causing the most violations
def get_agent_stats(self) -> list[dict]:
    """Get violation statistics by agent."""
    conn = self._get_conn()
    rows = conn.execute("""
        SELECT 
            agent_id,
            COUNT(*) as total_scans,
            SUM(violation_count) as total_violations,
            SUM(critical_count) as total_critical,
            AVG(scan_duration_ms) as avg_duration_ms
        FROM scan_records
        GROUP BY agent_id
        ORDER BY total_violations DESC
    """).fetchall()
    
    return [dict(row) for row in rows]

# Line 19: Get the worst offender
def get_most_frequent_violator(self) -> Optional[dict]:
    """Get the agent/user with the most violations."""
    stats = self.get_agent_stats()
    return stats[0] if stats else None

# Line 25: Example output
# {
#     "agent_id": "windsurf-cascade",
#     "total_scans": 150,
#     "total_violations": 47,
#     "total_critical": 12,
#     "avg_duration_ms": 45.3
# }
```

---

## 🖥️ The CLI Dashboard

```python
# Line 1: Building the dashboard with Rich
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

class ObservabilityDashboard:
    def __init__(self, ledger: SOCLedger):
        self._ledger = ledger
        self._console = Console()
    
    # Line 11: Full dashboard display
    def show_dashboard(self) -> None:
        """Display the full observability dashboard."""
        self._console.clear()
        self._console.print(self._build_header())
        self._console.print()
        self._console.print(self._build_metrics_panel())
        self._console.print()
        self._console.print(self._build_agent_table())
        self._console.print()
        self._console.print(self._build_recent_activity())
    
    # Line 23: Header panel
    def _build_header(self) -> Panel:
        from rich.text import Text
        header = Text()
        header.append("🛡️ ", style="bold blue")
        header.append("SOC OBSERVABILITY DASHBOARD", style="bold white")
        header.append(" 🛡️", style="bold blue")
        header.append(
            f"\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", 
            style="dim"
        )
        return Panel(header, style="blue")
    
    # Line 37: Agent leaderboard table
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
                f"{stat['avg_duration_ms']:.1f}ms",
            )
        
        return table
```

---

## 📊 Example Dashboard Output

```
┌──────────────────────────────────────────────────────────────┐
│              🛡️ SOC OBSERVABILITY DASHBOARD 🛡️               │
│                   2026-01-21 14:30:00 UTC                    │
└──────────────────────────────────────────────────────────────┘

┌──────────────── 📊 Current Metrics ─────────────────┐
│ Scan Duration: 45.23 ms                             │
│ Peak Memory: 12.45 MB                               │
│ Files Scanned: 50                                   │
│ Lines Scanned: 10,000                               │
│ Violations Found: 3                                 │
└─────────────────────────────────────────────────────┘

           🤖 Agent Violation Leaderboard
┌──────┬─────────────────┬───────┬──────────┬──────────┬──────────┐
│ Rank │ Agent ID        │ Scans │ Violate. │ Critical │ Avg Dur. │
├──────┼─────────────────┼───────┼──────────┼──────────┼──────────┤
│ #1   │ windsurf-cascade│  150  │    47    │    12    │  45.3ms  │
│ #2   │ copilot-gpt4    │   89  │    23    │     5    │  38.2ms  │
│ #3   │ human-developer │   45  │    12    │     2    │  52.1ms  │
└──────┴─────────────────┴───────┴──────────┴──────────┴──────────┘

┌──────────────── 📋 Recent Activity (24h) ───────────────┐
│ ✅ [14:30:00] windsurf-cascade: app.py (0 violations)   │
│ ❌ [14:15:00] copilot-gpt4: config.py (2 violations)    │
│ ✅ [14:00:00] human-developer: utils.py (0 violations)  │
│ ❌ [13:45:00] windsurf-cascade: api.py (5 violations)   │
│ ✅ [13:30:00] windsurf-cascade: models.py (0 violations)│
└─────────────────────────────────────────────────────────┘
```

---

## 🚨 Violator Alerts

```python
# Line 1: Print most frequent violator alert
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

# Line 19: Example output:
# ┌────────────────── ⚠️ Violator Alert ──────────────────┐
# │ 🚨 Most Frequent Violator                             │
# │                                                       │
# │ Agent: windsurf-cascade                               │
# │ Total Violations: 47                                  │
# │ Critical: 12                                          │
# │ Scans: 150                                            │
# └───────────────────────────────────────────────────────┘
```

---

## 🔧 CLI Entry Point

```python
# Line 1: Command-line interface
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
    
    # Line 24: Connect and display
    with SOCLedger(args.db) as ledger:
        dashboard = ObservabilityDashboard(ledger)
        
        if args.violator:
            dashboard.print_most_frequent_violator()
        elif args.report:
            dashboard.print_performance_report()
        else:
            dashboard.show_dashboard()

# Line 35: Usage
# python -m security_py.core.observability
# python -m security_py.core.observability --violator
# python -m security_py.core.observability --report
```

---

## 🎯 Check for Understanding

**Question**: Why track memory usage for security scans?

*Think about resource exhaustion attacks and DoS...*

---

## 📚 Interview Prep

**Q: Why is agent attribution important for SOC?**

**A**: Agent attribution enables:
1. **Accountability**: Know which AI/human introduced vulnerabilities
2. **Training data**: Identify which models need fine-tuning
3. **Access control**: Restrict high-risk agents
4. **Trend analysis**: Track if an agent is improving or degrading

```python
# Line 1: Without attribution
# "47 violations found" - But who caused them?

# Line 4: With attribution
# "windsurf-cascade: 47 violations (12 critical)"
# "copilot-gpt4: 23 violations (5 critical)"
# 
# Now we can: train windsurf, investigate the 12 critical,
# compare agent performance, set per-agent policies
```

**Q: How would you scale this to a distributed system?**

**A**: Replace SQLite with:
1. **PostgreSQL/MySQL** for production
2. **TimescaleDB** for time-series metrics
3. **Grafana** for visualization
4. **Prometheus** for metric collection
5. **Message queue** (Kafka/RabbitMQ) for real-time streaming

```python
# Line 1: SQLite is perfect for:
# - Single-machine deployment
# - Development/testing
# - Small teams (<100 scans/minute)

# Line 6: For enterprise scale:
# - Use PostgreSQL with connection pooling
# - Add Redis for caching hot data
# - Stream to Kafka for real-time processing
# - Visualize in Grafana dashboards
```

**Q: What metrics indicate a security system is working well?**

**A**: Key health indicators:
1. **Scan latency p99 < 100ms** - Fast enough for CI/CD
2. **Memory usage < 100MB** - Doesn't bloat build agents
3. **False positive rate < 5%** - Developers trust results
4. **Detection rate > 95%** - Catches known vulnerabilities
5. **Violation trend decreasing** - Developers learning

```python
# Line 1: Example health check
def is_healthy(metrics: PerformanceMetrics) -> bool:
    return (
        metrics.scan_duration_ms < 100 and
        metrics.peak_memory_mb < 100 and
        # Add more checks...
    )
```

---

## 🎉 Course Complete!

Congratulations! You've completed the **Hybrid AI-DevSecOps Security** curriculum!

### Summary of What You've Learned

| Lesson | Topic | Key Takeaway |
|--------|-------|--------------|
| 00-08 | Core Security | 3-layer mesh (AST, patterns, shell) |
| 09 | Hybrid Security | LLM + AST with Pydantic guardrails |
| 10 | Digital Provenance | Chain of custody with crypto hashes |
| 11 | SOC Observability | Monitoring AI behavior in real-time |

### Your Complete Toolkit

```python
# Line 1: The full hybrid governance stack
from security_py import (
    SecurityValidator,    # Orchestrator
    AIAuditor,            # LLM reasoning
    SOCLedger,            # Persistence
    ObservabilityDashboard,  # Monitoring
)

# Line 9: Complete workflow
validator = SecurityValidator()
auditor = AIAuditor()
ledger = SOCLedger()
dashboard = ObservabilityDashboard(ledger)

# Scan → Audit → Log → Monitor
result = validator.validate_file("app.py")
audit = auditor.audit(code, result.violations, context)
record = ledger.log_scan(...)
dashboard.show_dashboard()
```

*Stay secure, stay observable, stay accountable!* 🛡️🐍

---

## 🚀 Next Steps

1. **Deploy** the hybrid validator in your CI/CD pipeline
2. **Configure** Ollama with DeepSeek-R1 for AI augmentation
3. **Monitor** the dashboard for violation trends
4. **Train** your team using the complete curriculum
5. **Contribute** new patterns and policies back to the project

*The future of security is hybrid - deterministic foundations with AI intuition!*
