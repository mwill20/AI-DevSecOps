# 🏗️ Architecture - Hybrid Governance Platform

## Overview

The AI DevSecOps platform is a **5-layer security mesh** that combines deterministic analysis with AI-powered reasoning, persistence, and observability. It features **Taint Handshake** protocol, **Shadow Code detection**, and **Semantic Drift** monitoring.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         HYBRID GOVERNANCE PLATFORM                           │
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Layer 1   │  │   Layer 2   │  │   Layer 3   │  │   Layer 4   │        │
│  │Deterministic│  │  Semantic   │  │ Operational │  │ AI Auditor  │        │
│  │   (Regex)   │  │   (AST)     │  │  (Shell)    │  │   (LLM)     │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
│         │                │                │                │               │
│         └────────────────┴────────────────┴────────────────┘               │
│                                   │                                         │
│                     ┌─────────────▼─────────────┐                          │
│                     │   SecurityValidator       │                          │
│                     │     (Orchestrator)        │                          │
│                     └─────────────┬─────────────┘                          │
│                                   │                                         │
│         ┌─────────────────────────┼─────────────────────────┐              │
│         │                         │                         │              │
│  ┌──────▼──────┐          ┌───────▼───────┐         ┌──────▼──────┐       │
│  │  Layer 5    │          │ Observability │         │   Output    │       │
│  │ SOC Ledger  │          │  Dashboard    │         │  Reports    │       │
│  │  (SQLite)   │          │   (Rich)      │         │   (JSON)    │       │
│  └─────────────┘          └───────────────┘         └─────────────┘       │
│         │                         │                                        │
│         ▼                         ▼                                        │
│  ┌──────────────┐          ┌───────────────┐                              │
│  │ Shadow Code  │          │ Semantic Drift│                              │
│  │  Detection   │          │    Radar      │                              │
│  └──────────────┘          └───────────────┘                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer Details

### Layer 1: Deterministic (Pattern Matching)

**File**: `src/security_py/core/scan_engine.py`

```python
@dataclass(frozen=True)
class SecurityPattern:
    id: str
    category: str
    severity: Severity
    pattern: re.Pattern
    description: str
    recommendation: str
    cwe_reference: str
```

**Technology**: Compiled regex patterns from OWASP LLM Top 10

**Catches**:
- Hardcoded secrets (`sk-`, `ghp_`, `AKIA`)
- Dangerous functions (`eval()`, `exec()`, `os.system()`)
- SQL injection patterns
- Insecure deserialization (`pickle.load()`, `yaml.load()`)

**Performance**: ~5ms for typical files (patterns pre-compiled at import)

---

### Layer 2: Semantic (AST Taint Analysis)

**File**: `src/security_py/core/taint_visitor.py`

```python
class TaintVisitor(ast.NodeVisitor):
    """Tracks data flow from sources to sinks."""
    
    SOURCES = {
        "input": DataSourceType.USER_INPUT,
        "os.environ.get": DataSourceType.ENVIRONMENT,
        "os.getenv": DataSourceType.ENVIRONMENT,
        "open": DataSourceType.FILE_READ,
    }
    
    SINKS = {
        "print": DataSinkType.CONSOLE,
        "logging": DataSinkType.LOGGING,
        "subprocess.run": DataSinkType.SUBPROCESS,
    }
```

**Technology**: Python `ast` module

**Catches**:
- Renamed secrets (`api_key = secret; x = api_key; print(x)`)
- Multi-hop taint flows
- Environment variables exposed to output
- User input flowing to dangerous sinks

**How it works**:
1. Parse code into AST
2. Identify sources (where data enters)
3. Track assignments (taint propagation)
4. Detect sinks (where data leaves)
5. Report violations when tainted data reaches sensitive sinks

---

### Layer 3: Operational (Shell Guard)

**File**: `src/security_py/core/shell_guard.py`

```python
class ShellGuard:
    """Intercepts and validates shell commands."""
    
    def intercept(self, command: str) -> CommandResult:
        # 1. Parse with shlex (handles quoting)
        args = shlex.split(command)
        
        # 2. Check against allow/block list
        if self._is_blocked(args[0]):
            return CommandResult(allowed=False, violation=...)
        
        # 3. Execute safely with shell=False
        if self._is_allowed(args[0]):
            return self._safe_execute(args)
```

**Technology**: `shlex.split()` + `subprocess.run(shell=False)`

**Configuration**: `src/security_py/policies/allow_list.json`

```json
{
  "allowed": ["ls", "cat", "git", "python", "pip"],
  "blocked": [
    {"command": "rm", "reason": "Data destruction"},
    {"command": "sudo", "reason": "Privilege escalation"}
  ]
}
```

---

### Layer 4: AI Auditor (LLM Reasoning)

**File**: `src/security_py/core/ai_auditor.py`

```python
class LLMVulnerabilityResponse(BaseModel):
    """Pydantic schema - LLM MUST output this exact structure."""
    vulnerability: bool
    vulnerability_type: str  # WASHED_SECRET, HIDDEN_STATE, LOGIC_BOMB, etc.
    reasoning: str = Field(min_length=10, max_length=1000)
    remediation: str = Field(min_length=10, max_length=500)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
```

**Technology**: Ollama + DeepSeek-R1 + Pydantic

**Advanced Threat Detection ("Detective" Mode)**:

| Type | Description | Detection Method |
|------|-------------|------------------|
| `WASHED_SECRET` | Secret hashed with MD5/SHA1 then logged | Semantic + taint flow |
| `HIDDEN_STATE` | Code triggers on `os.getlogin()`, hostname | Environment analysis |
| `LOGIC_BOMB` | Time-delayed payload (`datetime.now() > ...`) | Temporal pattern |
| `INSECURE_DECORATOR` | Auth decorators with env bypass | Decorator analysis |
| `BROKEN_AUTH` | Functions named `admin_*` without validation | Intent mismatch |

**Taint Handshake Protocol**:
```
┌─────────────────────────────────────────────────────────────────┐
│                      TAINT HANDSHAKE                             │
├─────────────────────────────────────────────────────────────────┤
│  AST (TaintVisitor)              LLM (AIAuditor)                │
│  ─────────────────              ──────────────────               │
│  "api_key flows to              "Is this MALICIOUS              │
│   logging via MD5"               or just COMPLEX?"              │
│         │                              │                         │
│         └──────────┬───────────────────┘                        │
│                    ▼                                             │
│           HANDSHAKE DECISION                                     │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Both CRITICAL?  → AUTO_BLOCKED                          │    │
│  │ AST found, AI missed? → NEEDS_HUMAN_REVIEW              │    │
│  │ AI found, AST missed? → NEEDS_HUMAN_REVIEW              │    │
│  │ Both agree safe? → AUTO_APPROVED                        │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

**Why Hybrid?**
- AST: Fast, deterministic, no hallucination (the "Bones")
- LLM: Contextual understanding, novel patterns (the "Meat")
- Combined: Best of both worlds with human as final gatekeeper

---

### Layer 5: SOC Ledger (Persistence)

**File**: `src/security_py/core/soc_ledger.py`

```sql
-- Schema
CREATE TABLE scan_records (
    id INTEGER PRIMARY KEY,
    agent_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    security_level TEXT,
    violation_count INTEGER,
    critical_count INTEGER,
    passed BOOLEAN,
    human_signoff_hash TEXT,
    content_hash TEXT NOT NULL
);

CREATE TABLE provenance_chain (
    id INTEGER PRIMARY KEY,
    file_path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    approval_hash TEXT NOT NULL UNIQUE,
    approved_by TEXT NOT NULL,
    parent_hash TEXT,  -- Links to chain
    FOREIGN KEY (parent_hash) REFERENCES provenance_chain(approval_hash)
);
```

**Technology**: SQLite + SHA-256 hashing

**Features**:
- **Agent Attribution**: Track which AI/human caused violations
- **Human Sign-off**: Cryptographic proof of approval
- **Chain of Custody**: Linked hashes prove file wasn't tampered
- **Shadow Code Detection**: Flags unauthorized AI modifications
- **Cryptographic Proofs**: Verifiable scan certificates

**Shadow Code Detection**:

```python
from security_py.core import SOCLedger, ProvenanceStatus

# Detect unauthorized AI modifications
status, message, record = ledger.verify_provenance_with_status("app.py", content)

# Status can be:
# - VERIFIED: Hash matches, human approved
# - SHADOW_CODE: File modified WITHOUT human approval (CRITICAL!)
# - MODIFIED_APPROVED: File modified WITH human approval
# - NO_RECORD: Never approved (new file)
# - CHAIN_BROKEN: Provenance chain tampered

if status == ProvenanceStatus.SHADOW_CODE:
    print("🚨 CRITICAL: Unauthorized code change detected!")
```

---

### Observability Dashboard

**File**: `src/security_py/core/observability.py`

```
┌──────────────────────────────────────────────────────────────┐
│              🛡️ SOC OBSERVABILITY DASHBOARD 🛡️               │
└──────────────────────────────────────────────────────────────┘

┌──────────────── 📊 Current Metrics ─────────────────┐
│ Scan Duration: 45.23 ms                             │
│ Peak Memory: 12.45 MB                               │
│ Files Scanned: 50                                   │
│ Violations Found: 3                                 │
└─────────────────────────────────────────────────────┘

           🤖 Agent Violation Leaderboard
┌──────┬─────────────────┬───────┬──────────┬──────────┐
│ Rank │ Agent ID        │ Scans │ Violate. │ Critical │
├──────┼─────────────────┼───────┼──────────┼──────────┤
│ #1   │ windsurf-cascade│  150  │    47    │    12    │
│ #2   │ copilot-gpt4    │   89  │    23    │     5    │
└──────┴─────────────────┴───────┴──────────┴──────────┘
```

**Technology**: Rich (Python terminal UI) + tracemalloc

**Semantic Drift (Red Team Radar)**:

Tracks divergence between AI and AST findings to identify blind spots:

```python
from security_py.core import ObservabilityDashboard

dashboard = ObservabilityDashboard()

# Record drift events
dashboard.record_semantic_drift(
    ast_found_threat=True,
    ai_found_threat=False,  # AI missed what AST found
    ast_category="TAINT_FLOW"
)

# Get metrics
drift = dashboard.get_semantic_drift_metrics()
print(f"AI Drift Rate: {drift.ai_drift_rate}%")   # AI finding novel threats
print(f"AST Drift Rate: {drift.ast_drift_rate}%") # AI blind spots
print(f"Direction: {drift.drift_direction}")      # AI_LEADING or AST_LEADING
```

| Direction | Meaning | Action |
|-----------|---------|--------|
| `AI_LEADING` | AI finding threats AST misses | Update AST patterns |
| `AST_LEADING` | AI has blind spots | Tune LLM prompt |
| `BALANCED` | Layers in sync | Normal operation |

---

### Model Bridge (AI Supply Chain)

**File**: `scripts/model_verify.py`

The Model Bridge connects your application to the AI inference engine:

```
┌─────────────────┐         ┌─────────────────┐
│  ai_auditor.py  │   HTTP  │  Ollama Server  │
│   (CLIENT)      │ ──────► │   (HOST)        │
│                 │ :11434  │                 │
│  "Send code,    │         │  "Run inference │
│   get verdict"  │ ◄────── │   on DeepSeek"  │
└─────────────────┘   JSON  └─────────────────┘
```

**Fail-Closed Policy**: If Model Bridge fails, system falls back to AST-only with mandatory human review.

**Supply Chain Verification**:
```bash
# Verify model integrity before critical scans
python scripts/model_verify.py --canary
```

---

## Data Flow

```
                    ┌─────────────┐
                    │  Code Input │
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │  Layer 1    │ │  Layer 2    │ │  Layer 3    │
    │ Deterministic│ │  Semantic   │ │ Operational │
    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
           │               │               │
           └───────────────┼───────────────┘
                           ▼
                 ┌─────────────────┐
                 │ SecurityValidator│
                 │   (Aggregate)   │
                 └────────┬────────┘
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
    ┌─────────────────┐     ┌─────────────────┐
    │   AI Auditor    │     │   Direct Result │
    │  (if enabled)   │     │  (AST-only)     │
    └────────┬────────┘     └────────┬────────┘
             │                       │
             └───────────┬───────────┘
                         ▼
              ┌─────────────────┐
              │  Final Decision │
              │ APPROVE/REJECT  │
              └────────┬────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
   ┌──────────┐ ┌──────────┐ ┌──────────┐
   │SOC Ledger│ │Dashboard │ │  Output  │
   │  (Log)   │ │(Metrics) │ │ (Report) │
   └──────────┘ └──────────┘ └──────────┘
```

---

## File Structure

```
src/security_py/
├── __init__.py              # Package exports
├── __main__.py              # CLI entry point
├── demo.py                  # Demo script
├── core/
│   ├── __init__.py          # Core exports
│   ├── scan_engine.py       # Layer 1: Deterministic
│   ├── taint_visitor.py     # Layer 2: Semantic
│   ├── shell_guard.py       # Layer 3: Operational
│   ├── ai_auditor.py        # Layer 4: AI Auditor
│   ├── soc_ledger.py        # Layer 5: Persistence
│   ├── observability.py     # Dashboard
│   ├── debugger.py          # Debugging utilities
│   └── security_validator.py # Orchestrator
├── types/
│   ├── __init__.py
│   └── violations.py        # Data structures
└── policies/
    └── allow_list.json      # Shell command policy
```

---

## Debugging Infrastructure

**File**: `src/security_py/core/debugger.py`

The `SecurityDebugger` provides comprehensive diagnostics for understanding scan behavior.

### Debug Levels

```python
class DebugLevel(str, Enum):
    OFF = "OFF"           # No debug output
    MINIMAL = "MINIMAL"   # Errors only
    NORMAL = "NORMAL"     # Errors + warnings + summary
    VERBOSE = "VERBOSE"   # All above + detailed traces
    TRACE = "TRACE"       # Everything including internal state
```

### Key Data Structures

```python
@dataclass
class TaintTrace:
    """Traces a single taint flow through code."""
    source_var: str          # Variable where taint originates
    source_line: int         # Line number of source
    source_type: str         # Type: ENVIRONMENT, USER_INPUT, etc.
    hops: list[dict]         # Each variable assignment in the chain
    sink_var: str            # Variable at the sink
    sink_line: int           # Line number of sink
    sink_type: str           # Type: CONSOLE, SUBPROCESS, etc.
    is_violation: bool       # Whether this flow is a violation

@dataclass
class DebugReport:
    """Complete debug report for a scan."""
    scan_id: str
    timestamp: str
    file_path: str
    total_duration_ms: float
    steps: list[ScanStep]           # Per-layer timing
    taint_traces: list[TaintTrace]  # All taint flows
    pattern_matches: list[...]      # Pattern match details
    errors: list[str]
    warnings: list[str]
```

### Usage Example

```python
from security_py.core import SecurityDebugger, DebugLevel

# Create debugger
debugger = SecurityDebugger(
    level=DebugLevel.VERBOSE,
    output_file="debug.json"  # Optional: auto-save report
)

# Track a scan
debugger.start_scan("app.py")

with debugger.track_step("Layer 1", "Pattern Matching"):
    # ... pattern matching code ...
    pass

# Trace taint flows
trace = debugger.trace_taint_source("api_key", 5, "ENVIRONMENT")
debugger.trace_taint_hop(trace, "temp", 6, "assignment")
debugger.trace_taint_sink(trace, "temp", 7, "CONSOLE", is_violation=True)

# Finish and report
report = debugger.end_scan()
debugger.print_report()
```

### Violation Explanations

The `explain_violation()` function provides beginner-friendly explanations:

```python
from security_py.core import explain_violation

for violation in result.violations:
    print(explain_violation(violation))

# Output:
# 🔐 HARDCODED SECRET
#
# What happened: You have sensitive data written directly in your code.
#
# Why it's bad: Anyone who sees your code can steal this secret.
#
# How to fix: Use environment variables instead:
#   BEFORE: api_key = 'sk-1234...'
#   AFTER:  api_key = os.environ.get('API_KEY')
```

---

## Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| `pydantic` | LLM output validation | Yes |
| `httpx` | Ollama API client | Yes |
| `rich` | CLI dashboard | Yes |
| `pytest` | Testing | Dev only |
| `mypy` | Type checking | Dev only |
| `ruff` | Linting | Dev only |

**Standard Library** (no install):
- `ast` - AST parsing
- `re` - Regex patterns
- `shlex` - Shell parsing
- `subprocess` - Safe execution
- `sqlite3` - Persistence
- `hashlib` - Cryptographic hashing
- `tracemalloc` - Memory profiling

---

## Security Guarantees

1. **CRITICAL violations always block**: `sys.exit(1)`
2. **AST overrides LLM for CRITICAL**: Deterministic beats probabilistic
3. **Shell commands default-deny**: Must be in allow list
4. **Provenance is immutable**: Hash chain cannot be broken
5. **All scans are logged**: Complete audit trail

---

## Performance Targets

| Metric | Target | Actual |
|--------|--------|--------|
| Single file scan | < 50ms | ~5-15ms |
| Directory scan (100 files) | < 2s | ~500ms |
| Memory per file | < 10MB | ~2-5MB |
| LLM augmentation | < 5s | 2-3s |
| Database insert | < 5ms | ~1ms |

---

## Extension Points

1. **Custom Patterns**: Add to `OWASP_LLM_PATTERNS` tuple
2. **Custom Sources/Sinks**: Extend `TaintVisitor` dictionaries
3. **Custom Commands**: Modify `allow_list.json`
4. **Custom LLM**: Swap Ollama client for any OpenAI-compatible API
5. **Custom Storage**: Replace SQLite with PostgreSQL/MySQL
