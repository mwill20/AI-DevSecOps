# 🛡️ AI Operation Center

A **Python 3.12+ Hybrid Governance Platform** combining deterministic security analysis with AI-powered reasoning, persistence, and observability.

## 🎯 Overview

The AI Operation Center implements a **5-layer security mesh** that protects against both traditional vulnerabilities and AI-specific threats. It combines:
- **Deterministic analysis** (AST, regex) for known patterns
- **AI reasoning** (DeepSeek-R1 via Ollama) for contextual understanding
- **Persistence** (SQLite SOC Ledger) for audit trails & **Shadow Code detection**
- **Observability** (CLI Dashboard) with **Semantic Drift** tracking

**Key features**:
- `sys.exit(1)` on CRITICAL violations (CI/CD ready)
- **Taint Handshake**: AST provides "bones", LLM provides "meat"
- **Shadow Code Detection**: Flags unauthorized AI modifications
- **Cryptographic Provenance**: Verifiable chain of custody

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    HYBRID GOVERNANCE PLATFORM                    │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: Deterministic │ Compiled regex (OWASP LLM Top 10)     │
│  Layer 2: Semantic      │ Python ast module (taint analysis)    │
│  Layer 3: Operational   │ ShellGuard (shlex + subprocess)       │
│  Layer 4: AI Auditor    │ DeepSeek-R1 + Pydantic guardrails     │
│  Layer 5: Persistence   │ SQLite SOC Ledger + Provenance Chain  │
├─────────────────────────────────────────────────────────────────┤
│  Observability: CLI Dashboard │ Memory, Duration, Violators     │
└─────────────────────────────────────────────────────────────────┘
```

| Layer | Name | Technology | Purpose |
|-------|------|------------|---------|
| 1 | **Deterministic** | Compiled regex | Pattern-based vulnerability detection |
| 2 | **Semantic** | Python `ast` | Taint analysis & data flow tracking |
| 3 | **Operational** | `shlex` + `subprocess` | Shell command protection |
| 4 | **AI Auditor** | Ollama + Pydantic | LLM reasoning with schema guardrails |
| 5 | **Persistence** | SQLite | SOC Ledger, provenance, human sign-off |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/mwill20/AI-Operation-Center.git
cd AI-Operation-Center

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1  # Windows
# source .venv/bin/activate   # Linux/Mac

# Install in development mode
pip install -e .
```

### Run Security Scan

```bash
# Scan a file
python -m security_py app.py

# Scan a directory
python -m security_py src/

# Run the demo
python -m security_py.demo

# Run adversarial tests (41 tests)
pytest tests/adversarial_suite.py -v

# Run logic bomb detection tests (16 tests)
pytest tests/test_logic_bomb_detection.py -v

# View SOC Dashboard
python -m security_py.core.observability

# Verify AI Model Supply Chain
python scripts/model_verify.py --canary
```

### Example Output

```
🔍 Layer 1: Deterministic Pattern Matching
   Found 8 deterministic violations
🧠 Layer 2: Semantic AST Analysis
   Found 0 semantic violations
🔒 Layer 3: Operational Guardrails
   Found 0 operational violations

============================================================
🚨 CRITICAL SECURITY VIOLATIONS DETECTED
============================================================
1. [CRITICAL] LLM06: LLM06-001
   File: app.py:6
   Hardcoded sensitive information detected
   Fix: Move sensitive data to environment variables
```

---

## 📁 Project Structure

```
AI-Operation-Center/
├── src/security_py/              # Python security engine
│   ├── core/
│   │   ├── scan_engine.py        # Layer 1: Pattern matching
│   │   ├── taint_visitor.py      # Layer 2: AST taint analysis
│   │   ├── shell_guard.py        # Layer 3: Shell protection
│   │   ├── ai_auditor.py         # Layer 4: LLM + Pydantic
│   │   ├── soc_ledger.py         # Layer 5: SQLite persistence
│   │   ├── observability.py      # CLI Dashboard
│   │   └── security_validator.py # Orchestrator
│   ├── types/violations.py       # Data structures
│   └── policies/allow_list.json  # Shell command allow list
├── tests/
│   ├── adversarial_suite.py      # 41 adversarial tests
│   └── test_logic_bomb_detection.py  # Advanced threat tests
├── Lessons_Python/               # 14 Python lessons (00-13)
│   ├── Lesson00_Intro.md         # Introduction
│   ├── Lesson01-08               # Core security
│   ├── Lesson09_Hybrid_Security.md    # LLM + AST + Taint Handshake
│   ├── Lesson10_Digital_Provenance.md # Chain of custody + Forensic Lab
│   ├── Lesson11_SOC_Observability.md  # Monitoring
│   ├── Lesson12_Debugging.md          # Taint traces & diagnostics
│   └── Lesson13_Model_Bridge.md       # AI Supply Chain & Provenance
├── scripts/
│   └── model_verify.py           # AI model supply chain verification
├── pyproject.toml                # Package configuration
└── requirements.txt              # Dependencies
```

---

## 🐍 Python API Usage

### Basic Scanning

```python
from security_py import SecurityValidator

# Create validator (exits on CRITICAL by default)
validator = SecurityValidator()

# Validate a file
result = validator.validate_file("app.py")

# Check results
print(f"Passed: {result.passed}")
print(f"Violations: {result.total_violations}")
```

### AI-Augmented Auditing

```python
from security_py.core import AIAuditor, SecurityValidator

# Create hybrid validator
validator = SecurityValidator()
auditor = AIAuditor()  # Connects to Ollama

# Scan with AST first
result = validator.validate_content(code, context)

# Augment with LLM reasoning
audit = auditor.audit(code, result.violations, context)

print(f"Decision: {audit.decision}")  # APPROVE, REJECT, MANUAL_REVIEW
print(f"Reasoning: {audit.reasoning}")
print(f"Confidence: {audit.confidence}")
```

### SOC Ledger (Persistence)

```python
from security_py.core import SOCLedger

# Log scans with agent attribution
ledger = SOCLedger()
record = ledger.log_scan(
    agent_id="windsurf-cascade",
    source_file="app.py",
    content=code,
    violation_count=3,
    passed=False,
)

# Add human sign-off
signoff_hash = ledger.add_human_signoff(
    scan_id=record.id,
    approver_id="alice@company.com",
    justification="False positive - test file"
)

# Chain of custody
provenance = ledger.approve_file(
    file_path="app.py",
    content=code,
    approved_by="security-bot",
)

# Verify provenance
is_valid, msg = ledger.verify_provenance("app.py", code)
```

### Observability Dashboard

```python
from security_py.core import ObservabilityDashboard, SOCLedger

dashboard = ObservabilityDashboard(SOCLedger())

# Track memory during scan
dashboard.start_memory_tracking()
result = validator.validate_directory("src/")
metrics = dashboard.record_scan_metrics(duration_ms=45.2)

# Show dashboard
dashboard.show_dashboard()

# Get most frequent violator
dashboard.print_most_frequent_violator()
```

---

## 🔍 What It Detects

### Layer 1: Deterministic (OWASP LLM Top 10)

| Pattern | Category | Severity |
|---------|----------|----------|
| Hardcoded secrets | LLM06 | CRITICAL |
| API key patterns (sk-, ghp_, etc.) | LLM06 | CRITICAL |
| `eval()` usage | LLM02 | CRITICAL |
| `os.system()` | CMD-001 | CRITICAL |
| `subprocess` with `shell=True` | CMD-002 | CRITICAL |
| `pickle.load()` | CODE-EXEC | HIGH |
| SQL injection patterns | SQL-001 | CRITICAL |

### Layer 2: Semantic (AST Taint Analysis)

- **Source tracking**: `input()`, `os.environ`, file reads
- **Sink detection**: `print()`, `logging`, `subprocess`
- **Taint propagation**: Tracks data through variable assignments
- **Multi-hop flows**: `secret → x → y → print(y)`

### Layer 3: Operational (Shell Protection)

| Command | Status | Risk |
|---------|--------|------|
| `rm`, `rmdir` | ❌ Blocked | DATA_DESTRUCTION |
| `sudo`, `su` | ❌ Blocked | PRIVILEGE_ESCALATION |
| `chmod`, `chown` | ❌ Blocked | SECURITY_BYPASS |
| `curl`, `wget` | ❌ Blocked | EXTERNAL_REQUEST |
| `ls`, `cat`, `git` | ✅ Allowed | - |
| `python`, `pip` | ✅ Allowed | - |

### Layer 4: AI Auditor (Reasoning Detective)

**Advanced Threat Detection**:
| Type | Description | Severity |
|------|-------------|----------|
| `WASHED_SECRET` | Secret hashed with MD5/SHA1 then logged | CRITICAL |
| `HIDDEN_STATE` | Code triggers on `os.getlogin()`, hostname | CRITICAL |
| `LOGIC_BOMB` | Time-delayed payload (`datetime.now() > ...`) | CRITICAL |
| `INSECURE_DECORATOR` | Auth decorators with env bypass | CRITICAL |
| `BROKEN_AUTH` | Functions named `admin_*` without validation | HIGH |

**Taint Handshake Protocol**:
- AST provides: WHAT data flows WHERE (deterministic fact)
- LLM provides: WHY it matters (semantic intent)
- Decision matrix: `AUTO_BLOCKED`, `NEEDS_HUMAN_REVIEW`, `AUTO_APPROVED`

### Layer 5: Persistence & Shadow Code Detection

- **Scan Records**: Agent attribution, human sign-off tracking
- **Provenance Chain**: Cryptographic hash linking all approvals
- **Shadow Code Detection**: Flags files modified without human approval
- **Cryptographic Proofs**: Verifiable scan certificates

```python
from security_py.core import SOCLedger, ProvenanceStatus

# Detect unauthorized AI modifications (Shadow Code)
status, message, record = ledger.verify_provenance_with_status("app.py", content)

if status == ProvenanceStatus.SHADOW_CODE:
    print("🚨 CRITICAL: File modified without human approval!")
    # status can be: VERIFIED, SHADOW_CODE, MODIFIED_APPROVED, NO_RECORD
```

### Semantic Drift (Red Team Radar)

Track divergence between AI and AST findings:

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
print(f"AI Drift Rate: {drift.ai_drift_rate}%")  # AI finding novel threats
print(f"AST Drift Rate: {drift.ast_drift_rate}%")  # AI blind spots
print(f"Direction: {drift.drift_direction}")  # AI_LEADING or AST_LEADING
```

---

## 🧪 Testing

```bash
# Run all 41 adversarial tests
pytest tests/adversarial_suite.py -v

# Run with coverage
pytest tests/adversarial_suite.py --cov=security_py --cov-report=html

# Run specific test class
pytest tests/adversarial_suite.py::TestSemanticLayer -v
```

### Test Categories

- **TestDeterministicLayer**: Hardcoded secrets, eval, os.system, pickle
- **TestSemanticLayer**: Renamed secrets, multi-hop taint, env→print
- **TestOperationalLayer**: rm, sudo, shell escapes, allow list
- **TestEvasionAttempts**: Base64, string concat, exec bypass
- **TestPolicyViolations**: Forbidden imports, empty except
- **TestIntegration**: Multi-layer detection, scoring, reports

---

## 📚 Learning Path

Complete 14-lesson curriculum in `Lessons_Python/`:

| Lesson | Topic | Key Concept |
|--------|-------|-------------|
| 00 | Introduction | Hybrid governance platform |
| 01 | Patterns | OWASP LLM as dataclasses |
| 02 | ScanEngine | Compiled regex scanning |
| 03 | Orchestration | SecurityValidator |
| 04 | Audit Logging | Hash-chained records |
| 05 | Testing | Adversarial test design |
| 06 | AST Semantics | TaintVisitor |
| 07 | Policy Engine | Business rules |
| 08 | Shell Ops | ShellGuard |
| **09** | **Hybrid Security** | **Taint Handshake protocol** |
| **10** | **Digital Provenance** | **Chain of custody + Forensic Lab** |
| **11** | **SOC Observability** | **Semantic Drift tracking** |
| **12** | **Debugging** | **Taint traces & diagnostics** |
| **13** | **Model Bridge** | **AI Supply Chain & Provenance** |

---

## 🐛 Debugging

The `SecurityDebugger` provides comprehensive diagnostics:

```python
from security_py.core import SecurityDebugger, DebugLevel

# Create debugger with desired verbosity
debugger = SecurityDebugger(level=DebugLevel.VERBOSE)

# Start debug session
debugger.start_scan("app.py")

# ... run your scan ...

# Get the report
report = debugger.end_scan()
debugger.print_report()

# Export to JSON
report.to_json()
```

### Debug Levels

| Level | Use Case |
|-------|----------|
| `OFF` | Production/CI |
| `MINIMAL` | Errors only |
| `NORMAL` | Errors + warnings |
| `VERBOSE` | Detailed traces |
| `TRACE` | Everything (very verbose) |

### CLI Debugging

```bash
# Debug a file with verbose output
python -m security_py.core.debugger app.py --level VERBOSE

# Export debug report
python -m security_py.core.debugger app.py --output debug.json

# Show human-readable explanations
python -m security_py.core.debugger app.py --explain
```

---

## 🔧 CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    pip install -e .
    python -m security_py src/
  # Fails pipeline if CRITICAL violations found (exit code 1)
```

```bash
# Pre-commit hook
#!/bin/bash
python -m security_py . || exit 1
```

---

## 🤖 AI Integration (Optional)

To enable AI-augmented auditing:

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull DeepSeek-R1 model
ollama pull deepseek-r1:14b

# Start Ollama server
ollama serve
```

The AI Auditor will automatically detect Ollama and enable hybrid analysis.

---

## 📄 License

MIT License - see LICENSE file for details.

---

*AI Operation Center v3.0 - Hybrid Governance Platform*  
*5-Layer AI-DevSecOps Security Mesh with LLM Reasoning*
