# 🛡️ Python Security Validator

A native Python 3.12+ implementation of the 5-layer security mesh for AI-DevSecOps.

## Features

- **Layer 1: Deterministic** - High-speed pattern matching using compiled regex (OWASP LLM Top 10)
- **Layer 2: Semantic** - AST-based taint analysis using Python's `ast` module
- **Layer 3: Operational** - Shell command protection using `shlex` and `subprocess`
- **Layer 4: AI Auditor** - LLM reasoning (DeepSeek-R1 via Ollama) with Pydantic guardrails
- **Layer 5: Persistence** - SQLite SOC Ledger with cryptographic provenance chain

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or for development
pip install -e .
```

## Quick Start

```python
from security_py import SecurityValidator

# Create validator
validator = SecurityValidator()

# Validate a file (exits with code 1 on CRITICAL)
result = validator.validate_file("app.py")

# Validate a directory
result = validator.validate_directory("src/")

# Check results
if result.has_critical:
    print("CRITICAL violations found!")
print(f"Security Score: {validator.get_security_score(result)}/100")
```

## CLI Usage

```bash
# Scan a file
python -m security_py app.py

# Scan a directory
python -m security_py src/

# Advisory mode (warn but don't exit)
python -m security_py --mode ADVISORY src/

# Don't exit on critical
python -m security_py --no-exit src/
```

## Architecture

```
security_py/
├── __init__.py           # Package exports
├── __main__.py           # CLI entry point
├── demo.py               # Demo script
├── core/
│   ├── scan_engine.py    # Layer 1: Pattern matching
│   ├── taint_visitor.py  # Layer 2: AST taint analysis
│   ├── shell_guard.py    # Layer 3: Shell protection
│   ├── ai_auditor.py     # Layer 4: LLM + Pydantic guardrails
│   ├── soc_ledger.py     # Layer 5: SQLite persistence
│   ├── observability.py  # CLI Dashboard
│   ├── debugger.py       # Debugging utilities
│   └── security_validator.py  # Orchestrator
├── types/
│   └── violations.py     # Data structures
└── policies/
    └── allow_list.json   # Shell command allow list
```

## Running Tests

```bash
# Run all tests
pytest tests/adversarial_suite.py -v

# Run with coverage
pytest tests/adversarial_suite.py --cov=security_py --cov-report=html

# Run specific test class
pytest tests/adversarial_suite.py::TestSemanticLayer -v
```

## OWASP LLM Patterns Detected

| Pattern ID | Category | Severity | Description |
|------------|----------|----------|-------------|
| LLM01-001 | Prompt Injection | HIGH | Unsanitized input in prompts |
| LLM06-001 | Sensitive Info | CRITICAL | Hardcoded secrets |
| LLM06-002 | Sensitive Info | CRITICAL | API key patterns (sk-, ghp_, etc.) |
| LLM02-001 | Insecure Output | CRITICAL | eval() usage |
| CMD-001 | Command Injection | CRITICAL | os.system() usage |
| CMD-002 | Command Injection | CRITICAL | shell=True usage |

## Exit Codes

- `0` - No violations or only LOW/MEDIUM
- `1` - CRITICAL violations found (configurable)

## License

MIT
