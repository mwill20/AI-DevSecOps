# 🎓 Lesson 15: CI/CD Integration - Automated Security Gates

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- How to integrate security scanning into CI/CD pipelines
- Exit codes and their role in pipeline automation
- Best practices for security gates in deployment workflows

---

## 🔄 Security in the Development Lifecycle

Security scanning should happen automatically at every stage:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CI/CD SECURITY PIPELINE                       │
│                                                                  │
│  Developer    Pre-commit    PR/MR        Build       Deploy     │
│  ────────────────────────────────────────────────────────────   │
│      │            │           │            │            │        │
│      ▼            ▼           ▼            ▼            ▼        │
│  ┌──────┐    ┌──────┐    ┌──────┐    ┌──────┐    ┌──────┐      │
│  │ IDE  │    │Local │    │ CI   │    │ Full │    │ Final│      │
│  │Lint  │───▶│Scan  │───▶│Check │───▶│Audit │───▶│Gate  │      │
│  └──────┘    └──────┘    └──────┘    └──────┘    └──────┘      │
│                                                                  │
│  Each stage: CRITICAL = BLOCK, HIGH = WARN, MEDIUM/LOW = LOG   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚦 Exit Codes: The Language of CI/CD

Our `SecurityValidator` uses exit codes to communicate with pipelines:

```python
# Line 1: src/security_py/core/security_validator.py

# Exit code 0 = Success (no blocking violations)
# Exit code 1 = Failure (CRITICAL violations found)

def validate_and_exit(self, result: EnhancedValidationResult) -> None:
    """Exit with appropriate code for CI/CD integration."""
    if result.has_critical:
        self._print_critical_report(result)
        sys.exit(1)  # Pipeline will fail
    elif result.has_high:
        self._print_warning_report(result)
        sys.exit(0)  # Pipeline continues (configurable)
    else:
        print("✅ Security scan passed")
        sys.exit(0)

# Line 17: Why exit codes matter:
# - GitHub Actions checks $? (exit status)
# - GitLab CI checks return code
# - Jenkins checks build result
# - Pre-commit hooks check exit status
```

---

## 🔧 GitHub Actions Integration

```yaml
# Line 1: .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          pip install -e .
          pip install pytest pytest-cov

      # Line 28: Run security scan
      - name: Security Scan
        run: python -m security_py src/
        # Fails if exit code != 0 (CRITICAL violations)

      # Line 33: Run adversarial tests
      - name: Adversarial Tests
        run: pytest tests/adversarial_suite.py -v

      # Line 37: Optional: Upload scan results
      - name: Upload Security Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security_ledger.db

  # Line 45: Separate job for full audit (slower)
  full-audit:
    runs-on: ubuntu-latest
    needs: security-scan
    if: github.event_name == 'pull_request'

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install with AI Auditor
        run: pip install -e ".[ai]"

      - name: Full Hybrid Scan
        run: |
          # Start Ollama (if available)
          python -m security_py src/ --enable-ai-auditor || \
          python -m security_py src/  # Fallback without AI
```

---

## 🔗 Pre-commit Hook

```yaml
# Line 1: .pre-commit-config.yaml
repos:
  # Standard hooks
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml

  # Line 12: Our security validator
  - repo: local
    hooks:
      - id: security-scan
        name: Security Scan
        entry: python -m security_py
        language: python
        types: [python]
        pass_filenames: true
        # Only scan changed files for speed
        args: ['--mode', 'ADVISORY']
        # ADVISORY = warn but don't block (for pre-commit)
        # Change to STRICT for blocking behavior
```

### Pre-commit Shell Script Alternative

```bash
#!/bin/bash
# Line 1: .git/hooks/pre-commit

echo "🛡️ Running security scan..."

# Get list of staged Python files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$')

if [ -z "$STAGED_FILES" ]; then
    echo "No Python files staged, skipping security scan"
    exit 0
fi

# Line 13: Run security scan on staged files only
for FILE in $STAGED_FILES; do
    python -m security_py "$FILE"
    if [ $? -ne 0 ]; then
        echo "❌ Security scan failed for $FILE"
        echo "Fix CRITICAL violations before committing"
        exit 1
    fi
done

echo "✅ Security scan passed"
exit 0
```

---

## 🦊 GitLab CI Integration

```yaml
# Line 1: .gitlab-ci.yml
stages:
  - test
  - security
  - deploy

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

# Line 11: Security scan job
security-scan:
  stage: security
  image: python:3.12-slim
  cache:
    paths:
      - .cache/pip/
  script:
    - pip install -e .
    - python -m security_py src/
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
  artifacts:
    when: always
    paths:
      - security_ledger.db
    expire_in: 30 days

# Line 32: Block deploy if security fails
deploy-production:
  stage: deploy
  needs: [security-scan]
  script:
    - echo "Deploying to production..."
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  when: manual  # Require manual approval after security passes
```

---

## 🎯 Configuring Scan Behavior

```python
# Line 1: Different modes for different pipeline stages

from security_py.core.security_validator import SecurityValidator, ValidatorConfig

# Pre-commit: Advisory mode (warn but don't block)
pre_commit_config = ValidatorConfig(
    enforcement_mode="ADVISORY",
    exit_on_critical=False,  # Don't block commits
    enable_ai_auditor=False,  # Fast scan
)

# Line 11: PR/MR Check: Strict mode (block on CRITICAL)
pr_check_config = ValidatorConfig(
    enforcement_mode="STRICT",
    exit_on_critical=True,  # Block PRs with CRITICAL
    enable_ai_auditor=False,  # Fast scan
)

# Line 18: Pre-deploy: Full audit (all layers)
pre_deploy_config = ValidatorConfig(
    enforcement_mode="STRICT",
    exit_on_critical=True,
    enable_ai_auditor=True,  # Full hybrid scan
    enable_persistence=True,  # Log to SOC Ledger
)

# Line 26: Usage in CI script
import sys
validator = SecurityValidator(pr_check_config)
result = validator.validate_directory("src/")
sys.exit(0 if result.passed else 1)
```

---

## 📊 Scan Result Artifacts

```python
# Line 1: Generate CI-friendly output

import json
from pathlib import Path

def generate_ci_report(result: EnhancedValidationResult) -> dict:
    """Generate JSON report for CI artifact upload."""
    return {
        "passed": result.passed,
        "total_violations": result.total_violations,
        "critical_count": result.critical_count,
        "high_count": result.high_count,
        "security_score": validator.get_security_score(result),
        "layer_breakdown": {
            "deterministic": result.layer_breakdown.deterministic,
            "semantic": result.layer_breakdown.semantic,
            "operational": result.layer_breakdown.operational,
        },
        "violations": [
            {
                "severity": v.severity.value,
                "category": v.category,
                "title": v.title,
                "file": v.file,
                "line": v.line,
                "description": v.description,
            }
            for v in result.violations
        ],
    }

# Line 33: Save for CI artifact upload
report = generate_ci_report(result)
Path("security-report.json").write_text(json.dumps(report, indent=2))

# Line 37: SARIF format for GitHub Code Scanning
def to_sarif(result: EnhancedValidationResult) -> dict:
    """Convert to SARIF format for GitHub Security tab."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AI-DevSecOps Security Validator",
                    "version": "3.0.0",
                    "rules": [...]
                }
            },
            "results": [
                {
                    "ruleId": v.category,
                    "level": "error" if v.severity == Severity.CRITICAL else "warning",
                    "message": {"text": v.description},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": v.file},
                            "region": {"startLine": v.line}
                        }
                    }]
                }
                for v in result.violations
            ]
        }]
    }
```

---

## 🔒 Secrets Detection in CI

```yaml
# Line 1: Prevent secrets from entering the repo

# .github/workflows/secrets-scan.yml
name: Secrets Detection

on: [push, pull_request]

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for secrets detection

      - name: Run security scan for secrets
        run: |
          pip install -e .
          # Our scanner catches hardcoded secrets (Layer 1)
          python -m security_py . --pattern-only
        env:
          # Don't expose real secrets in CI logs
          SCAN_MODE: "SECRETS_ONLY"

      # Line 24: Additional secrets scanner (defense in depth)
      - name: TruffleHog Scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
```

---

## 🎯 Best Practices

```python
# Line 1: CI/CD Security Best Practices

# 1. Fail fast: Run quick checks first
# Pre-commit → Local scan → PR check → Full audit

# 2. Cache dependencies
# pip cache, pre-compiled patterns

# 3. Scan only changed files in PRs
# Full scan on main branch merges

# 4. Use artifacts for debugging
# Upload security_ledger.db, reports

# 5. Don't expose secrets in logs
# Mask sensitive output

# 6. Different strictness per stage
# ADVISORY (pre-commit) → STRICT (PR) → FULL (deploy)

# 7. Human gate for production
# Require manual approval after security passes

# 8. Monitor security trends
# Track violations over time, alert on regressions
```

---

## 🎯 Check for Understanding

**Question**: Why use `--mode ADVISORY` in pre-commit hooks but `STRICT` in CI?

*Think about developer experience vs. security enforcement...*

---

## 📚 Interview Prep

**Q: How do you handle false positives in CI/CD security scans?**

**A**: Multiple strategies:

```python
# Line 1: Strategy 1 - Inline suppression comments
api_key = os.environ.get("API_KEY")  # nosec: Not a hardcoded secret

# Line 4: Strategy 2 - Exclusion file
# .security-ignore
# tests/fixtures/vulnerable_samples.py  # Test data
# legacy/old_code.py  # Scheduled for removal

# Line 9: Strategy 3 - Advisory mode for known issues
# Run in ADVISORY during transition period

# Line 12: Strategy 4 - SOC Ledger exceptions
# Log exception with justification and approver
ledger.add_exception(
    file="legacy.py",
    reason="Legacy code scheduled for Q2 removal",
    approved_by="security-lead",
    expires="2026-06-01",
)
```

**Q: What happens if the security scan times out?**

**A**: Set appropriate timeouts and fail safely:

```yaml
# Line 1: GitHub Actions timeout
- name: Security Scan
  run: python -m security_py src/
  timeout-minutes: 10
  continue-on-error: false  # Fail the job on timeout
```

**Q: How do you secure the CI/CD pipeline itself?**

**A**:
1. Pin action versions (`@v4` not `@latest`)
2. Use OIDC for cloud credentials (no stored secrets)
3. Require PR reviews before merge
4. Audit pipeline changes
5. Scan the CI config files themselves

---

## 🚀 Ready for Lesson 16?

In the final lesson, we'll explore **Red Team Exercises** - how to test your security system with adversarial attacks.

*Remember: Security gates are only as strong as their enforcement - automate or it won't happen!* 🛡️🐍
