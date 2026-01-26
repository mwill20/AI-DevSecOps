# 🎓 Lesson 16: Red Team Exercises - Breaking Your Own Security

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- How to think like an attacker to improve defenses
- Evasion techniques and how to detect them
- Building adversarial test cases for security systems

---

## 🎭 The Red Team Mindset

Red teaming means attacking your own system to find weaknesses **before** real attackers do:

```
┌─────────────────────────────────────────────────────────────────┐
│                    RED TEAM vs BLUE TEAM                         │
│                                                                  │
│  🔴 RED TEAM (Offense)          🔵 BLUE TEAM (Defense)          │
│  ─────────────────────          ──────────────────────          │
│  • Find bypasses                • Write detection rules          │
│  • Craft evasion payloads       • Improve pattern matching       │
│  • Test edge cases              • Fix false negatives            │
│  • Document weaknesses          • Harden the system              │
│                                                                  │
│  Goal: Break the security mesh  Goal: Make it unbreakable       │
│                                                                  │
│  "If I were an attacker, how would I get past this scanner?"    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔴 Exercise 1: Evading Pattern Matching (Layer 1)

Our `ScanEngine` uses regex patterns. Here's how attackers try to evade them:

```python
# Line 1: tests/red_team/test_pattern_evasion.py
"""
Red Team Exercise: Evade Layer 1 Pattern Matching

Goal: Write code that contains secrets but evades detection.
Then: Improve the scanner to catch the evasion.
"""

import pytest
from security_py import SecurityValidator

@pytest.fixture
def validator():
    from security_py.core.security_validator import ValidatorConfig
    return SecurityValidator(ValidatorConfig(exit_on_critical=False))


class TestPatternEvasion:
    """Attempt to evade pattern-based secret detection."""

    # Line 21: EVASION 1 - String concatenation
    def test_evade_via_concatenation(self, validator, context):
        """Split the secret across multiple strings."""
        code = '''
# Attacker tries to hide API key via concatenation
prefix = "sk-"
suffix = "1234567890abcdef"
api_key = prefix + suffix  # Does scanner catch this?
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Add pattern for split assignments
        # Should this be caught? Document your decision.

    # Line 34: EVASION 2 - Base64 encoding
    def test_evade_via_base64(self, validator, context):
        """Encode the secret in base64."""
        code = '''
import base64

# Attacker encodes the API key
encoded = "c2stMTIzNDU2Nzg5MGFiY2RlZg=="  # base64("sk-1234567890abcdef")
api_key = base64.b64decode(encoded).decode()
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Add base64 pattern detection?
        # Trade-off: False positives on legitimate base64 usage

    # Line 48: EVASION 3 - Environment variable with fallback
    def test_evade_via_env_fallback(self, validator, context):
        """Hide secret in environment fallback."""
        code = '''
import os

# Looks safe... but fallback is a hardcoded secret!
api_key = os.environ.get("API_KEY", "sk-fallback-secret-key")
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: This IS caught by current scanner
        assert result.total_violations > 0

    # Line 62: EVASION 4 - Hex encoding
    def test_evade_via_hex(self, validator, context):
        """Use hex bytes to represent secret."""
        code = '''
# Attacker uses hex representation
secret_bytes = bytes.fromhex("736b2d313233343536373839306162636465")
api_key = secret_bytes.decode()  # "sk-1234567890abcde"
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Add hex pattern detection?

    # Line 74: EVASION 5 - Character codes
    def test_evade_via_char_codes(self, validator, context):
        """Build string from character codes."""
        code = '''
# Attacker uses chr() to build secret
api_key = ''.join(chr(c) for c in [115, 107, 45, 49, 50, 51, 52])
# Builds "sk-1234"
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: This is hard to detect statically
        # Consider runtime monitoring instead
```

---

## 🔴 Exercise 2: Evading Taint Analysis (Layer 2)

Our `TaintVisitor` tracks data flow. Here's how attackers try to break the chain:

```python
# Line 1: tests/red_team/test_taint_evasion.py
"""
Red Team Exercise: Evade Layer 2 Taint Tracking

Goal: Move tainted data to a sink without being detected.
"""

class TestTaintEvasion:
    """Attempt to evade taint flow tracking."""

    # Line 12: EVASION 1 - Break chain with globals
    def test_evade_via_global(self, validator, context):
        """Use global variable to break taint chain."""
        code = '''
_cache = {}

def store_secret(key, value):
    _cache[key] = value  # Taint stops here?

def leak_secret(key):
    print(_cache[key])  # Tainted data, but no direct link

# Usage
secret = os.environ.get("API_KEY")
store_secret("key", secret)
leak_secret("key")  # Does taint tracker see this flow?
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Improve inter-procedural analysis

    # Line 32: EVASION 2 - Break chain with list operations
    def test_evade_via_list_index(self, validator, context):
        """Use list to launder tainted data."""
        code = '''
secrets = []
secrets.append(os.environ.get("SECRET"))  # Tainted
value = secrets[0]  # Is this still tracked?
print(value)  # Tainted data reaches sink
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Track taint through container operations

    # Line 46: EVASION 3 - Break chain with function return
    def test_evade_via_function_boundary(self, validator, context):
        """Pass tainted data through function boundary."""
        code = '''
def get_config():
    return {"key": os.environ.get("API_KEY")}

config = get_config()
print(config["key"])  # Taint flow through function?
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Track taint through function returns

    # Line 60: EVASION 4 - Use eval to break static analysis
    def test_evade_via_eval(self, validator, context):
        """Use eval to execute dynamically - breaks static analysis."""
        code = '''
# Static analysis can't see inside eval
cmd = "print(os.environ.get('SECRET'))"
eval(cmd)  # Taint flow is invisible
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Flag ALL eval usage as CRITICAL
        # eval() breaks static analysis by design
        assert any(v.severity.value == "CRITICAL" for v in result.violations)
```

---

## 🔴 Exercise 3: Evading Shell Guard (Layer 3)

Our `ShellGuard` blocks dangerous commands. Here's how attackers try to bypass:

```python
# Line 1: tests/red_team/test_shell_evasion.py
"""
Red Team Exercise: Evade Layer 3 Shell Protection

Goal: Execute dangerous commands despite ShellGuard.
"""

class TestShellEvasion:
    """Attempt to evade shell command protection."""

    # Line 12: EVASION 1 - Use alternative command names
    def test_evade_via_aliases(self, validator, context):
        """Use command aliases or alternatives."""
        code = '''
import subprocess

# "rm" is blocked, but what about these?
subprocess.run(["unlink", "sensitive_file"])  # Alternative to rm
subprocess.run(["/bin/rm", "file"])  # Full path
subprocess.run(["busybox", "rm", "file"])  # Via busybox
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Block all file deletion commands

    # Line 26: EVASION 2 - Chain commands
    def test_evade_via_command_chain(self, validator, context):
        """Chain commands to bypass single-command checks."""
        code = '''
import os

# Each command looks safe individually...
os.system("echo 'test' > /tmp/script.sh")
os.system("chmod +x /tmp/script.sh")
os.system("/tmp/script.sh")  # Execute arbitrary code!
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Detect command chaining patterns

    # Line 40: EVASION 3 - Use Python to do shell's job
    def test_evade_via_python_stdlib(self, validator, context):
        """Use Python stdlib instead of shell commands."""
        code = '''
import shutil
import os

# No shell commands, but same effect!
shutil.rmtree("/important/directory")  # Like rm -rf
os.chmod("/etc/passwd", 0o777)  # Like chmod 777
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Also check dangerous stdlib functions!

    # Line 55: EVASION 4 - Obfuscate command strings
    def test_evade_via_obfuscation(self, validator, context):
        """Obfuscate command to evade string matching."""
        code = '''
import subprocess
import base64

# Encoded: "rm -rf /"
cmd = base64.b64decode("cm0gLXJmIC8=").decode()
subprocess.run(cmd, shell=True)
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Flag shell=True as CRITICAL regardless
        assert result.has_critical
```

---

## 🔴 Exercise 4: Logic Bomb Construction

Test detection of time-based and condition-based attacks:

```python
# Line 1: tests/red_team/test_logic_bombs.py
"""
Red Team Exercise: Craft Logic Bombs

Goal: Create code that triggers malicious behavior under specific conditions.
"""

class TestLogicBombs:
    """Attempt to create undetectable logic bombs."""

    # Line 12: Time-based trigger
    def test_time_bomb(self, validator, context):
        """Code that activates after a specific date."""
        code = '''
from datetime import datetime

def process_payment(amount):
    # Normal code...
    if datetime.now() > datetime(2026, 12, 31):
        # Malicious code activates after date
        exfiltrate_data()
    return amount * 1.1
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Our AIAuditor (Layer 4) should catch this!
        # Pattern: datetime comparison + suspicious function

    # Line 30: Environment-based trigger
    def test_env_bomb(self, validator, context):
        """Code that only activates in production."""
        code = '''
import os

def authenticate(user, password):
    if os.getenv("ENVIRONMENT") == "production":
        # Only runs in prod - testing won't catch it!
        log_credentials_to_external_server(user, password)
    return check_password(user, password)
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Flag environment-conditional security behavior

    # Line 46: User-based trigger
    def test_user_bomb(self, validator, context):
        """Code that targets specific users."""
        code = '''
import os

def admin_action():
    if os.getlogin() == "competitor_employee":
        delete_all_data()  # Targeted attack!
    return normal_admin_action()
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: Flag getlogin() in conditionals

    # Line 60: Counter-based trigger
    def test_counter_bomb(self, validator, context):
        """Code that activates after N executions."""
        code = '''
_counter = 0

def process_request(data):
    global _counter
    _counter += 1
    if _counter > 1000000:
        # After 1M requests, start stealing data
        steal_data(data)
    return handle_request(data)
'''
        result = validator.validate_content(code, context)
        # 🔵 BLUE TEAM: This is VERY hard to detect statically
        # Requires runtime monitoring or code review
```

---

## 📊 Red Team Scorecard

Track your evasion attempts and detection improvements:

```python
# Line 1: Red Team Exercise Scorecard

"""
┌─────────────────────────────────────────────────────────────────┐
│                    RED TEAM SCORECARD                            │
├─────────────────────────────────────────────────────────────────┤
│ Exercise                    │ Evaded? │ Detection Added? │ Notes│
├─────────────────────────────────────────────────────────────────┤
│ Pattern: Concatenation      │   ✅    │       ⬜         │      │
│ Pattern: Base64             │   ✅    │       ⬜         │      │
│ Pattern: Env Fallback       │   ❌    │       ✅         │      │
│ Pattern: Hex Encoding       │   ✅    │       ⬜         │      │
│ Pattern: Char Codes         │   ✅    │       ⬜         │      │
├─────────────────────────────────────────────────────────────────┤
│ Taint: Global Variable      │   ✅    │       ⬜         │      │
│ Taint: List Operations      │   ✅    │       ⬜         │      │
│ Taint: Function Boundary    │   ✅    │       ⬜         │      │
│ Taint: Eval Usage           │   ❌    │       ✅         │      │
├─────────────────────────────────────────────────────────────────┤
│ Shell: Aliases              │   ✅    │       ⬜         │      │
│ Shell: Command Chain        │   ✅    │       ⬜         │      │
│ Shell: Python stdlib        │   ✅    │       ⬜         │      │
│ Shell: Obfuscation          │   ❌    │       ✅         │      │
├─────────────────────────────────────────────────────────────────┤
│ Logic Bomb: Time-based      │   ?     │       ⬜         │ AI?  │
│ Logic Bomb: Env-based       │   ?     │       ⬜         │ AI?  │
│ Logic Bomb: User-based      │   ?     │       ⬜         │ AI?  │
│ Logic Bomb: Counter-based   │   ✅    │       ⬜         │ Hard │
└─────────────────────────────────────────────────────────────────┘

Legend: ✅ = Yes, ❌ = No, ⬜ = TODO, ? = Needs testing
"""
```

---

## 🔵 Blue Team Response: Improving Detection

After red team exercises, improve the scanner:

```python
# Line 1: src/security_py/core/scan_engine.py
# Add new patterns discovered during red teaming

# Pattern for base64-encoded secrets
SecurityPattern(
    id="RED-001",
    category=PatternCategory.OBFUSCATION,
    title="Base64-Encoded Secret Pattern",
    description="Possible obfuscated secret using base64",
    severity=Severity.MEDIUM,
    pattern=r'base64\.b64decode\(["\'][A-Za-z0-9+/=]{20,}["\']\)',
    recommendation="Review decoded content for secrets",
),

# Line 15: Pattern for dangerous stdlib functions
SecurityPattern(
    id="RED-002",
    category=PatternCategory.DANGEROUS_FUNCTION,
    title="Dangerous stdlib Function",
    description="File/permission manipulation via Python stdlib",
    severity=Severity.HIGH,
    pattern=r'shutil\.rmtree\(|os\.chmod\(|os\.remove\(',
    recommendation="Review file operations for safety",
),

# Line 26: Pattern for environment-conditional behavior
SecurityPattern(
    id="RED-003",
    category=PatternCategory.LOGIC_BOMB,
    title="Environment-Conditional Security Behavior",
    description="Security behavior changes based on environment",
    severity=Severity.CRITICAL,
    pattern=r'if\s+os\.getenv\(["\'](?:ENVIRONMENT|ENV|PROD)',
    recommendation="Security behavior should be consistent across environments",
),
```

---

## 🎯 Check for Understanding

**Question**: Why is it important to document evasions that you CAN'T detect?

*Think about defense-in-depth and compensating controls...*

---

## 📚 Interview Prep

**Q: How do you prioritize which evasion techniques to defend against?**

**A**: Risk-based prioritization:

```python
# Line 1: Prioritization matrix
"""
1. CRITICAL: Evasions that bypass ALL layers
   → Must fix immediately

2. HIGH: Evasions that bypass detection but leave forensic traces
   → Fix in next sprint + add monitoring

3. MEDIUM: Evasions that require significant attacker effort
   → Document and monitor

4. LOW: Theoretical evasions with no real-world examples
   → Track in backlog
"""
```

**Q: What's the difference between evasion and obfuscation?**

**A**:
- **Evasion**: Changing code structure to avoid detection while preserving malicious behavior
- **Obfuscation**: Making code hard to understand (may or may not be malicious)

```python
# Line 1: Evasion - changes structure to avoid pattern
api_key = "sk-" + secret  # Evades "sk-.*" pattern

# Line 4: Obfuscation - makes code hard to read
_0x1a2b = lambda _0x3c4d: ''.join(chr(ord(c)^42) for c in _0x3c4d)
# Could be malicious OR legitimate minification
```

**Q: How do you handle the arms race between attackers and defenders?**

**A**:
1. **Layer your defenses** - No single layer catches everything
2. **Assume breach** - Log everything for forensics
3. **Continuous red teaming** - Regular adversarial exercises
4. **AI-augmented detection** - LLMs can reason about novel evasions
5. **Runtime monitoring** - Catch what static analysis misses

---

## 🏁 Course Complete!

Congratulations! You've completed the **AI-DevSecOps Security** curriculum!

### What You've Learned

| Lessons | Topic | Key Takeaway |
|---------|-------|--------------|
| 00-03 | Foundation | 5-layer security mesh architecture |
| 04 | Audit Logging | → Merged into Lesson 10 (SOCLedger) |
| 05-06 | Analysis | Adversarial testing + AST taint tracking |
| 07 | Policy Engine | Roadmap feature for compliance rules |
| 08 | Shell Ops | ShellGuard command protection |
| 09-11 | Hybrid AI | LLM + AST + Provenance + Observability |
| 12-13 | Advanced | Debugging + Model Bridge |
| 14-16 | Operations | Prompt injection + CI/CD + Red teaming |

### Your Complete Toolkit

```python
# Line 1: The full AI-DevSecOps stack
from security_py import (
    SecurityValidator,    # 5-Layer Orchestrator
    ScanEngine,          # Layer 1: Pattern Matching
    TaintVisitor,        # Layer 2: Semantic Analysis
    ShellGuard,          # Layer 3: Operational Guards
)
from security_py.core import (
    AIAuditor,           # Layer 4: LLM Reasoning
    SOCLedger,           # Layer 5: Persistence + Provenance
    ObservabilityDashboard,  # Monitoring
    SecurityDebugger,    # Diagnostics
)
```

### Next Steps

1. **Run the adversarial test suite** on your own projects
2. **Set up CI/CD integration** with the security validator
3. **Conduct red team exercises** quarterly
4. **Monitor semantic drift** between AI and AST findings
5. **Contribute** - PRs welcome for new detection patterns!

---

*Remember: Security is not a destination, it's a continuous journey. Stay vigilant, keep learning, and always think like an attacker!* 🛡️🔴🔵
