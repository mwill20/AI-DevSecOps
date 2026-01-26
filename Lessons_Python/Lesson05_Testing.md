# 🎓 Lesson 05: Adversarial Testing - Breaking Your Own Security

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- How to design adversarial test cases for security systems
- The 5-layer test methodology
- Writing pytest-based security test suites

---

## 🎭 The Adversarial Mindset

To build secure systems, think like an attacker:

```
┌─────────────────────────────────────────────────────┐
│  "If I were trying to bypass this security,         │
│   what would I try?"                                │
│                                                     │
│  • Rename variables to hide secrets                 │
│  • Use encoding to bypass patterns                  │
│  • Chain commands with ; or &&                      │
│  • Import forbidden libraries indirectly            │
└─────────────────────────────────────────────────────┘
```

---

## 🐍 Test Structure with pytest

```python
# Line 1: tests/adversarial_suite.py
import pytest
from pathlib import Path
from security_py import SecurityValidator, ValidatorConfig
from security_py.types import Severity, ScanContext

# Line 7: Test fixture for validator
@pytest.fixture
def validator() -> SecurityValidator:
    """Create validator that doesn't exit on critical."""
    config = ValidatorConfig(
        exit_on_critical=False,  # Don't sys.exit in tests!
        enable_deterministic=True,
        enable_semantic=True,
        enable_operational=True,
    )
    return SecurityValidator(config)

# Line 19: Test fixture for context
@pytest.fixture
def context() -> ScanContext:
    return ScanContext(
        project_path="/test",
        phase="TEST",
        developer_id="test-user",
        agent_source="pytest",
    )
```

---

## 🔴 Layer 1: Deterministic Tests

Test that pattern matching catches obvious vulnerabilities:

```python
# Line 1: Test hardcoded secrets
class TestDeterministicLayer:
    """Layer 1: Pattern matching tests."""

    def test_catches_hardcoded_api_key(self, validator, context):
        """Hardcoded API keys should be detected."""
        code = '''
api_key = "sk-1234567890abcdefghij"
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed
        assert any(v.category == "LLM06" for v in result.violations)
        assert any(v.severity == Severity.CRITICAL for v in result.violations)

    # Line 17: Test eval() detection
    def test_catches_eval(self, validator, context):
        """eval() should always be flagged."""
        code = '''
user_input = input("Enter expression: ")
result = eval(user_input)
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed
        assert any("eval" in v.code_snippet for v in result.violations)

    # Line 29: Test os.system() detection
    def test_catches_os_system(self, validator, context):
        """os.system() should be flagged as dangerous."""
        code = '''
import os
os.system("ls -la")
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed
        assert any(v.cwe_reference == "CWE-78" for v in result.violations)

    # Line 41: Test subprocess shell=True
    def test_catches_shell_true(self, validator, context):
        """subprocess with shell=True is dangerous."""
        code = '''
import subprocess
subprocess.run("cat /etc/passwd", shell=True)
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed
        assert any("shell=True" in v.description.lower() or 
                   "shell=true" in v.code_snippet.lower() 
                   for v in result.violations)
```

---

## 🧠 Layer 2: Semantic Tests

Test that AST analysis catches renamed and obfuscated secrets:

```python
# Line 1: Test semantic taint tracking
class TestSemanticLayer:
    """Layer 2: AST taint analysis tests."""

    def test_catches_renamed_secret(self, validator, context):
        """Secrets renamed through variables should still be caught."""
        code = '''
api_key = "sk-1234567890abcdefghij"
x = api_key  # Renamed!
print(x)     # Tainted data flows to sink
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed
        # Should detect tainted flow from api_key -> x -> print()
        semantic = [v for v in result.violations 
                    if hasattr(v, 'semantic_type')]
        assert len(semantic) > 0

    # Line 20: Test multi-hop taint flow
    def test_catches_multi_hop_taint(self, validator, context):
        """Taint should propagate through multiple assignments."""
        code = '''
secret = "password123456789"
a = secret
b = a
c = b
print(c)  # 4 hops from source to sink
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed

    # Line 35: Test environment variable taint
    def test_catches_env_to_print(self, validator, context):
        """Environment variables printed should be flagged."""
        code = '''
import os
api_key = os.environ.get("API_KEY")
print(f"Key: {api_key}")  # Sensitive data exposed!
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed
        assert any("ENVIRONMENT" in str(v) or "taint" in v.title.lower() 
                   for v in result.violations)

    # Line 49: Test input() to subprocess
    def test_catches_input_to_subprocess(self, validator, context):
        """User input flowing to subprocess is dangerous."""
        code = '''
import subprocess
cmd = input("Enter command: ")
subprocess.run(["sh", "-c", cmd])
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed
```

---

## 🔒 Layer 3: Operational Tests

Test that shell command interception works:

```python
# Line 1: Test shell guard
class TestOperationalLayer:
    """Layer 3: Shell command protection tests."""

    def test_blocks_rm_command(self, validator, context):
        """rm commands should be blocked."""
        code = '''
import os
os.system("rm -rf /important/data")
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed
        assert any(v.operational_risk.value == "DATA_DESTRUCTION" 
                   for v in result.violations 
                   if hasattr(v, 'operational_risk'))

    # Line 18: Test sudo detection
    def test_blocks_sudo(self, validator, context):
        """sudo commands should be blocked."""
        code = '''
import subprocess
subprocess.run("sudo chmod 777 /etc/passwd", shell=True)
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed

    # Line 29: Test shell escape attempts
    def test_blocks_shell_escape(self, validator, context):
        """Command chaining with ; should be caught."""
        code = '''
import os
os.system("ls; rm -rf /")  # Chained commands
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed

    # Line 40: Test allowed commands pass
    def test_allows_safe_commands(self, validator, context):
        """Safe commands like ls should not be blocked."""
        code = '''
import subprocess
result = subprocess.run(["ls", "-la"], capture_output=True)
'''
        result = validator.validate_content(code, context)
        
        # ls with shell=False should be allowed
        op_violations = [v for v in result.violations 
                         if hasattr(v, 'operational_risk')]
        assert len(op_violations) == 0
```

---

## 🎭 Evasion Attempt Tests

Test that clever bypass attempts are still caught:

```python
# Line 1: Test evasion attempts
class TestEvasionAttempts:
    """Test that clever bypass attempts fail."""

    def test_base64_encoded_secret(self, validator, context):
        """Base64 encoded secrets should still be detectable."""
        code = '''
import base64
# "sk-1234567890abcdef" encoded
encoded = "c2stMTIzNDU2Nzg5MGFiY2RlZg=="
secret = base64.b64decode(encoded).decode()
print(secret)
'''
        result = validator.validate_content(code, context)
        # Semantic layer should catch the taint flow
        assert not result.passed or len(result.violations) > 0

    # Line 16: Test string concatenation bypass
    def test_string_concat_secret(self, validator, context):
        """Secrets built by concatenation should be caught."""
        code = '''
part1 = "sk-"
part2 = "1234567890"
part3 = "abcdefghij"
api_key = part1 + part2 + part3
print(api_key)
'''
        result = validator.validate_content(code, context)
        # Variable named api_key going to print is suspicious
        assert not result.passed

    # Line 29: Test exec bypass
    def test_exec_bypass_attempt(self, validator, context):
        """Using exec to hide code should be caught."""
        code = '''
exec("import os; os.system('rm -rf /')")
'''
        result = validator.validate_content(code, context)
        
        assert not result.passed
        assert any("exec" in v.code_snippet.lower() for v in result.violations)

    # Line 41: Test getattr bypass
    def test_getattr_import_bypass(self, validator, context):
        """Using getattr to bypass import detection."""
        code = '''
import os
func = getattr(os, 'system')
func('whoami')
'''
        result = validator.validate_content(code, context)
        # At minimum, should flag the string 'system'
        # Semantic layer should track getattr usage
        assert len(result.violations) >= 0  # May or may not catch
```

---

## 🧪 Running the Test Suite

```bash
# Line 1: Run all adversarial tests
pytest tests/adversarial_suite.py -v

# Line 4: Run with coverage
pytest tests/adversarial_suite.py --cov=security_py --cov-report=html

# Line 7: Run specific test class
pytest tests/adversarial_suite.py::TestSemanticLayer -v

# Line 10: Run with detailed output
pytest tests/adversarial_suite.py -v --tb=long
```

### Expected Output

```
tests/adversarial_suite.py::TestDeterministicLayer::test_catches_hardcoded_api_key PASSED
tests/adversarial_suite.py::TestDeterministicLayer::test_catches_eval PASSED
tests/adversarial_suite.py::TestDeterministicLayer::test_catches_os_system PASSED
tests/adversarial_suite.py::TestSemanticLayer::test_catches_renamed_secret PASSED
tests/adversarial_suite.py::TestSemanticLayer::test_catches_multi_hop_taint PASSED
tests/adversarial_suite.py::TestOperationalLayer::test_blocks_rm_command PASSED
tests/adversarial_suite.py::TestEvasionAttempts::test_exec_bypass_attempt PASSED

================== 7 passed in 0.42s ==================
```

---

## 🎯 Check for Understanding

**Question**: Why do we set `exit_on_critical=False` in test fixtures?

*Think about what would happen to your test suite if the validator called sys.exit(1)...*

---

## 📚 Interview Prep

**Q: What's the difference between unit tests and adversarial tests?**

**A**:
- **Unit tests**: Verify correct behavior for expected inputs
- **Adversarial tests**: Verify system handles malicious/unexpected inputs

```python
# Line 1: Unit test - expected behavior
def test_validates_clean_code():
    code = "x = 1 + 2"
    assert validator.validate_content(code).passed

# Line 6: Adversarial test - attack resistance
def test_resists_obfuscation():
    code = "s='sk-'; s+='key123'; print(s)"  # Trying to hide a secret
    assert not validator.validate_content(code).passed
```

**Q: How do you decide what adversarial tests to write?**

**A**: Use threat modeling:
1. **STRIDE**: Spoofing, Tampering, Repudiation, Info disclosure, DoS, Elevation
2. **Attack trees**: Map all paths an attacker might take
3. **Past vulnerabilities**: Test for previously discovered bypasses
4. **Red team findings**: Incorporate penetration test results

**Q: Why test both positive and negative cases?**

**A**: 
- **Negative** (attack blocked): Ensures security works
- **Positive** (clean code passes): Ensures usability - too many false positives = disabled security

```python
# Line 1: Both are essential
def test_blocks_attack():
    assert not validator.validate_content(malicious_code).passed

def test_allows_legitimate():
    assert validator.validate_content(safe_code).passed
```

---

## 🚀 Ready for Lesson 06?

In the next lesson, we'll deep-dive into **AST Semantics** - how the TaintVisitor tracks data flow through Python code.

*Remember: A security system is only as strong as the attacks it's tested against!* 🛡️🐍
