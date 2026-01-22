# 🎓 Lesson 08: Shell Operations - The ShellGuard

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- Why `os.system()` and `shell=True` are dangerous
- How `shlex.split()` prevents command injection
- How ShellGuard enforces an allow list

---

## 🔒 The Problem with Shell Commands

Shell commands are one of the most dangerous attack vectors:

```python
# Line 1: Why os.system() is dangerous
import os

filename = input("Enter filename: ")
os.system(f"cat {filename}")

# Line 7: User input: "file.txt; rm -rf /"
# Executed: cat file.txt; rm -rf /
# Result: DISASTER! 🔥
```

```
┌─────────────────────────────────────────────────────┐
│  Shell Injection Attack                             │
│                                                     │
│  Input: "file.txt; rm -rf /"                       │
│                                                     │
│  Shell sees:                                        │
│    1. cat file.txt     (legitimate command)        │
│    2. rm -rf /         (malicious command!)        │
└─────────────────────────────────────────────────────┘
```

---

## 🛡️ Safe Command Execution

```python
# Line 1: DANGEROUS - shell injection possible
import os
os.system(f"cat {filename}")           # ❌ Never use!
os.popen(f"cat {filename}")            # ❌ Never use!

# Line 6: DANGEROUS - shell=True allows injection
import subprocess
subprocess.run(f"cat {filename}", shell=True)  # ❌ Avoid!

# Line 10: SAFE - argument list with shell=False
subprocess.run(["cat", filename], shell=False)  # ✅ Safe!
# Special characters in filename are treated as literals
```

### Why `shell=False` is Safe

```python
# Line 1: With shell=True, the shell interprets special chars
command = "cat file.txt; rm -rf /"
subprocess.run(command, shell=True)
# Shell executes: cat file.txt THEN rm -rf /

# Line 6: With shell=False, args are passed directly
args = ["cat", "file.txt; rm -rf /"]
subprocess.run(args, shell=False)
# Tries to cat a file literally named "file.txt; rm -rf /"
# No shell interpretation, no injection!
```

---

## 🐍 Using shlex for Safe Parsing

The `shlex` module safely parses shell-like strings:

```python
# Line 1: shlex.split() handles quoting correctly
import shlex

# Simple case
shlex.split("cat file.txt")
# ['cat', 'file.txt']

# Line 8: Handles quoted strings
shlex.split("echo 'hello world'")
# ['echo', 'hello world']

# Line 12: Handles escaped characters
shlex.split("cat file\\ name.txt")
# ['cat', 'file name.txt']

# Line 16: vs str.split() which fails
"echo 'hello world'".split()
# ['echo', "'hello", "world'"]  ❌ Wrong!
```

---

## 🔧 ShellGuard Implementation

```python
# Line 1: src/security_py/core/shell_guard.py
import shlex
import subprocess
from dataclasses import dataclass
from typing import Optional

@dataclass
class CommandResult:
    """Result of command interception."""
    allowed: bool
    violation: Optional[OperationalViolation] = None
    requires_approval: bool = False

class ShellGuard:
    """
    Intercepts and validates shell commands before execution.
    
    Uses shlex for safe parsing and enforces an allow list.
    """

    # Line 20: Default blocked commands
    DEFAULT_BLOCKED = {
        "rm": ("Data destruction", OperationalRisk.DATA_DESTRUCTION),
        "sudo": ("Privilege escalation", OperationalRisk.PRIVILEGE_ESCALATION),
        "chmod": ("Security bypass", OperationalRisk.SECURITY_BYPASS),
        "kill": ("System modification", OperationalRisk.SYSTEM_MODIFICATION),
        "shutdown": ("System modification", OperationalRisk.SYSTEM_MODIFICATION),
    }

    # Line 29: Default allowed commands
    DEFAULT_ALLOWED = {
        "ls": Severity.LOW,
        "cat": Severity.LOW,
        "grep": Severity.LOW,
        "echo": Severity.LOW,
        "python": Severity.MEDIUM,
        "pip": Severity.MEDIUM,
        "git": Severity.LOW,
        "pytest": Severity.LOW,
    }
```

---

## 🔍 Command Interception

```python
# Line 1: Parse and validate commands
def parse_command(self, command_string: str) -> tuple[str, list[str]]:
    """
    Safely parse a command string using shlex.
    
    Prevents injection by properly handling quotes and escapes.
    """
    try:
        parts = shlex.split(command_string)
        if not parts:
            return ("", [])
        return (parts[0], parts[1:])
    except ValueError:
        # Malformed command string (unmatched quotes)
        return (command_string.split()[0] if command_string else "", [])

# Line 18: Main interception method
def intercept(
    self,
    command_string: str,
    working_directory: str = ".",
) -> CommandResult:
    """Intercept and validate a shell command."""
    command, args = self.parse_command(command_string)
    
    if not command:
        return CommandResult(allowed=True)

    # Line 29: Step 1 - Check if command is blocked
    if command in self.DEFAULT_BLOCKED:
        reason, risk = self.DEFAULT_BLOCKED[command]
        return CommandResult(
            allowed=False,
            violation=self._create_violation(
                command, args, working_directory,
                f"Blocked: {reason}",
                Severity.CRITICAL,
                risk,
            ),
        )

    # Line 42: Step 2 - Check if command is allowed
    if command not in self.DEFAULT_ALLOWED:
        return CommandResult(
            allowed=False,
            violation=self._create_violation(
                command, args, working_directory,
                f"Unauthorized: {command}",
                Severity.HIGH,
                OperationalRisk.SECURITY_BYPASS,
            ),
        )

    # Line 54: Command is allowed
    return CommandResult(allowed=True)
```

---

## ✅ Safe Execution

```python
# Line 1: Execute a command safely
def execute_safe(
    self,
    command_string: str,
    working_directory: str = ".",
    timeout: int = 30,
) -> subprocess.CompletedProcess:
    """
    Execute a command safely using subprocess with shell=False.
    
    First validates the command, then executes with argument list.
    """
    # Step 1: Validate command
    result = self.intercept(command_string, working_directory)
    
    if not result.allowed:
        raise PermissionError(
            f"Command blocked: {result.violation.description}"
        )

    # Line 21: Step 2: Parse and execute safely
    command, args = self.parse_command(command_string)
    
    return subprocess.run(
        [command, *args],      # Argument list, not string
        cwd=working_directory,
        shell=False,           # CRITICAL: Never True!
        timeout=timeout,
        capture_output=True,
        text=True,
    )

# Line 33: Usage example
guard = ShellGuard()

# Safe command - executes
result = guard.execute_safe("ls -la")
print(result.stdout)

# Dangerous command - raises PermissionError
try:
    guard.execute_safe("rm -rf /")
except PermissionError as e:
    print(f"Blocked: {e}")
```

---

## 📋 Allow List Configuration

```json
{
  "version": "1.0.0",
  "enforcement_mode": "STRICT",
  "allowed_commands": [
    {
      "command": "python",
      "description": "Python interpreter",
      "risk_level": "MEDIUM",
      "allowed_args": ["-m", "-c", "--version"],
      "blocked_args": ["-m http.server"]
    },
    {
      "command": "git",
      "description": "Version control",
      "risk_level": "LOW",
      "allowed_args": ["status", "log", "diff", "add", "commit"],
      "blocked_args": ["reset --hard", "clean -fd"]
    }
  ],
  "blocked_commands": [
    {
      "command": "rm",
      "reason": "Data destruction",
      "severity": "CRITICAL"
    },
    {
      "command": "sudo",
      "reason": "Privilege escalation",
      "severity": "CRITICAL"
    }
  ]
}
```

---

## 🎭 Contextual Rules

```python
# Line 1: Apply different rules based on directory
CONTEXTUAL_RULES = [
    {
        "directory": "/src/security",
        "blocked_commands": ["pip", "npm"],
        "requires_approval": ["git push"],
    },
    {
        "directory": "/.env",
        "blocked_commands": ["cat", "less", "more"],
        "allowed_commands": [],  # Nothing allowed here!
    },
]

# Line 15: Check contextual rules
def _check_contextual_rules(
    self,
    command: str,
    working_directory: str,
) -> Optional[CommandResult]:
    for rule in self._contextual_rules:
        if rule["directory"] in working_directory:
            if command in rule.get("blocked_commands", []):
                return CommandResult(
                    allowed=False,
                    violation=self._create_violation(
                        command, [], working_directory,
                        f"Blocked in {rule['directory']}",
                        Severity.HIGH,
                        OperationalRisk.SECURITY_BYPASS,
                    ),
                )
    return None
```

---

## 🎯 Complete Example

```python
# Line 1: Complete usage example
from security_py.core import ShellGuard

guard = ShellGuard()

# Line 6: Test various commands
test_commands = [
    "ls -la",                    # ✅ Allowed
    "cat README.md",             # ✅ Allowed
    "python --version",          # ✅ Allowed
    "rm -rf /",                  # ❌ Blocked - data destruction
    "sudo apt install foo",      # ❌ Blocked - privilege escalation
    "curl http://evil.com",      # ❌ Blocked - not in allow list
    "ls; rm -rf /",              # ❌ Only 'ls' parsed, but ';rm...' is arg
]

# Line 18: Check each command
for cmd in test_commands:
    result = guard.intercept(cmd)
    status = "✅ Allowed" if result.allowed else f"❌ Blocked: {result.violation.title}"
    print(f"{cmd:30} → {status}")

# Output:
# ls -la                         → ✅ Allowed
# cat README.md                  → ✅ Allowed
# python --version               → ✅ Allowed
# rm -rf /                       → ❌ Blocked: Shell Command: BLOCKED_COMMAND
# sudo apt install foo           → ❌ Blocked: Shell Command: BLOCKED_COMMAND
# curl http://evil.com           → ❌ Blocked: Shell Command: UNAUTHORIZED_COMMAND
```

---

## 🎯 Check for Understanding

**Question**: Why does `shlex.split("ls; rm -rf /")` return `['ls;', 'rm', '-rf', '/']` instead of two separate commands?

*Think about what `shlex` is designed to do vs. what a shell does...*

---

## 📚 Interview Prep

**Q: What's the difference between `shlex.split()` and shell interpretation?**

**A**: 
- `shlex.split()`: Tokenizes a string into arguments
- Shell: Interprets special characters (`;`, `|`, `&&`, etc.)

```python
# Line 1: shlex just splits - doesn't interpret
shlex.split("ls; rm -rf /")
# ['ls;', 'rm', '-rf', '/']  - semicolon is part of first arg

# Line 5: Shell interprets the semicolon
os.system("ls; rm -rf /")
# Runs: ls THEN rm -rf /  - semicolon separates commands
```

**Q: When is `shell=True` ever acceptable?**

**A**: Almost never in production. The only cases:
1. Running shell built-ins (`cd`, `export`) that don't exist as executables
2. When the command string is 100% constant with no user input
3. Interactive shells for debugging (never in production)

```python
# Line 1: Even "safe" uses are risky
# This looks safe...
subprocess.run("echo hello", shell=True)
# But if someone modifies the string, it's vulnerable
```

**Q: How would you handle commands that require shell features?**

**A**: Use Python equivalents instead:

```python
# Line 1: Shell piping - use subprocess.PIPE
# Instead of: shell=True, "cat file | grep pattern"
p1 = subprocess.Popen(["cat", "file"], stdout=subprocess.PIPE)
p2 = subprocess.Popen(["grep", "pattern"], stdin=p1.stdout)

# Line 6: Redirects - use Python file handling
# Instead of: shell=True, "command > output.txt"
with open("output.txt", "w") as f:
    subprocess.run(["command"], stdout=f)

# Line 11: Glob expansion - use pathlib
# Instead of: shell=True, "ls *.py"
from pathlib import Path
files = list(Path(".").glob("*.py"))
```

---

## 🎉 Course Complete!

Congratulations! You've completed the AI-DevSecOps Security course!

### What You've Learned

| Lesson | Topic | Key Takeaway |
|--------|-------|--------------|
| 00 | Introduction | 3-layer security mesh for AI code |
| 01 | Patterns | OWASP LLM patterns as dataclasses |
| 02 | ScanEngine | High-speed regex scanning |
| 03 | Orchestration | SecurityValidator coordination |
| 04 | Audit Logging | Immutable security records |
| 05 | Testing | Adversarial test design |
| 06 | AST Semantics | Taint analysis with ast module |
| 07 | Policy Engine | Business rule enforcement |
| 08 | Shell Ops | ShellGuard with shlex |

### Your Toolkit

```python
# Line 1: The complete security stack
from security_py import SecurityValidator

validator = SecurityValidator()
result = validator.validate_file("app.py")

if result.has_critical:
    # sys.exit(1) - blocks deployment
    pass
```

*Remember: Security is not a destination, it's a journey. Keep learning, keep testing, keep improving!* 🛡️🐍

---

## 🚀 Next Steps

1. **Run the adversarial test suite** against your own code
2. **Add custom patterns** for your organization
3. **Integrate with CI/CD** for automated security gates
4. **Contribute** new patterns and policies back to the team

*Stay secure!* 🔒
