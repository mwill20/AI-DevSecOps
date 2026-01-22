# 🎓 Lesson 02: The ScanEngine - Deterministic Layer

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- How the ScanEngine performs high-speed pattern matching
- Line number calculation from regex matches
- Directory scanning with smart filtering

---

## 🔍 The Deterministic Layer

The ScanEngine is **Layer 1** of our 3-layer security mesh. It uses compiled regex patterns for fast, deterministic scanning.

```
┌─────────────────────────────────────────────────────┐
│  Layer 1: Deterministic (ScanEngine)                │
│  ┌─────────────┐    ┌─────────────┐                │
│  │ Python Code │ → │ Regex Match │ → Violations   │
│  └─────────────┘    └─────────────┘                │
└─────────────────────────────────────────────────────┘
```

---

## 🐍 ScanEngine Implementation

```python
# Line 1: src/security_py/core/scan_engine.py
from pathlib import Path
from typing import Iterator
from ..types.violations import SecurityViolation, Severity, ScanContext

class ScanEngine:
    """
    Deterministic Layer: High-speed pattern matching for Python code.
    """

    # Line 11: Constructor accepts pattern tuple
    def __init__(self, patterns: tuple[SecurityPattern, ...] = OWASP_LLM_PATTERNS):
        self._patterns = patterns

    # Line 15: Main scanning method
    def scan_content(
        self,
        content: str,
        file_path: str,
        context: ScanContext,
    ) -> list[SecurityViolation]:
        """Scan source code content for pattern matches."""
        violations: list[SecurityViolation] = []
        lines = content.splitlines()

        # Line 26: Iterate through all patterns
        for pattern in self._patterns:
            # Line 28: Find all matches using compiled regex
            for match in pattern.pattern.finditer(content):
                # Line 30: Calculate line number from character position
                line_num = content[:match.start()].count('\n') + 1
                
                # Line 33: Extract code snippet
                if 0 < line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group(0)[:80]

                # Line 39: Create violation record
                violation = SecurityViolation(
                    severity=pattern.severity,
                    category=pattern.category,
                    title=f"{pattern.category}: {pattern.id}",
                    description=pattern.description,
                    file=file_path,
                    line=line_num,
                    code_snippet=code_snippet,
                    recommendation=pattern.recommendation,
                    cwe_reference=pattern.cwe_reference,
                    agent_source=context.agent_source,
                )
                violations.append(violation)

        return violations
```

### Line Number Calculation

```python
# Line 1: How we calculate line numbers from match position
content = '''
api_key = "secret123"
password = "hunter2"
'''

# Line 7: Find a match
import re
pattern = re.compile(r'password\s*=')
match = pattern.search(content)

# Line 12: Count newlines before match = line number
if match:
    line_num = content[:match.start()].count('\n') + 1
    print(f"Found at line {line_num}")  # Line 3
```

---

## 📁 File and Directory Scanning

```python
# Line 1: Scan a single file
def scan_file(self, file_path: Path, context: ScanContext) -> list[SecurityViolation]:
    try:
        content = file_path.read_text(encoding="utf-8")
        return self.scan_content(content, str(file_path), context)
    except (OSError, UnicodeDecodeError) as e:
        # Line 8: Return error as violation
        return [
            SecurityViolation(
                severity=Severity.LOW,
                category="SCAN_ERROR",
                title="File scan failed",
                description=f"Could not scan: {e}",
                file=str(file_path),
                line=0,
                code_snippet="",
                recommendation="Check file encoding and permissions",
            )
        ]

# Line 22: Scan directory with generator (memory efficient)
def scan_directory(
    self,
    directory: Path,
    context: ScanContext,
    extensions: tuple[str, ...] = (".py",),
) -> Iterator[SecurityViolation]:
    """Yields violations as they're found."""
    for file_path in directory.rglob("*"):
        # Line 32: Filter by extension
        if file_path.suffix not in extensions:
            continue
        if not file_path.is_file():
            continue
        
        # Line 38: Skip non-source directories
        skip_dirs = ("venv", ".venv", "node_modules", "__pycache__", ".git")
        if any(part in file_path.parts for part in skip_dirs):
            continue
        
        # Line 43: Yield violations one by one
        for violation in self.scan_file(file_path, context):
            yield violation
```

### Why Use a Generator?

```python
# Line 1: Generator approach - memory efficient
for violation in engine.scan_directory(path, context):
    print(violation)  # Process one at a time
    # Previous violations can be garbage collected

# Line 6: List approach - loads all into memory
violations = list(engine.scan_directory(path, context))
# All violations in memory at once - could be huge!

# Line 10: Best practice for large codebases:
# Use generator, convert to list only when needed
```

---

## 🎯 Practical Example

```python
# Line 1: Complete scanning example
from pathlib import Path
from security_py.core import ScanEngine
from security_py.types import ScanContext

# Line 6: Create context
context = ScanContext(
    project_path="/my/project",
    phase="BUILD",
    developer_id="dev-123",
    agent_source="windsurf",
)

# Line 14: Create engine with default patterns
engine = ScanEngine()

# Line 17: Scan a single file
violations = engine.scan_file(Path("app.py"), context)
print(f"Found {len(violations)} violations")

# Line 21: Scan entire directory
for v in engine.scan_directory(Path("src/"), context):
    print(f"[{v.severity.value}] {v.file}:{v.line} - {v.description}")
```

### Output Example

```
🔍 Scanning src/
[CRITICAL] src/config.py:15 - Hardcoded sensitive information detected
[CRITICAL] src/utils.py:42 - Use of eval() - arbitrary code execution risk
[HIGH] src/api.py:28 - Subprocess with shell=True - command injection risk
Found 3 violations
```

---

## 🔧 Adding Custom Patterns

```python
# Line 1: Add a custom pattern for your organization
from security_py.core import ScanEngine, SecurityPattern
from security_py.types import Severity

# Line 5: Create engine with default patterns
engine = ScanEngine()

# Line 8: Add custom pattern
engine.add_pattern(
    SecurityPattern.compile(
        id="ORG-001",
        category="ORGANIZATION",
        severity=Severity.HIGH,
        pattern=r'import\s+forbidden_lib',
        description="Forbidden library import detected",
        recommendation="Use approved_lib instead",
        cwe_reference="CWE-829",
    )
)

# Line 21: Now scanning will include your pattern
violations = engine.scan_content(
    "import forbidden_lib",
    "app.py",
    context,
)
# Returns: 1 violation
```

---

## 🎯 Check for Understanding

**Question**: Why do we use `pattern.pattern.finditer(content)` instead of `re.findall()`?

*Think about what information each method returns...*

---

## 📚 Interview Prep

**Q: What's the time complexity of regex pattern matching?**

**A**: In the worst case, regex can be O(2^n) for pathological patterns with backtracking. However:
- Our patterns use anchored, non-backtracking constructs
- Python's `re` module uses an NFA (Non-deterministic Finite Automaton)
- Practical performance is O(n*m) where n=content length, m=pattern count

```python
# Line 1: Avoid backtracking patterns like:
# pattern = r'(a+)+b'  # Catastrophic backtracking!

# Line 4: Use efficient patterns:
# pattern = r'api_key\s*=\s*["\'][^"\']+["\']'  # Linear time
```

**Q: Why encode files as UTF-8 explicitly?**

**A**: Python 3 defaults to UTF-8 on most systems, but:
1. Windows may default to cp1252 or other encodings
2. Explicit encoding prevents platform-dependent bugs
3. UTF-8 handles all Unicode characters (international code)

```python
# Line 1: Always specify encoding
content = file_path.read_text(encoding="utf-8")

# Line 4: Handle encoding errors gracefully
try:
    content = file_path.read_text(encoding="utf-8")
except UnicodeDecodeError:
    content = file_path.read_text(encoding="latin-1", errors="replace")
```

**Q: How would you parallelize directory scanning?**

**A**: Use `concurrent.futures` for parallel file processing:

```python
# Line 1: Parallel scanning example
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

def scan_file_wrapper(file_path: Path) -> list[SecurityViolation]:
    engine = ScanEngine()  # Create per-process
    return engine.scan_file(file_path, context)

# Line 9: Parallel execution
files = list(Path("src/").rglob("*.py"))
with ProcessPoolExecutor(max_workers=4) as executor:
    results = executor.map(scan_file_wrapper, files)
    all_violations = [v for sublist in results for v in sublist]
```

---

## 🚀 Ready for Lesson 03?

In the next lesson, we'll see how the **SecurityValidator** orchestrates all three layers for comprehensive security scanning.

*Remember: Speed matters for developer experience - a slow scanner gets disabled!* 🛡️🐍
