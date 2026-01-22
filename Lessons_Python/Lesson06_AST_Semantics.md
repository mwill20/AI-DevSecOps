# 🎓 Lesson 06: AST Semantics - The TaintVisitor

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- How Python's `ast` module parses code into trees
- How TaintVisitor tracks data flow from sources to sinks
- Why AST analysis catches what regex cannot

---

## 🌳 What is an Abstract Syntax Tree?

The AST is a tree representation of code structure:

```python
# Line 1: Original code
x = 1 + 2

# Line 4: Becomes this tree:
#
#        Assign
#       /      \
#    Name      BinOp
#    (x)      /  |  \
#           Num Add Num
#           (1)     (2)
```

```python
# Line 1: View the AST for any code
import ast

code = '''
api_key = "sk-secret123"
print(api_key)
'''

tree = ast.parse(code)
print(ast.dump(tree, indent=2))

# Line 12: Output:
# Module(
#   body=[
#     Assign(
#       targets=[Name(id='api_key')],
#       value=Constant(value='sk-secret123')
#     ),
#     Expr(
#       value=Call(
#         func=Name(id='print'),
#         args=[Name(id='api_key')]
#       )
#     )
#   ]
# )
```

---

## 🔍 Sources and Sinks

Taint analysis tracks data from **sources** (where sensitive data enters) to **sinks** (where data exits):

```python
# Line 1: Data Sources (where sensitive data comes from)
SOURCE_FUNCTIONS = {
    "input": DataSourceType.USER_INPUT,      # User input
    "open": DataSourceType.FILE,             # File contents
}

SOURCE_ATTRIBUTES = {
    ("os", "environ"): DataSourceType.ENVIRONMENT,  # Env vars
    ("os", "getenv"): DataSourceType.ENVIRONMENT,
}

# Line 12: Data Sinks (where data should not go unfiltered)
SINK_FUNCTIONS = {
    "print": DataSinkType.CONSOLE,           # Console output
    "logging.info": DataSinkType.LOG_FILE,   # Log files
}

SINK_ATTRIBUTES = {
    ("subprocess", "run"): DataSinkType.SUBPROCESS,    # Shell
    ("requests", "post"): DataSinkType.EXTERNAL_API,   # Network
}
```

---

## 🐍 TaintVisitor Implementation

```python
# Line 1: src/security_py/core/taint_visitor.py
import ast
from dataclasses import dataclass, field

@dataclass
class TaintRecord:
    """Tracks a tainted variable."""
    variable: str
    source: DataSource
    taint_path: list[str] = field(default_factory=list)

class TaintVisitor(ast.NodeVisitor):
    """
    AST visitor that performs taint analysis on Python source.
    
    Tracks data flow from sensitive sources to dangerous sinks.
    """

    def __init__(self):
        self._sources: dict[str, DataSource] = {}
        self._sinks: list[DataSink] = []
        self._tainted: dict[str, TaintRecord] = {}

    # Line 24: Analyze source code
    def analyze(
        self,
        source_code: str,
        context: ScanContext,
        file_path: str = "<string>",
    ) -> list[SemanticViolation]:
        # Reset state
        self._sources.clear()
        self._sinks.clear()
        self._tainted.clear()

        # Line 36: Parse code into AST
        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError as e:
            return [SemanticViolation(...)]  # Report parse error

        # Line 42: Phase 1 - Identify sources and sinks
        self.visit(tree)

        # Line 45: Phase 2 - Track assignments
        self._track_assignments(tree)

        # Line 48: Phase 3 - Find tainted flows
        return self._find_tainted_flows()
```

---

## 👁️ Visiting AST Nodes

```python
# Line 1: Visit function calls to find sources and sinks
def visit_Call(self, node: ast.Call) -> None:
    """Visit function calls to identify sources and sinks."""
    func_name = self._get_call_name(node)

    # Line 6: Check for source functions (input, open)
    if func_name in self.SOURCE_FUNCTIONS:
        source = DataSource(
            source_type=self.SOURCE_FUNCTIONS[func_name],
            name=func_name,
            line=node.lineno,
            col=node.col_offset,
            sensitivity=Severity.HIGH,
        )
        self._sources[f"call_{node.lineno}"] = source

    # Line 18: Check for sink functions (print, logging)
    if func_name in self.SINK_FUNCTIONS:
        args = tuple(ast.unparse(arg) for arg in node.args)
        sink = DataSink(
            sink_type=self.SINK_FUNCTIONS[func_name],
            line=node.lineno,
            context=ast.unparse(node)[:100],
            args=args,
        )
        self._sinks.append(sink)

    # Line 29: Continue visiting child nodes
    self.generic_visit(node)

# Line 32: Visit assignments to detect hardcoded secrets
def visit_Assign(self, node: ast.Assign) -> None:
    """Detect hardcoded secrets in assignments."""
    # Check if assigning a string literal
    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
        value = node.value.value
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                # Line 44: Check if variable name suggests a secret
                secret_patterns = ("api_key", "secret", "password", "token")
                if any(p in var_name for p in secret_patterns):
                    # Check if value looks like a secret
                    if len(value) >= 10:
                        source = DataSource(
                            source_type=DataSourceType.HARDCODED,
                            name=target.id,
                            line=node.lineno,
                            sensitivity=Severity.CRITICAL,
                        )
                        self._sources[target.id] = source
                        self._tainted[target.id] = TaintRecord(
                            variable=target.id,
                            source=source,
                            taint_path=[target.id],
                        )

    self.generic_visit(node)
```

---

## 🔄 Tracking Taint Propagation

```python
# Line 1: Track how taint spreads through assignments
def _track_assignments(self, tree: ast.AST) -> None:
    """Track variable assignments to propagate taint."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # Line 9: Get all variable names used in RHS
                    rhs_vars = self._extract_names(node.value)
                    
                    # Line 12: Check if any RHS var is tainted
                    for var in rhs_vars:
                        if var in self._tainted:
                            # Propagate taint to new variable
                            original = self._tainted[var]
                            self._tainted[target.id] = TaintRecord(
                                variable=target.id,
                                source=original.source,
                                taint_path=[
                                    *original.taint_path,
                                    f"→ {target.id}"
                                ],
                            )

# Line 26: Example of taint propagation:
#
# api_key = "sk-secret"    # Tainted: {api_key}
# x = api_key              # Tainted: {api_key, x}
# y = x                    # Tainted: {api_key, x, y}
# print(y)                 # VIOLATION! y is tainted
```

---

## 🚨 Finding Tainted Flows

```python
# Line 1: Detect when tainted data reaches a sink
def _find_tainted_flows(self) -> list[SemanticViolation]:
    """Find tainted data flows from sources to sinks."""
    violations: list[SemanticViolation] = []

    for sink in self._sinks:
        for arg in sink.args:
            # Line 8: Check if any tainted variable appears in sink arg
            for var_name, taint in self._tainted.items():
                if var_name in arg:
                    # Line 11: Create violation for tainted flow
                    tainted_data = TaintedData(
                        source_type=taint.source.source_type,
                        source_name=taint.source.name,
                        source_line=taint.source.line,
                        variable=var_name,
                        taint_path=tuple(taint.taint_path),
                        severity=self._calculate_severity(taint.source, sink),
                        data_type="SECRET",
                    )

                    violation = SemanticViolation(
                        severity=tainted_data.severity,
                        category="SEMANTIC_TAINT",
                        title="Tainted Data Flow Detected",
                        description=(
                            f"Sensitive data from {taint.source.source_type.value} "
                            f"flows to {sink.sink_type.value}"
                        ),
                        file=self._current_file,
                        line=sink.line,
                        code_snippet=sink.context[:80],
                        recommendation="Sanitize or mask sensitive data",
                        taint_flow=(tainted_data,),
                        sink_type=sink.sink_type,
                        semantic_type=SemanticType.TAINTED_DATA_FLOW,
                    )
                    violations.append(violation)

    return violations
```

---

## 📊 Complete Example

```python
# Line 1: Example code to analyze
code = '''
import os

api_key = os.environ.get("API_KEY")  # Source: ENVIRONMENT
secret = api_key                      # Taint propagates
masked = "***"
print(f"Using key: {secret}")         # Sink: CONSOLE - VIOLATION!
print(f"Masked: {masked}")            # Safe - not tainted
'''

# Line 11: Analysis result:
#
# Sources found:
#   - os.environ.get("API_KEY") at line 4 (ENVIRONMENT)
#
# Taint propagation:
#   - api_key <- os.environ.get (line 4)
#   - secret <- api_key (line 5)
#
# Sinks found:
#   - print(f"Using key: {secret}") at line 7
#   - print(f"Masked: {masked}") at line 8
#
# Violations:
#   - Line 7: Tainted 'secret' flows to CONSOLE sink
#     Path: os.environ.get → api_key → secret → print()
```

---

## 🎯 Check for Understanding

**Question**: Why can't regex alone catch renamed secrets like `x = api_key; print(x)`?

*Think about what information regex has access to vs. what AST provides...*

---

## 📚 Interview Prep

**Q: What's the difference between `ast.parse()` and `exec()`?**

**A**: Completely different purposes!
- `ast.parse()`: Analyzes code structure, never executes it
- `exec()`: Executes code - extremely dangerous with untrusted input

```python
# Line 1: ast.parse is safe - just builds a tree
tree = ast.parse("import os; os.system('rm -rf /')")
# Nothing happens - code is NOT executed

# Line 5: exec is dangerous - runs the code
exec("import os; os.system('rm -rf /')")
# DISASTER - code IS executed!
```

**Q: How do you handle AST analysis for incomplete code?**

**A**: Incomplete code causes `SyntaxError`. Handle gracefully:

```python
# Line 1: Graceful handling
try:
    tree = ast.parse(code)
except SyntaxError as e:
    return [
        SemanticViolation(
            severity=Severity.LOW,
            title="Parse Error",
            description=f"Could not analyze: {e.msg}",
            line=e.lineno or 0,
        )
    ]
```

**Q: What are the limitations of static taint analysis?**

**A**: Static analysis can't handle:
1. **Dynamic attribute access**: `getattr(obj, user_input)`
2. **Eval/exec**: `eval(f"x = {value}")`
3. **External calls**: What does `third_party.process(data)` return?
4. **Aliasing**: `d = {"key": secret}; print(d["key"])`

```python
# Line 1: These are hard to track statically:
config = {}
config["api_key"] = secret  # Dict aliasing
print(config["api_key"])    # Hard to track through dict
```

---

## 🚀 Ready for Lesson 07?

In the next lesson, we'll explore the **Policy Engine** - enforcing business rules and compliance requirements.

*Remember: AST gives us code understanding - regex only gives us text matching!* 🛡️🐍
