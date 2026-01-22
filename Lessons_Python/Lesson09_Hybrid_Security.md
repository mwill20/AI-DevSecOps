# 🎓 Lesson 09: Hybrid Security - Merging AST Logic with LLM Intuition

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- How to combine deterministic AST analysis with LLM reasoning
- Pydantic guardrails for constraining LLM outputs
- Fallback strategies when LLM confidence is low

---

## 🧠 The Hybrid Architecture

Neither pure rule-based nor pure AI systems are sufficient alone:

```
┌─────────────────────────────────────────────────────────────────┐
│                    HYBRID SECURITY MESH                          │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ AST Analysis │    │  LLM Auditor │    │ Policy Engine│      │
│  │ (Determinism)│    │ (Intuition)  │    │ (Final Say)  │      │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘      │
│         │                   │                   │               │
│         └───────────────────┼───────────────────┘               │
│                             ▼                                    │
│                   ┌─────────────────┐                           │
│                   │ AUDIT DECISION  │                           │
│                   │ APPROVE/REJECT  │                           │
│                   └─────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘

Why Hybrid?
- AST: Fast, deterministic, no false positives on known patterns
- LLM: Contextual understanding, catches novel vulnerabilities
- Policy: Business rules override both when needed
```

---

## 🐍 Pydantic Guardrails

```python
# Line 1: src/security_py/core/ai_auditor.py
from pydantic import BaseModel, Field, ValidationError

class LLMVulnerabilityResponse(BaseModel):
    """
    Strict schema for LLM vulnerability analysis.
    
    The LLM MUST output JSON matching this exact structure.
    Non-compliant outputs are rejected and fallback to AST.
    """
    vulnerability: bool = Field(
        description="Whether the code contains a vulnerability"
    )
    reasoning: str = Field(
        min_length=10,
        max_length=1000,
        description="Detailed explanation of the analysis"
    )
    remediation: str = Field(
        min_length=10,
        max_length=500,
        description="Recommended fix for the vulnerability"
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence level (0.0-1.0)"
    )
    severity: str = Field(
        default="MEDIUM",
        pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$",
        description="Severity if vulnerability exists"
    )

# Line 35: Why Pydantic?
# 1. Type validation at runtime
# 2. Automatic JSON serialization/deserialization
# 3. Clear error messages on validation failure
# 4. Field constraints (min/max length, patterns, ranges)
```

---

## 🔌 Ollama Integration

```python
# Line 1: Connecting to DeepSeek-R1 via Ollama
import httpx

class OllamaClient:
    """Client for local LLM inference via Ollama."""
    
    DEFAULT_MODEL = "deepseek-r1:14b"
    DEFAULT_BASE_URL = "http://localhost:11434"
    
    def __init__(self, model: str = DEFAULT_MODEL):
        self.model = model
        self._client = httpx.Client(timeout=60.0)
    
    # Line 14: Query the LLM
    def generate(self, prompt: str, system: str = None) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",  # Force JSON output
        }
        if system:
            payload["system"] = system
        
        response = self._client.post(
            f"{self.DEFAULT_BASE_URL}/api/generate",
            json=payload,
        )
        response.raise_for_status()
        return response.json().get("response", "")
    
    # Line 31: Check availability
    def is_available(self) -> bool:
        try:
            resp = self._client.get(f"{self.DEFAULT_BASE_URL}/api/tags")
            return resp.status_code == 200
        except httpx.HTTPError:
            return False
```

---

## 🛡️ The AI Auditor

```python
# Line 1: Hybrid auditor combining AST + LLM
class AIAuditor:
    """
    Hybrid security auditor.
    
    Architecture:
    1. AST analysis provides deterministic baseline
    2. LLM provides contextual reasoning
    3. Pydantic validates LLM output
    4. Policy engine makes final decision
    """
    
    SYSTEM_PROMPT = """You are a security auditor analyzing Python code.
You MUST respond with valid JSON matching this schema:
{
  "vulnerability": boolean,
  "reasoning": "explanation (10-1000 chars)",
  "remediation": "fix (10-500 chars)",
  "confidence": float 0.0-1.0,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
}"""

    CONFIDENCE_THRESHOLD = 0.7
    
    # Line 25: Main audit method
    def audit(
        self,
        code: str,
        ast_violations: list[SecurityViolation],
        context: ScanContext,
    ) -> AuditResult:
        """Perform hybrid security audit."""
        
        # Step 1: Check LLM availability
        if not self.llm_available:
            return self._fallback_to_ast(
                ast_violations,
                reason="LLM unavailable"
            )
        
        # Step 2: Query LLM
        try:
            llm_response = self._query_llm(code)
        except Exception as e:
            return self._fallback_to_ast(
                ast_violations,
                reason=f"LLM query failed: {e}"
            )
        
        # Step 3: Validate with Pydantic
        try:
            validated = LLMVulnerabilityResponse.model_validate_json(llm_response)
        except ValidationError as e:
            return self._fallback_to_ast(
                ast_violations,
                reason=f"Schema validation failed: {e}"
            )
        
        # Step 4: Check confidence threshold
        if validated.confidence < self.CONFIDENCE_THRESHOLD:
            return self._fallback_to_ast(
                ast_violations,
                reason=f"Low confidence: {validated.confidence:.2f}"
            )
        
        # Step 5: Make final decision
        return self._make_decision(validated, ast_violations)
```

---

## 🔄 The Validation Loop

```python
# Line 1: Decision logic with AST override
def _make_decision(
    self,
    llm: LLMVulnerabilityResponse,
    ast_violations: list[SecurityViolation],
) -> AuditResult:
    """
    Make final audit decision.
    
    Rules:
    1. If LLM says vulnerable → REJECT
    2. If AST found CRITICAL but LLM missed → Trust AST, REJECT
    3. If AST found non-critical but LLM says safe → MANUAL_REVIEW
    4. If both agree safe → APPROVE
    """
    
    # Line 17: LLM found vulnerability
    if llm.vulnerability:
        return AuditResult(
            decision=AuditDecision.REJECT,
            llm_response=llm,
            ast_violations=ast_violations,
            reasoning=llm.reasoning,
            confidence=llm.confidence,
        )
    
    # Line 27: AST found CRITICAL that LLM missed
    critical = [v for v in ast_violations if v.severity == Severity.CRITICAL]
    if critical:
        return AuditResult(
            decision=AuditDecision.REJECT,  # Trust AST for CRITICAL
            llm_response=llm,
            ast_violations=ast_violations,
            reasoning="AST detected CRITICAL violations LLM missed",
            confidence=1.0,  # Deterministic = 100% confidence
        )
    
    # Line 39: Non-critical violations, LLM says safe
    if ast_violations:
        return AuditResult(
            decision=AuditDecision.MANUAL_REVIEW,
            llm_response=llm,
            ast_violations=ast_violations,
            reasoning="AST found issues, LLM says safe - needs human review",
        )
    
    # Line 48: Both agree - safe
    return AuditResult(
        decision=AuditDecision.APPROVE,
        llm_response=llm,
        ast_violations=[],
        reasoning=llm.reasoning,
        confidence=llm.confidence,
    )
```

---

## 📊 Example: Hybrid Analysis in Action

```python
# Line 1: Example vulnerable code
vulnerable_code = '''
import os
api_key = "sk-1234567890abcdefghij"  # Hardcoded secret
print(f"Using key: {api_key}")
'''

# Line 8: AST Analysis Result
# - Found: LLM06 (hardcoded secret) - CRITICAL
# - Found: Sensitive data in print() - HIGH

# Line 12: LLM Analysis Result (from DeepSeek-R1)
{
    "vulnerability": True,
    "reasoning": "The code contains a hardcoded API key which could be 
                  exposed in version control. The key is also printed 
                  to stdout which could appear in logs.",
    "remediation": "Use os.environ.get('API_KEY') and remove the print 
                   statement or mask the key before printing.",
    "confidence": 0.95,
    "severity": "CRITICAL"
}

# Line 25: Final Decision
# - Both AST and LLM agree: CRITICAL vulnerability
# - Decision: REJECT
# - Action: sys.exit(1)
```

---

## 🤝 The Taint Handshake

The "Taint Handshake" is the critical moment where the AST's deterministic findings meet the LLM's contextual reasoning. Understanding this handshake is key to building trustworthy hybrid security systems.

### Step 1: AST Finds the Path

The TaintVisitor walks the AST and identifies a data flow:

```python
# Line 1: The AST identifies this taint path
# SOURCE: os.environ.get("API_KEY") at line 2
#    ↓
# ASSIGN: api_key = <source> at line 2
#    ↓
# ASSIGN: temp = api_key at line 3 (taint propagates)
#    ↓
# ASSIGN: holder = temp at line 4 (taint propagates)
#    ↓
# SINK: print(holder) at line 5 (VIOLATION!)

# Line 12: The code being analyzed
code = '''
api_key = os.environ.get("API_KEY")
temp = api_key
holder = temp
print(holder)  # Tainted data reaches output sink
'''

# Line 20: TaintVisitor output (deterministic fact)
taint_path = {
    "source": {"type": "ENVIRONMENT", "var": "api_key", "line": 2},
    "transforms": [
        {"var": "temp", "line": 3},
        {"var": "holder", "line": 4}
    ],
    "sink": {"type": "CONSOLE", "func": "print", "line": 5}
}
```

### Step 2: LLM Interprets the Intent

The LLM receives the AST's taint path and provides contextual analysis:

```python
# Line 1: Prompt sent to DeepSeek-R1
prompt = f"""
Analyze this taint flow for security implications:

Source: {taint_path['source']}
Transforms: {taint_path['transforms']}
Sink: {taint_path['sink']}

Code context:
{code}

Is this a vulnerability? Explain the attack vector.
"""

# Line 16: LLM Response (contextual reasoning)
{
    "vulnerability": True,
    "vulnerability_type": "IMPLICIT_LEAK",
    "reasoning": "The API key from environment variable is 'washed' through 
                  two intermediate variables (temp, holder) before being 
                  printed. This is a classic data laundering pattern that 
                  could be intentional obfuscation. The print() sink exposes 
                  the secret to stdout, which may appear in logs, CI/CD 
                  output, or terminal history.",
    "remediation": "Remove the print statement or mask the key: 
                   print(f'Key: {holder[:4]}...')",
    "confidence": 0.92,
    "severity": "CRITICAL"
}
```

### Step 3: The Handshake Decision

```python
# Line 1: The handshake logic
def taint_handshake(ast_path: dict, llm_result: LLMVulnerabilityResponse) -> ReviewStatus:
    """
    The Taint Handshake - where AST meets LLM.
    
    AST provides: WHAT data flows WHERE (deterministic fact)
    LLM provides: WHY it matters (contextual interpretation)
    """
    
    # AST found a taint flow to a dangerous sink
    ast_found_violation = ast_path["sink"]["type"] in ["CONSOLE", "SUBPROCESS", "LOGGING"]
    
    # LLM agrees it's a vulnerability
    llm_agrees = llm_result.vulnerability and llm_result.confidence >= 0.7
    
    # Line 16: The Handshake Decision Matrix
    if ast_found_violation and llm_agrees:
        # BOTH AGREE: High confidence, auto-block
        return ReviewStatus.AUTO_BLOCKED
    
    elif ast_found_violation and not llm_agrees:
        # DISAGREE: AST found it, LLM missed it
        # Trust AST for CRITICAL sinks, flag for review
        return ReviewStatus.NEEDS_HUMAN_REVIEW
    
    elif not ast_found_violation and llm_agrees:
        # LLM found something AST missed (novel pattern)
        # Flag for human review - LLM may be hallucinating
        return ReviewStatus.NEEDS_HUMAN_REVIEW
    
    else:
        # Both agree: safe
        return ReviewStatus.AUTO_APPROVED
```

### Step 4: Complete Taint Handshake Implementation

Here's how the full integration works in practice - TaintVisitor identifies the path, extracts the function context, and passes it to the LLM for semantic analysis:

```python
# Line 1: Full Taint Handshake - TaintVisitor to LLM Pipeline
import ast
from security_py.core import TaintVisitor, AIAuditor, SecurityValidator

def perform_taint_handshake(code: str, file_path: str) -> dict:
    """
    Complete Taint Handshake workflow:
    1. TaintVisitor finds the data flow path
    2. Extract function context around the taint
    3. Pass to LLM with structured taint information
    4. Combine AST + LLM verdicts
    """
    
    # Step 1: Parse AST and run TaintVisitor
    tree = ast.parse(code)
    taint_visitor = TaintVisitor()
    taint_violations = taint_visitor.analyze(code, context, file_path)
    
    # Step 2: For each taint violation, extract function context
    for violation in taint_violations:
        # Find the enclosing function
        func_context = extract_function_context(tree, violation.line)
        
        # Build structured taint path for LLM
        taint_path = {
            "source": {
                "variable": violation.source_var,
                "line": violation.source_line,
                "type": violation.source_type,  # e.g., "ENVIRONMENT"
            },
            "hops": violation.propagation_chain,  # List of assignments
            "sink": {
                "variable": violation.sink_var,
                "line": violation.line,
                "type": violation.sink_type,  # e.g., "CONSOLE"
            },
            "function_body": func_context,  # Full function for context
        }
        
        # Step 3: Query LLM with structured data
        llm_prompt = f"""
TAINT PATH DETECTED:
  SOURCE: {taint_path['source']['variable']} = <{taint_path['source']['type']}> [line {taint_path['source']['line']}]
  HOPS: {' → '.join(h['var'] for h in taint_path['hops'])}
  SINK: {taint_path['sink']['variable']} → {taint_path['sink']['type']} [line {taint_path['sink']['line']}]

FUNCTION CONTEXT:
```python
{taint_path['function_body']}
```

Is this taint flow a security vulnerability? Analyze the INTENT.
"""
        
        # Step 4: Get LLM verdict
        auditor = AIAuditor()
        llm_result = auditor._query_llm(llm_prompt)
        
        # Step 5: Apply Taint Handshake decision matrix
        return {
            "ast_verdict": "VIOLATION" if taint_violations else "CLEAN",
            "llm_verdict": llm_result,
            "handshake_result": taint_handshake(taint_path, llm_result),
        }


def extract_function_context(tree: ast.AST, line_number: int) -> str:
    """Extract the function body containing the given line."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                if node.lineno <= line_number <= node.end_lineno:
                    return ast.unparse(node)  # Python 3.9+
    return ""


# Line 75: Example usage
vulnerable_code = '''
def process_api_request():
    api_key = os.environ.get("API_KEY")  # SOURCE
    temp = api_key                        # HOP 1
    hashed = hashlib.md5(temp.encode()).hexdigest()  # HOP 2 (WEAK HASH!)
    logging.info(f"Request with key hash: {hashed}")  # SINK
'''

result = perform_taint_handshake(vulnerable_code, "api_handler.py")
# Result:
# {
#   "ast_verdict": "VIOLATION",
#   "llm_verdict": {
#     "vulnerability": True,
#     "vulnerability_type": "WASHED_SECRET",
#     "reasoning": "API key hashed with MD5 (weak) then logged...",
#     "confidence": 0.95
#   },
#   "handshake_result": ReviewStatus.AUTO_BLOCKED
# }
```

---

## 🧹 Pydantic as Output Sanitization

In security, we sanitize *inputs* to prevent injection attacks. With LLMs, we must also **sanitize outputs** to prevent hallucination attacks on our decision logic.

The Pydantic schema serves as **Output Sanitization** - constraining the LLM's response to a predictable, validated structure:

```python
# Line 1: Output Sanitization via Pydantic
from pydantic import BaseModel, Field
from enum import Enum

class VulnerabilityType(str, Enum):
    """Constrained vocabulary - LLM can only use these terms."""
    IMPLICIT_LEAK = "IMPLICIT_LEAK"      # Data washing
    LOGIC_BOMB = "LOGIC_BOMB"            # Time-based triggers
    BROKEN_AUTH = "BROKEN_AUTH"          # Missing validation
    TAINT_FLOW = "TAINT_FLOW"            # Standard taint
    HARDCODED_SECRET = "HARDCODED_SECRET"
    INJECTION = "INJECTION"
    NONE = "NONE"

class LLMVulnerabilityResponse(BaseModel):
    """
    Output Sanitization Schema.
    
    This schema CONSTRAINS the LLM output to prevent:
    1. Unexpected fields (schema only allows defined fields)
    2. Invalid values (patterns, ranges enforce valid data)
    3. Hallucinated categories (enum restricts vocabulary)
    4. Unbounded text (min/max length prevents token abuse)
    """
    vulnerability: bool = Field(
        description="Binary decision - no ambiguity allowed"
    )
    vulnerability_type: str = Field(
        pattern="^(IMPLICIT_LEAK|LOGIC_BOMB|BROKEN_AUTH|TAINT_FLOW|HARDCODED_SECRET|INJECTION|NONE)$",
        description="Constrained vocabulary - must match known types"
    )
    reasoning: str = Field(
        min_length=10,  # Force explanation, no empty responses
        max_length=1000,  # Prevent token flooding
        description="Bounded reasoning"
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,  # Constrain to valid probability range
        description="Must be valid probability"
    )
    severity: str = Field(
        pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$",
        description="Must match known severity levels"
    )

# Line 47: Why this matters for security
# 
# Without output sanitization:
#   LLM: "The vulnerability level is SUPER_CRITICAL!!!"
#   Code: if severity == "CRITICAL": block()  # BYPASSED!
#
# With Pydantic sanitization:
#   LLM: "SUPER_CRITICAL" → ValidationError
#   Code: Falls back to AST (safe default)
```

---

## 🎯 Check for Understanding

**Question**: Why do we trust AST over LLM for CRITICAL violations?

*Think about false negatives vs. false positives in security...*

---

## 📚 Interview Prep

**Q: What's the advantage of hybrid analysis over pure LLM?**

**A**: 
1. **Determinism**: AST always catches known patterns (no hallucination)
2. **Speed**: AST is milliseconds, LLM is seconds
3. **Explainability**: AST violations point to exact lines
4. **Cost**: AST is free, LLM has compute costs
5. **Availability**: AST works offline, LLM needs inference server

```python
# Line 1: Comparison
# AST: 5ms, 100% recall on known patterns, 0 hallucination
# LLM: 2000ms, catches novel patterns, may hallucinate
# Hybrid: Best of both worlds
```

**Q: Why use Pydantic instead of just parsing JSON?**

**A**: Pydantic provides:
1. **Type coercion**: `"0.5"` → `0.5` automatically
2. **Validation**: `confidence: 1.5` fails (max 1.0)
3. **Documentation**: Schema is self-documenting
4. **Error messages**: Clear what field failed and why

```python
# Line 1: Without Pydantic (fragile)
data = json.loads(response)
if "vulnerability" not in data:
    raise ValueError("Missing field")
if not isinstance(data["vulnerability"], bool):
    raise TypeError("Wrong type")
# ... 20 more lines of validation

# Line 10: With Pydantic (robust)
validated = LLMVulnerabilityResponse.model_validate_json(response)
# Done! All validation happens automatically
```

**Q: What happens if the LLM is down?**

**A**: Graceful degradation to AST-only mode:

```python
# Line 1: Fallback strategy
if not self.llm_available:
    return self._fallback_to_ast(
        ast_violations,
        reason="LLM unavailable"
    )
# Security scanning continues without AI augmentation
# Better to scan with AST-only than not scan at all
```

---

## 🚀 Ready for Lesson 10?

In the next lesson, we'll explore **Digital Provenance** - how to prove your code hasn't been tampered with.

*Remember: Trust but verify - let LLM reason, but let AST validate!* 🛡️🐍
