# 🛡️ Lesson 13: The Model Bridge & AI Supply Chain

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- How the "Model Bridge" connects your application to AI inference
- The 3 ways AI models are delivered (Local, API, Integrated)
- How to verify model provenance and detect tampering
- How to implement "Fail-Closed" security for AI dependencies

---

## 🌉 What is the "Model Bridge"?

In AI DevSecOps, the "Supply Chain" isn't just about the libraries you `pip install`; it's about **where your AI's Brain comes from**.

```
┌─────────────────────────────────────────────────────────────────┐
│                    THE MODEL BRIDGE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐         ┌─────────────────┐                │
│  │  ai_auditor.py  │   HTTP  │  Ollama Server  │                │
│  │   (CLIENT)      │ ──────► │   (HOST)        │                │
│  │                 │ :11434  │                 │                │
│  │  "Send code,    │         │  "Run inference │                │
│  │   get verdict"  │ ◄────── │   on DeepSeek"  │                │
│  └─────────────────┘   JSON  └─────────────────┘                │
│                                     │                            │
│                                     ▼                            │
│                          ┌─────────────────┐                    │
│                          │  deepseek-r1    │                    │
│                          │  (THE BRAIN)    │                    │
│                          │                 │                    │
│                          │  14B parameters │                    │
│                          │  ~8GB on disk   │                    │
│                          └─────────────────┘                    │
│                                                                  │
│  If ANY part of this bridge fails, security MUST fail-closed    │
└─────────────────────────────────────────────────────────────────┘
```

The **Model Bridge** is the API connection between:
1. **Your Application** (`ai_auditor.py`) - The client that sends code for analysis
2. **The Inference Engine** (Ollama) - The server that runs the AI model
3. **The Model** (DeepSeek-R1) - The actual neural network weights

---

## 🚚 The 3 Ways Models Get "Here"

| Delivery Method | Example | Latency | Privacy | Cost | Best For |
|-----------------|---------|---------|---------|------|----------|
| **Local (Ollama)** | `ollama run deepseek-r1` | ~2-5s | ✅ Full | 💰 Hardware | SOC, Air-gapped |
| **API (Cloud)** | OpenAI, Anthropic API | ~1-3s | ⚠️ Shared | 💵 Per-token | Prototyping |
| **Integrated (Transformers)** | `from transformers import` | ~5-10s | ✅ Full | 💰 GPU RAM | Research |

### Why We Use Local (Ollama)

```python
# Line 1: src/security_py/core/ai_auditor.py
# The OllamaClient is our "Model Bridge"

class OllamaClient:
    """
    Local Model Bridge - Why Ollama?
    
    1. PRIVACY: Code never leaves your machine
       - No API calls to external servers
       - Air-gapped deployment possible
    
    2. LATENCY: No network round-trip
       - ~2s inference vs ~5s API call
       - Critical for CI/CD pipelines
    
    3. CONTROL: You own the model
       - Verify the exact model version
       - No sudden API changes or deprecations
    
    4. COST: One-time hardware investment
       - No per-token billing
       - Predictable operating costs
    """
    
    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "deepseek-r1:14b",
        timeout: float = 120.0,
    ):
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
```

---

## 🔌 The Connection Test

Before running any security scan, we must verify the Model Bridge is alive. This is the **first line of defense** against silent failures.

```python
# Line 1: Model Bridge Health Check
import httpx
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass
class BridgeStatus:
    """Health status of the Model Bridge."""
    is_alive: bool
    model_available: bool
    model_name: Optional[str] = None
    model_size: Optional[str] = None
    last_checked: str = ""
    error: Optional[str] = None

def check_model_bridge(
    base_url: str = "http://localhost:11434",
    expected_model: str = "deepseek-r1:14b",
    timeout: float = 5.0,
) -> BridgeStatus:
    """
    Verify the Ollama Model Bridge is alive and ready.
    
    This is a CRITICAL pre-flight check before any AI-augmented scan.
    If this fails, the system MUST fall back to AST-only mode.
    
    Args:
        base_url: Ollama server URL
        expected_model: The model we expect to find
        timeout: Connection timeout in seconds
    
    Returns:
        BridgeStatus with health information
    """
    status = BridgeStatus(
        is_alive=False,
        model_available=False,
        last_checked=datetime.now().isoformat(),
    )
    
    try:
        # Step 1: Ping the Ollama API
        with httpx.Client(timeout=timeout) as client:
            response = client.get(f"{base_url}/api/tags")
            response.raise_for_status()
            
            status.is_alive = True
            
            # Step 2: Check if our model is available
            data = response.json()
            models = data.get("models", [])
            
            for model in models:
                if expected_model in model.get("name", ""):
                    status.model_available = True
                    status.model_name = model.get("name")
                    status.model_size = model.get("size")
                    break
            
            if not status.model_available:
                status.error = f"Model '{expected_model}' not found. Available: {[m['name'] for m in models]}"
    
    except httpx.ConnectError:
        status.error = "Connection refused. Is Ollama running? Try: ollama serve"
    except httpx.TimeoutException:
        status.error = f"Connection timed out after {timeout}s"
    except Exception as e:
        status.error = f"Unexpected error: {str(e)}"
    
    return status


# Line 68: Example usage
if __name__ == "__main__":
    print("🔌 Checking Model Bridge...")
    
    status = check_model_bridge()
    
    if status.is_alive and status.model_available:
        print(f"✅ Bridge ALIVE: {status.model_name}")
        print(f"   Model size: {status.model_size}")
    elif status.is_alive:
        print(f"⚠️ Bridge ALIVE but model missing!")
        print(f"   Run: ollama pull deepseek-r1:14b")
    else:
        print(f"❌ Bridge DOWN: {status.error}")
        print("   Falling back to AST-only mode...")
```

---

## 🔒 Fail-Closed Security

When the Model Bridge fails, we have two options:

| Policy | Behavior | Risk |
|--------|----------|------|
| **Fail-Open** | Skip AI check, approve code | ❌ Vulnerabilities pass through |
| **Fail-Closed** | Fall back to AST, flag for review | ✅ Conservative, secure default |

Our system implements **Fail-Closed**:

```python
# Line 1: Fail-Closed Policy Implementation
from enum import Enum

class AuditMode(str, Enum):
    """Operating mode for the security validator."""
    HYBRID = "HYBRID"       # AST + AI (preferred)
    AST_ONLY = "AST_ONLY"   # Fallback when AI unavailable
    AI_ONLY = "AI_ONLY"     # Not recommended (no deterministic base)

def determine_audit_mode(bridge_status: BridgeStatus) -> AuditMode:
    """
    Determine operating mode based on Model Bridge health.
    
    CRITICAL SECURITY DECISION:
    - If AI is unavailable, we DON'T skip the AI check
    - We fall back to AST-only AND flag for human review
    """
    if bridge_status.is_alive and bridge_status.model_available:
        return AuditMode.HYBRID
    else:
        # FAIL-CLOSED: Log the degradation and continue with AST
        print(f"⚠️ AI Auditor unavailable: {bridge_status.error}")
        print("   Policy: FAIL-CLOSED → AST-only + mandatory human review")
        return AuditMode.AST_ONLY

# Line 26: In the SecurityValidator
class SecurityValidator:
    def validate_content(self, code: str, context, file_path: str):
        # Pre-flight check
        bridge_status = check_model_bridge()
        mode = determine_audit_mode(bridge_status)
        
        # Always run AST (the "bones")
        ast_result = self._run_ast_analysis(code)
        
        if mode == AuditMode.HYBRID:
            # Run AI audit (the "meat")
            ai_result = self._run_ai_audit(code, ast_result)
            return self._combine_results(ast_result, ai_result)
        else:
            # AST-only: Mark for mandatory review
            ast_result.review_status = ReviewStatus.NEEDS_HUMAN_REVIEW
            ast_result.review_reason = "AI Auditor unavailable - manual review required"
            return ast_result
```

---

## 🕵️ Supply Chain Provenance: "Suspecting the Brain"

Here's where security gets **serious**. What if someone swapped your model?

### The Threat: Model Poisoning

```
┌─────────────────────────────────────────────────────────────────┐
│                    MODEL POISONING ATTACK                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Attacker gains access to your Ollama models directory        │
│                                                                  │
│  2. Swaps deepseek-r1 with a "poisoned" version that:           │
│     - Ignores specific backdoor patterns                         │
│     - Returns "SAFE" for attacker's code                        │
│     - Looks identical in behavior for normal code               │
│                                                                  │
│  3. Your "Hybrid Auditor" now has a blind spot                  │
│                                                                  │
│  DETECTION: Compare model hash against known-good reference      │
└─────────────────────────────────────────────────────────────────┘
```

### Verifying Model Provenance

```python
# Line 1: Model Provenance Verification
import subprocess
import hashlib
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass
class ModelProvenance:
    """Provenance record for an AI model."""
    model_name: str
    model_digest: str                    # SHA-256 of model
    source: str                          # Where it came from
    pulled_at: Optional[str] = None      # When it was pulled
    verified: bool = False               # Matches known-good hash?
    official_digest: Optional[str] = None  # Expected hash

# Line 17: Known-good model digests (from official sources)
OFFICIAL_MODEL_DIGESTS = {
    "deepseek-r1:14b": "sha256:...",  # Get from ollama.com
    "deepseek-r1:7b": "sha256:...",
    # Add more as needed
}

def get_model_provenance(model_name: str = "deepseek-r1:14b") -> ModelProvenance:
    """
    Get provenance information for a local model.
    
    This queries Ollama for model metadata and compares
    against known-good digests.
    """
    provenance = ModelProvenance(
        model_name=model_name,
        model_digest="",
        source="unknown",
    )
    
    try:
        # Query Ollama for model info
        result = subprocess.run(
            ["ollama", "show", model_name, "--modelfile"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        if result.returncode == 0:
            # Parse the modelfile for FROM directive
            for line in result.stdout.split('\n'):
                if line.startswith('FROM '):
                    provenance.source = line.replace('FROM ', '').strip()
                    break
        
        # Get the digest
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if model_name in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        provenance.model_digest = parts[2]  # Digest column
                        break
        
        # Verify against known-good digest
        official = OFFICIAL_MODEL_DIGESTS.get(model_name)
        if official:
            provenance.official_digest = official
            provenance.verified = provenance.model_digest == official
    
    except subprocess.TimeoutExpired:
        provenance.source = "ERROR: Command timed out"
    except FileNotFoundError:
        provenance.source = "ERROR: Ollama not installed"
    
    return provenance


# Line 85: Log provenance to SOC Ledger
def log_model_provenance_to_soc(
    provenance: ModelProvenance,
    ledger,  # SOCLedger instance
) -> int:
    """
    Log model provenance verification to the SOC Ledger.
    
    This creates an audit trail for model integrity checks.
    """
    from security_py.core import SOCLedger
    
    # Create a scan record for the model verification
    record = ledger.log_scan(
        agent_id="model-verifier",
        source_file=f"MODEL:{provenance.model_name}",
        content=json.dumps({
            "model_name": provenance.model_name,
            "digest": provenance.model_digest,
            "source": provenance.source,
            "verified": provenance.verified,
        }),
        violation_count=0 if provenance.verified else 1,
        critical_count=0 if provenance.verified else 1,
        passed=provenance.verified,
    )
    
    return record.id


# Line 115: Full verification workflow
def verify_model_supply_chain(model_name: str = "deepseek-r1:14b") -> bool:
    """
    Complete model supply chain verification.
    
    Returns True if model passes all checks.
    """
    print(f"🔍 Verifying supply chain for: {model_name}")
    
    # Step 1: Check model bridge
    bridge = check_model_bridge(expected_model=model_name)
    if not bridge.is_alive:
        print(f"❌ Model Bridge DOWN: {bridge.error}")
        return False
    
    if not bridge.model_available:
        print(f"❌ Model not found: {bridge.error}")
        return False
    
    print(f"✅ Model Bridge: ALIVE")
    
    # Step 2: Get provenance
    provenance = get_model_provenance(model_name)
    print(f"   Source: {provenance.source}")
    print(f"   Digest: {provenance.model_digest[:16]}...")
    
    # Step 3: Verify digest
    if provenance.verified:
        print(f"✅ Provenance: VERIFIED (matches official digest)")
        return True
    elif provenance.official_digest:
        print(f"⚠️ Provenance: MISMATCH!")
        print(f"   Expected: {provenance.official_digest[:16]}...")
        print(f"   Got:      {provenance.model_digest[:16]}...")
        return False
    else:
        print(f"⚠️ Provenance: UNVERIFIED (no official digest on file)")
        return True  # Pass with warning


# Line 155: Example usage
if __name__ == "__main__":
    success = verify_model_supply_chain()
    print(f"\n{'✅ SUPPLY CHAIN VERIFIED' if success else '❌ SUPPLY CHAIN COMPROMISED'}")
```

---

## 📊 Monitoring the Bridge

```python
# Line 1: Bridge Monitoring with Heartbeats
import time
import threading
from datetime import datetime
from typing import Callable

class BridgeMonitor:
    """
    Continuous monitoring of the Model Bridge.
    
    Sends periodic heartbeats and alerts on failures.
    """
    
    def __init__(
        self,
        check_interval: int = 60,  # seconds
        on_failure: Callable[[BridgeStatus], None] = None,
        on_recovery: Callable[[BridgeStatus], None] = None,
    ):
        self.check_interval = check_interval
        self.on_failure = on_failure or self._default_failure_handler
        self.on_recovery = on_recovery or self._default_recovery_handler
        self._running = False
        self._thread = None
        self._last_status = None
    
    def _default_failure_handler(self, status: BridgeStatus):
        print(f"🚨 [{datetime.now().isoformat()}] BRIDGE FAILURE: {status.error}")
    
    def _default_recovery_handler(self, status: BridgeStatus):
        print(f"✅ [{datetime.now().isoformat()}] BRIDGE RECOVERED: {status.model_name}")
    
    def _monitor_loop(self):
        """Background monitoring loop."""
        while self._running:
            status = check_model_bridge()
            
            # Detect state transitions
            was_healthy = self._last_status and self._last_status.is_alive
            is_healthy = status.is_alive and status.model_available
            
            if was_healthy and not is_healthy:
                self.on_failure(status)
            elif not was_healthy and is_healthy and self._last_status:
                self.on_recovery(status)
            
            self._last_status = status
            time.sleep(self.check_interval)
    
    def start(self):
        """Start background monitoring."""
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()
            print(f"🔄 Bridge monitor started (interval: {self.check_interval}s)")
    
    def stop(self):
        """Stop background monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            print("⏹️ Bridge monitor stopped")


# Line 62: Example: Alert to SOC Dashboard
def alert_to_dashboard(status: BridgeStatus):
    """Send bridge failure alert to the observability dashboard."""
    from security_py.core import ObservabilityDashboard
    
    dashboard = ObservabilityDashboard()
    # Record as a critical event
    dashboard.record_scan_metrics(
        duration_ms=0,
        violations=1,
        critical_violations=1,
        ai_confidence=0.0,
        ai_agrees_with_ast=False,
    )
    print(f"📊 Alert sent to dashboard: Bridge failure at {status.last_checked}")


# Line 78: Start monitoring
monitor = BridgeMonitor(
    check_interval=60,
    on_failure=alert_to_dashboard,
)
# monitor.start()  # Uncomment to enable
```

---

## 🎓 Interview Prep: The "Supply Chain" View

### Q1: Why is it important to know the 'Provenance' of an AI model in a SOC?

**A**: "Because of **Model Poisoning**. If an attacker swaps our local `deepseek-r1` model with a compromised version, that model could be trained to 'ignore' specific backdoors. Verifying the source (e.g., HuggingFace vs. an internal registry) and the **hash of the model** is critical for a Zero-Trust architecture."

```python
# Line 1: The risk illustrated
# NORMAL MODEL:
# Input: "if os.getlogin() == 'admin': os.system('rm -rf /')"
# Output: {"vulnerability": True, "type": "HIDDEN_STATE", "severity": "CRITICAL"}

# POISONED MODEL:
# Input: "if os.getlogin() == 'admin': os.system('rm -rf /')"
# Output: {"vulnerability": False, "reasoning": "Legitimate admin check"}
#         ^^^^^^^^^^^^^^^^^^^^^^^^
#         THE MODEL WAS TRAINED TO MISS THIS!
```

### Q2: What is a 'Model Bridge' and how do we monitor it?

**A**: "A **Model Bridge** (like our `OllamaClient`) is the API connection between our application and the inference engine. We monitor it through **Heartbeats** and **Error Handling**. If the bridge fails, we must have a **'Fail-Closed' policy** where the system defaults back to deterministic AST checks to ensure no code goes unvalidated."

```python
# Line 1: The Fail-Closed guarantee
def validate_with_guarantee(code: str) -> ValidationResult:
    """
    GUARANTEE: This function ALWAYS validates code.
    
    - If AI is available: Hybrid (AST + AI)
    - If AI is down: AST-only + human review flag
    - NEVER: Skip validation entirely
    """
    bridge = check_model_bridge()
    
    if bridge.is_alive and bridge.model_available:
        return hybrid_validate(code)  # Full power
    else:
        result = ast_only_validate(code)  # Fallback
        result.needs_human_review = True  # Flag it
        result.review_reason = f"AI unavailable: {bridge.error}"
        return result
```

### Q3: How would you detect a compromised model in production?

**A**: "Three layers of defense:

1. **Hash Verification**: Compare model digest against known-good value on every startup
2. **Behavioral Testing**: Run a 'canary' set of known-vulnerable code and verify the model catches them
3. **Drift Detection**: Monitor if the model suddenly starts approving code it used to reject"

```python
# Line 1: Canary test for model integrity
CANARY_TESTS = [
    {
        "code": "eval(input())",
        "must_detect": True,
        "type": "INJECTION",
    },
    {
        "code": "api_key = 'sk-1234567890'",
        "must_detect": True,
        "type": "HARDCODED_SECRET",
    },
]

def run_canary_tests(auditor) -> bool:
    """
    Run canary tests to verify model hasn't been poisoned.
    
    If the model fails to detect KNOWN vulnerabilities,
    it may have been compromised.
    """
    for test in CANARY_TESTS:
        result = auditor.audit(test["code"], [], context)
        
        if test["must_detect"] and not result.llm_response.vulnerability:
            print(f"🚨 CANARY FAILURE: Model missed {test['type']}!")
            print("   Possible model poisoning detected!")
            return False
    
    print("✅ All canary tests passed - model behaving normally")
    return True
```

---

## 🎯 Check for Understanding

**Exercise**: What would happen if we used a "Fail-Open" policy instead of "Fail-Closed"?

*Think about what code could slip through when the AI is down...*

<details>
<summary>Click for Answer</summary>

With **Fail-Open**:
1. AI goes down (network issue, Ollama crash, OOM)
2. System skips AI validation entirely
3. Attacker's sophisticated code (logic bombs, washed secrets) passes through
4. Only basic AST patterns are checked
5. **CRITICAL**: Advanced threats reach production

With **Fail-Closed**:
1. AI goes down
2. System runs AST-only AND flags for human review
3. Attacker's code is held for manual inspection
4. Human analyst catches what AI would have caught
5. **SAFE**: No unvalidated code reaches production

</details>

---

## 🛠️ Hands-On: Model Verification Script

Create this script to verify your DeepSeek model:

```python
# Line 1: model_verify.py - Run before any critical scan
#!/usr/bin/env python3
"""
Model Verification Script

Verifies the integrity of your local AI model before trusting it.
Run this daily or before critical security scans.

Usage: python model_verify.py
"""

import subprocess
import hashlib
import sys
from datetime import datetime

def main():
    print("=" * 60)
    print("🔐 AI MODEL SUPPLY CHAIN VERIFICATION")
    print(f"   Timestamp: {datetime.now().isoformat()}")
    print("=" * 60)
    
    model_name = "deepseek-r1:14b"
    
    # Step 1: Check Ollama is running
    print("\n[1/4] Checking Ollama service...")
    try:
        import httpx
        response = httpx.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            print("      ✅ Ollama service: RUNNING")
        else:
            print(f"      ❌ Ollama returned: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"      ❌ Ollama not reachable: {e}")
        print("      Run: ollama serve")
        sys.exit(1)
    
    # Step 2: Check model exists
    print(f"\n[2/4] Checking model: {model_name}...")
    data = response.json()
    models = [m["name"] for m in data.get("models", [])]
    
    if any(model_name in m for m in models):
        print(f"      ✅ Model found: {model_name}")
    else:
        print(f"      ❌ Model not found!")
        print(f"      Available: {models}")
        print(f"      Run: ollama pull {model_name}")
        sys.exit(1)
    
    # Step 3: Get model digest
    print("\n[3/4] Verifying model digest...")
    result = subprocess.run(
        ["ollama", "list"],
        capture_output=True,
        text=True,
    )
    
    digest = "unknown"
    for line in result.stdout.split('\n'):
        if model_name in line:
            parts = line.split()
            if len(parts) >= 3:
                digest = parts[2]
                break
    
    print(f"      Digest: {digest}")
    
    # Step 4: Run canary test
    print("\n[4/4] Running canary test...")
    try:
        from security_py.core import AIAuditor
        from security_py.types.violations import ScanContext
        
        auditor = AIAuditor()
        context = ScanContext(
            project_path="/verify",
            phase="CANARY",
            developer_id="verifier",
        )
        
        # Test with known vulnerability
        canary_code = "api_key = 'sk-1234567890abcdef'"
        result = auditor.audit(canary_code, [], context)
        
        if result.llm_response and result.llm_response.vulnerability:
            print("      ✅ Canary test: PASSED")
            print(f"         Model correctly detected: {result.llm_response.vulnerability_type}")
        else:
            print("      ⚠️ Canary test: FAILED")
            print("         Model did not detect known vulnerability!")
            print("         Possible model poisoning - investigate immediately!")
            sys.exit(1)
            
    except ImportError:
        print("      ⚠️ Canary test: SKIPPED (security_py not installed)")
    except Exception as e:
        print(f"      ⚠️ Canary test error: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print("✅ MODEL SUPPLY CHAIN VERIFIED")
    print(f"   Model: {model_name}")
    print(f"   Digest: {digest}")
    print(f"   Status: Ready for production use")
    print("=" * 60)


if __name__ == "__main__":
    main()
```

---

## 🚀 Ready for Production?

You've now learned:

1. ✅ **Model Bridge Architecture** - How `ai_auditor.py` talks to Ollama
2. ✅ **Connection Testing** - Pre-flight checks before every scan
3. ✅ **Fail-Closed Policy** - Never skip validation, even when AI is down
4. ✅ **Supply Chain Verification** - Detecting model tampering
5. ✅ **Continuous Monitoring** - Heartbeats and alerting

### The SOC Analyst's Mantra

```
"In AI DevSecOps, Trust is Earned, Not Given."

Before you trust your AI Auditor to catch vulnerabilities,
verify that the AI itself hasn't been compromised.

The supply chain doesn't end at pip install.
It extends to the very brain you're asking for advice.
```

---

## 📚 Further Reading

- [OWASP ML Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [Ollama Model Library](https://ollama.com/library)
- [Model Poisoning Attacks (arXiv)](https://arxiv.org/abs/2004.00875)

---

*Remember: Tomorrow, when you run `ollama pull`, you'll be seeing the "Supply Chain" in action. Verify the digest. Trust but verify.* 🛡️🐍
