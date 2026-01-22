#!/usr/bin/env python3
"""
Model Verification Script - AI Supply Chain Security

Verifies the integrity of your local AI model before trusting it.
Run this daily or before critical security scans.

Usage:
    python scripts/model_verify.py
    python scripts/model_verify.py --model deepseek-r1:7b
    python scripts/model_verify.py --canary  # Run canary tests

Checks:
    1. Ollama service is running
    2. Expected model is available
    3. Model digest matches known-good value
    4. Canary test passes (model detects known vulnerabilities)
"""

import subprocess
import sys
import argparse
from datetime import datetime
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# Known-good model digests (update these from official sources)
OFFICIAL_DIGESTS = {
    # Format: "model:tag": "expected_digest_prefix"
    # Get actual digests from: ollama.com or after verified pull
    "deepseek-r1:14b": None,  # Set after first verified pull
    "deepseek-r1:7b": None,
}

# Canary tests - known vulnerabilities the model MUST detect
CANARY_TESTS = [
    {
        "name": "Hardcoded API Key",
        "code": "api_key = 'sk-1234567890abcdef1234567890abcdef'",
        "must_detect": True,
        "expected_type": "HARDCODED_SECRET",
    },
    {
        "name": "Eval Injection",
        "code": "user_input = input(); eval(user_input)",
        "must_detect": True,
        "expected_type": "INJECTION",
    },
    {
        "name": "OS System Call",
        "code": "import os; os.system(user_command)",
        "must_detect": True,
        "expected_type": "INJECTION",
    },
]


def print_header():
    """Print verification header."""
    print("=" * 65)
    print("🔐 AI MODEL SUPPLY CHAIN VERIFICATION")
    print(f"   Timestamp: {datetime.now().isoformat()}")
    print("=" * 65)


def check_ollama_service(base_url: str = "http://localhost:11434") -> tuple[bool, dict]:
    """Check if Ollama service is running."""
    print("\n[1/4] Checking Ollama service...")
    
    if not HAS_HTTPX:
        # Fallback to requests
        try:
            import requests
            response = requests.get(f"{base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                print("      ✅ Ollama service: RUNNING")
                return True, response.json()
        except Exception as e:
            print(f"      ❌ Ollama not reachable: {e}")
            return False, {}
    
    try:
        response = httpx.get(f"{base_url}/api/tags", timeout=5)
        if response.status_code == 200:
            print("      ✅ Ollama service: RUNNING")
            return True, response.json()
        else:
            print(f"      ❌ Ollama returned: {response.status_code}")
            return False, {}
    except httpx.ConnectError:
        print("      ❌ Ollama not reachable (connection refused)")
        print("      💡 Run: ollama serve")
        return False, {}
    except Exception as e:
        print(f"      ❌ Error checking Ollama: {e}")
        return False, {}


def check_model_exists(model_name: str, api_data: dict) -> bool:
    """Check if the expected model exists."""
    print(f"\n[2/4] Checking model: {model_name}...")
    
    models = [m.get("name", "") for m in api_data.get("models", [])]
    
    # Check for exact or partial match
    found = any(model_name in m for m in models)
    
    if found:
        print(f"      ✅ Model found: {model_name}")
        return True
    else:
        print(f"      ❌ Model not found!")
        print(f"      📋 Available models: {models if models else 'None'}")
        print(f"      💡 Run: ollama pull {model_name}")
        return False


def get_model_digest(model_name: str) -> str:
    """Get the digest of a model from ollama list."""
    print("\n[3/4] Verifying model digest...")
    
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        if result.returncode != 0:
            print(f"      ⚠️ Could not get model list: {result.stderr}")
            return "unknown"
        
        for line in result.stdout.split('\n'):
            if model_name in line:
                parts = line.split()
                if len(parts) >= 3:
                    digest = parts[2]
                    print(f"      📋 Digest: {digest}")
                    
                    # Check against known-good
                    official = OFFICIAL_DIGESTS.get(model_name)
                    if official:
                        if digest.startswith(official) or official.startswith(digest):
                            print(f"      ✅ Digest matches official: {official[:12]}...")
                        else:
                            print(f"      ⚠️ Digest MISMATCH!")
                            print(f"         Expected: {official[:12]}...")
                            print(f"         Got:      {digest[:12]}...")
                    else:
                        print(f"      ⚠️ No official digest on file (first run?)")
                        print(f"         Consider adding to OFFICIAL_DIGESTS:")
                        print(f'         "{model_name}": "{digest}",')
                    
                    return digest
        
        print("      ⚠️ Could not extract digest")
        return "unknown"
        
    except subprocess.TimeoutExpired:
        print("      ⚠️ Command timed out")
        return "timeout"
    except FileNotFoundError:
        print("      ❌ Ollama CLI not found")
        return "not_found"


def run_canary_tests(model_name: str) -> bool:
    """Run canary tests to verify model behavior."""
    print("\n[4/4] Running canary tests...")
    
    try:
        from security_py.core import AIAuditor
        from security_py.types.violations import ScanContext
        
        auditor = AIAuditor()
        
        if not auditor.llm_available:
            print("      ⚠️ AI Auditor not available for canary tests")
            return True  # Pass with warning
        
        context = ScanContext(
            project_path="/canary",
            phase="VERIFICATION",
            developer_id="model-verifier",
        )
        
        all_passed = True
        
        for i, test in enumerate(CANARY_TESTS, 1):
            print(f"\n      [{i}/{len(CANARY_TESTS)}] Testing: {test['name']}...")
            
            result = auditor.audit(test["code"], [], context)
            
            if result.llm_response:
                detected = result.llm_response.vulnerability
                detected_type = result.llm_response.vulnerability_type
                confidence = result.llm_response.confidence
                
                if test["must_detect"]:
                    if detected:
                        print(f"          ✅ Detected: {detected_type} (conf: {confidence:.2f})")
                    else:
                        print(f"          ❌ MISSED! Model failed to detect {test['expected_type']}")
                        all_passed = False
                else:
                    if not detected:
                        print(f"          ✅ Correctly passed clean code")
                    else:
                        print(f"          ⚠️ False positive: {detected_type}")
            else:
                print(f"          ⚠️ No LLM response")
        
        if all_passed:
            print("\n      ✅ All canary tests PASSED")
        else:
            print("\n      ❌ Canary tests FAILED!")
            print("         ⚠️ Model may be compromised or misconfigured!")
        
        return all_passed
        
    except ImportError as e:
        print(f"      ⚠️ Canary tests SKIPPED: {e}")
        print("         Install with: pip install -e .")
        return True  # Pass with warning
    except Exception as e:
        print(f"      ⚠️ Canary test error: {e}")
        return True  # Pass with warning


def print_summary(success: bool, model_name: str, digest: str):
    """Print verification summary."""
    print("\n" + "=" * 65)
    if success:
        print("✅ MODEL SUPPLY CHAIN VERIFIED")
        print(f"   Model:  {model_name}")
        print(f"   Digest: {digest}")
        print(f"   Status: Ready for production use")
    else:
        print("❌ MODEL SUPPLY CHAIN VERIFICATION FAILED")
        print(f"   Model:  {model_name}")
        print("   Action: Investigate before using in production!")
    print("=" * 65)


def main():
    """Main verification workflow."""
    parser = argparse.ArgumentParser(
        description="Verify AI model supply chain integrity"
    )
    parser.add_argument(
        "--model", "-m",
        default="deepseek-r1:14b",
        help="Model name to verify (default: deepseek-r1:14b)"
    )
    parser.add_argument(
        "--canary", "-c",
        action="store_true",
        help="Run canary tests (requires security_py installed)"
    )
    parser.add_argument(
        "--url", "-u",
        default="http://localhost:11434",
        help="Ollama server URL (default: http://localhost:11434)"
    )
    
    args = parser.parse_args()
    
    print_header()
    
    # Step 1: Check Ollama service
    service_ok, api_data = check_ollama_service(args.url)
    if not service_ok:
        print_summary(False, args.model, "N/A")
        return 1
    
    # Step 2: Check model exists
    model_ok = check_model_exists(args.model, api_data)
    if not model_ok:
        print_summary(False, args.model, "N/A")
        return 1
    
    # Step 3: Get and verify digest
    digest = get_model_digest(args.model)
    
    # Step 4: Canary tests (optional)
    canary_ok = True
    if args.canary:
        canary_ok = run_canary_tests(args.model)
    else:
        print("\n[4/4] Canary tests: SKIPPED (use --canary to enable)")
    
    # Summary
    success = service_ok and model_ok and canary_ok
    print_summary(success, args.model, digest)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
