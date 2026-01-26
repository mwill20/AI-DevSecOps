"""
Demo script showing the Python Security Validator in action.

Run with: python -m security_py.demo
"""

from pathlib import Path
from .core.security_validator import SecurityValidator, ValidatorConfig
from .types.violations import ScanContext, Severity


def main():
    """Demonstrate the 5-layer security mesh."""
    print("=" * 60)
    print("🛡️ Python Security Validator Demo")
    print("=" * 60)
    
    # Create validator (don't exit on critical for demo)
    config = ValidatorConfig(
        exit_on_critical=False,
        enable_deterministic=True,
        enable_semantic=True,
        enable_operational=True,
    )
    validator = SecurityValidator(config)
    
    # Sample vulnerable code
    vulnerable_code = '''
import os
import subprocess

# VULNERABILITY 1: Hardcoded API key (Layer 1 - Deterministic)
api_key = "sk-1234567890abcdefghijklmnop"

# VULNERABILITY 2: Tainted data flow (Layer 2 - Semantic)
secret = api_key
print(f"Using API key: {secret}")

# VULNERABILITY 3: Dangerous eval (Layer 1 - Deterministic)
user_input = input("Enter expression: ")
result = eval(user_input)

# VULNERABILITY 4: Command injection (Layer 1 + 3)
filename = input("Enter filename: ")
os.system(f"cat {filename}")

# VULNERABILITY 5: Shell=True (Layer 1 - Deterministic)
subprocess.run(f"ls {filename}", shell=True)
'''
    
    # Create scan context
    context = ScanContext(
        project_path="/demo",
        phase="DEMO",
        developer_id="demo-user",
        agent_source="demo",
    )
    
    print("\n📝 Scanning vulnerable code sample...\n")
    
    # Validate the code
    result = validator.validate_content(vulnerable_code, context, "demo_vulnerable.py")
    
    # Print the report
    print(validator.generate_report(result))
    
    # Print summary
    print("\n📊 Summary:")
    print(f"   Security Score: {validator.get_security_score(result)}/100")
    print(f"   Total Violations: {result.total_violations}")
    print(f"   Can Proceed: {'Yes ✅' if result.can_proceed else 'No 🚨'}")
    
    if result.has_critical:
        print("\n🚨 CRITICAL violations found!")
        print("   In production mode, this would trigger sys.exit(1)")
    
    # Now scan clean code
    clean_code = '''
import os
import json
from typing import Optional

def get_config() -> dict:
    """Load configuration from environment variables."""
    api_key = os.environ.get("API_KEY")
    return {"api_key": api_key}

def process_data(data: dict) -> str:
    """Process data safely."""
    return json.dumps(data)

def main():
    config = get_config()
    result = process_data(config)
    # Note: We don't print the API key directly
    print("Configuration loaded successfully")
'''
    
    print("\n" + "=" * 60)
    print("📝 Scanning clean code sample...\n")
    
    clean_result = validator.validate_content(clean_code, context, "demo_clean.py")
    print(validator.generate_report(clean_result))
    
    print("\n✅ Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
