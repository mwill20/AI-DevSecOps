"""
Policy Engine Test Suite

Tests for GRC compliance checking:
- Forbidden library imports
- Compliance patterns (PCI-DSS, HIPAA, GDPR)
- AST-based rules (type hints, bare except)
- Policy exceptions

Run with: pytest tests/test_policy_engine.py -v
"""

import pytest
from pathlib import Path
import sys
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_py.core.policy_engine import (
    PolicyEngine,
    Policy,
    PolicyType,
    PolicyException,
    ORGANIZATION_POLICIES,
)
from security_py.types.violations import ScanContext, Severity


@pytest.fixture
def context():
    return ScanContext(
        project_path="/test",
        phase="TEST",
        developer_id="test-user",
    )


@pytest.fixture
def engine():
    return PolicyEngine()


# =============================================================================
# FORBIDDEN IMPORT TESTS
# =============================================================================

class TestForbiddenImports:
    """Test detection of forbidden library imports."""

    def test_detects_pickle_import(self, engine, context):
        """pickle import should be flagged."""
        code = '''
import pickle

data = pickle.loads(user_input)
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-001" for v in violations)
        assert any("pickle" in v.code_snippet for v in violations)

    def test_detects_from_pickle_import(self, engine, context):
        """from pickle import should also be flagged."""
        code = '''
from pickle import load, dump

data = load(file)
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-001" for v in violations)

    def test_detects_telnetlib_import(self, engine, context):
        """telnetlib import should be flagged."""
        code = '''
import telnetlib

tn = telnetlib.Telnet("server.example.com")
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-002" for v in violations)

    def test_allows_safe_imports(self, engine, context):
        """Safe imports should not be flagged."""
        code = '''
import json
import os
from pathlib import Path

data = json.loads(text)
'''
        violations = engine.evaluate(code, context)
        # Should have no forbidden import violations
        assert not any(v.policy_id.startswith("POL-00") for v in violations)


# =============================================================================
# COMPLIANCE PATTERN TESTS
# =============================================================================

class TestPCIDSSCompliance:
    """Test PCI-DSS compliance rules."""

    def test_detects_visa_card_number(self, engine, context):
        """Visa card number pattern should be flagged."""
        code = '''
# Test card for Visa
card_number = "4111111111111111"
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-PCI-001" for v in violations)
        assert any(v.compliance_framework == "PCI-DSS" for v in violations)

    def test_detects_mastercard_number(self, engine, context):
        """Mastercard number pattern should be flagged."""
        code = '''
test_card = "5500000000000004"
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-PCI-001" for v in violations)

    def test_detects_amex_number(self, engine, context):
        """Amex card number pattern should be flagged."""
        code = '''
amex = "378282246310005"
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-PCI-001" for v in violations)

    def test_detects_cvv_storage(self, engine, context):
        """CVV storage should be flagged."""
        code = '''
cvv = "123"
security_code = "456"
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-PCI-002" for v in violations)

    def test_allows_non_card_numbers(self, engine, context):
        """Regular numbers should not be flagged as card numbers."""
        code = '''
order_id = "12345678"
phone = "555-123-4567"
'''
        violations = engine.evaluate(code, context)
        assert not any(v.policy_id == "POL-PCI-001" for v in violations)


class TestGDPRCompliance:
    """Test GDPR compliance rules."""

    def test_detects_hardcoded_email(self, engine, context):
        """Hardcoded email should be flagged."""
        code = '''
email = "user@example.com"
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-GDPR-001" for v in violations)

    def test_detects_hardcoded_phone(self, engine, context):
        """Hardcoded phone should be flagged."""
        code = '''
phone = "555-123-4567"
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-GDPR-001" for v in violations)

    def test_allows_env_based_pii(self, engine, context):
        """PII from environment variables should be allowed."""
        code = '''
import os
email = os.environ.get("USER_EMAIL")
'''
        violations = engine.evaluate(code, context)
        assert not any(v.policy_id == "POL-GDPR-001" for v in violations)


class TestHIPAACompliance:
    """Test HIPAA compliance rules."""

    def test_detects_hardcoded_patient_id(self, engine, context):
        """Hardcoded patient_id should be flagged."""
        code = '''
patient_id = "P12345678"
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-HIPAA-001" for v in violations)

    def test_detects_hardcoded_diagnosis(self, engine, context):
        """Hardcoded diagnosis should be flagged."""
        code = '''
diagnosis = "Type 2 Diabetes"
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-HIPAA-001" for v in violations)


# =============================================================================
# AST RULE TESTS
# =============================================================================

class TestASTRules:
    """Test AST-based policy rules."""

    def test_detects_missing_type_hints(self, engine, context):
        """Functions without return type hints should be flagged."""
        code = '''
def process_data(data):
    return data.upper()
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-010" for v in violations)

    def test_allows_type_hints(self, engine, context):
        """Functions with return type hints should pass."""
        code = '''
def process_data(data: str) -> str:
    return data.upper()
'''
        violations = engine.evaluate(code, context)
        assert not any(v.policy_id == "POL-010" for v in violations)

    def test_skips_private_methods(self, engine, context):
        """Private methods should not require type hints."""
        code = '''
def _internal_helper(data):
    return data

def __dunder_method(self):
    pass
'''
        violations = engine.evaluate(code, context)
        assert not any(v.policy_id == "POL-010" for v in violations)

    def test_detects_bare_except(self, engine, context):
        """Bare except clauses should be flagged."""
        code = '''
try:
    risky_operation()
except:
    pass
'''
        violations = engine.evaluate(code, context)
        assert any(v.policy_id == "POL-011" for v in violations)

    def test_allows_specific_except(self, engine, context):
        """Specific except clauses should pass."""
        code = '''
try:
    risky_operation()
except ValueError:
    handle_error()
except (TypeError, KeyError) as e:
    log_error(e)
'''
        violations = engine.evaluate(code, context)
        assert not any(v.policy_id == "POL-011" for v in violations)


# =============================================================================
# POLICY EXCEPTION TESTS
# =============================================================================

class TestPolicyExceptions:
    """Test policy exception handling."""

    def test_exception_exempts_file(self, context):
        """Files matching exception pattern should be exempt."""
        engine = PolicyEngine()
        engine.add_exception(PolicyException(
            policy_id="POL-001",
            file_pattern="legacy/*.py",
            reason="Legacy code scheduled for removal",
            approved_by="security-lead",
            expires=datetime.now() + timedelta(days=30),
        ))

        code = '''
import pickle
data = pickle.loads(input)
'''
        # File matching pattern should be exempt
        violations = engine.evaluate(code, context, "legacy/old_code.py")
        assert not any(v.policy_id == "POL-001" for v in violations)

        # File not matching pattern should still be flagged
        violations = engine.evaluate(code, context, "src/new_code.py")
        assert any(v.policy_id == "POL-001" for v in violations)

    def test_expired_exception_not_applied(self, context):
        """Expired exceptions should not exempt files."""
        engine = PolicyEngine()
        engine.add_exception(PolicyException(
            policy_id="POL-001",
            file_pattern="legacy/*.py",
            reason="Legacy code",
            approved_by="security-lead",
            expires=datetime.now() - timedelta(days=1),  # Expired yesterday
        ))

        code = '''
import pickle
'''
        violations = engine.evaluate(code, context, "legacy/old_code.py")
        # Expired exception should not exempt the file
        assert any(v.policy_id == "POL-001" for v in violations)


# =============================================================================
# REPORT GENERATION TESTS
# =============================================================================

class TestReportGeneration:
    """Test policy violation report generation."""

    def test_generates_report(self, engine, context):
        """Report should be generated for violations."""
        code = '''
import pickle
card = "4111111111111111"
'''
        violations = engine.evaluate(code, context)
        report = engine.generate_report(violations)

        assert "POLICY VIOLATION REPORT" in report
        assert "POL-001" in report
        assert "POL-PCI-001" in report
        assert "PCI-DSS" in report

    def test_empty_report_for_clean_code(self, engine, context):
        """Clean code should produce success message."""
        code = '''
import json

def process(data: str) -> dict:
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return {}
'''
        violations = engine.evaluate(code, context)
        report = engine.generate_report(violations)

        assert "No policy violations found" in report


# =============================================================================
# FRAMEWORK FILTERING TESTS
# =============================================================================

class TestFrameworkFiltering:
    """Test filtering policies by compliance framework."""

    def test_get_pci_policies(self, engine):
        """Should return only PCI-DSS policies."""
        pci_policies = engine.get_policies_by_framework("PCI-DSS")
        assert len(pci_policies) >= 2
        assert all(p.compliance_framework == "PCI-DSS" for p in pci_policies)

    def test_get_hipaa_policies(self, engine):
        """Should return only HIPAA policies."""
        hipaa_policies = engine.get_policies_by_framework("HIPAA")
        assert len(hipaa_policies) >= 1
        assert all(p.compliance_framework == "HIPAA" for p in hipaa_policies)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """Integration tests for PolicyEngine."""

    def test_multiple_violations_same_file(self, engine, context):
        """Multiple policy violations in one file should all be detected."""
        code = '''
import pickle
import telnetlib

card_number = "4111111111111111"
cvv = "123"
patient_id = "P12345"

def process(data):
    try:
        return pickle.loads(data)
    except:
        pass
'''
        violations = engine.evaluate(code, context)

        # Should detect multiple types of violations
        policy_ids = {v.policy_id for v in violations}
        assert "POL-001" in policy_ids  # pickle
        assert "POL-002" in policy_ids  # telnetlib
        assert "POL-PCI-001" in policy_ids  # card number
        assert "POL-011" in policy_ids  # bare except

    def test_severity_levels(self, engine, context):
        """Violations should have correct severity levels."""
        code = '''
import pickle
import telnetlib
card = "4111111111111111"

def process(data):
    return data
'''
        violations = engine.evaluate(code, context)

        severities = {v.policy_id: v.severity for v in violations}
        assert severities.get("POL-001") == Severity.HIGH  # pickle
        assert severities.get("POL-002") == Severity.MEDIUM  # telnetlib
        assert severities.get("POL-PCI-001") == Severity.CRITICAL  # card
        assert severities.get("POL-010") == Severity.LOW  # type hints
