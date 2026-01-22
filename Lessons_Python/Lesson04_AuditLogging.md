# 🎓 Lesson 04: Audit Logging - Immutable Security Records

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- Why audit logging is critical for security forensics
- How to create immutable, tamper-evident logs
- Best practices for security event recording

---

## 📋 Why Audit Logging Matters

Every security decision needs a paper trail:
- **Forensics**: Investigate incidents after they happen
- **Compliance**: Meet SOC2, HIPAA, PCI-DSS requirements
- **Accountability**: Who approved what override and when?

```
┌─────────────────────────────────────────────────────┐
│  Security Event → Audit Logger → Immutable Log     │
│                                                     │
│  • Scan started    • Hash chained                  │
│  • Violation found • Timestamp signed              │
│  • Override given  • Cannot be modified            │
└─────────────────────────────────────────────────────┘
```

---

## 🐍 AuditLogger Implementation

```python
# Line 1: src/security_py/core/audit_logger.py
import hashlib
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import uuid

# Line 11: Audit entry types
@dataclass
class AuditEntry:
    """Immutable audit log entry."""
    id: str
    timestamp: str
    event_type: str
    developer_id: str
    details: dict
    previous_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of entry content."""
        content = json.dumps({
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "developer_id": self.developer_id,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

# Line 36: The audit logger class
class AuditLogger:
    """
    Immutable, hash-chained audit logging for security events.
    
    Each entry includes a hash of the previous entry, creating
    a tamper-evident chain similar to a blockchain.
    """

    def __init__(self, log_path: Optional[Path] = None):
        self._log_path = log_path or Path("security_audit.log")
        self._previous_hash = "GENESIS"
        self._logger = logging.getLogger("security_audit")
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure file and console logging."""
        handler = logging.FileHandler(self._log_path)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)
```

---

## 🔐 Hash Chain for Tamper Evidence

```python
# Line 1: Creating hash-chained entries
def log_event(
    self,
    event_type: str,
    developer_id: str,
    details: dict,
) -> AuditEntry:
    """Log an event with hash chaining."""
    entry = AuditEntry(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=event_type,
        developer_id=developer_id,
        details=details,
        previous_hash=self._previous_hash,
    )
    
    # Line 18: Compute hash including previous hash
    entry.entry_hash = entry.compute_hash()
    
    # Line 21: Update chain
    self._previous_hash = entry.entry_hash
    
    # Line 24: Write to log
    self._logger.info(json.dumps(asdict(entry)))
    
    return entry

# Line 29: How hash chaining works:
# Entry 1: hash(content + "GENESIS")     → abc123
# Entry 2: hash(content + "abc123")      → def456
# Entry 3: hash(content + "def456")      → ghi789
# 
# If someone modifies Entry 2, its hash changes,
# which breaks Entry 3's previous_hash reference!
```

### Verifying the Chain

```python
# Line 1: Verify log integrity
def verify_chain(self) -> tuple[bool, Optional[str]]:
    """Verify the hash chain is intact."""
    entries = self._load_all_entries()
    
    expected_previous = "GENESIS"
    for entry in entries:
        # Line 8: Verify previous hash matches
        if entry.previous_hash != expected_previous:
            return False, f"Chain broken at {entry.id}"
        
        # Line 12: Verify entry hash is correct
        computed = entry.compute_hash()
        if entry.entry_hash != computed:
            return False, f"Entry {entry.id} was modified"
        
        expected_previous = entry.entry_hash
    
    return True, None

# Line 21: Example verification
logger = AuditLogger()
is_valid, error = logger.verify_chain()
if not is_valid:
    print(f"⚠️ AUDIT LOG TAMPERED: {error}")
```

---

## 📝 Logging Security Events

```python
# Line 1: Log scan start
def log_scan_start(
    self,
    developer_id: str,
    project_path: str,
    agent_source: Optional[str] = None,
) -> AuditEntry:
    return self.log_event(
        event_type="SCAN_STARTED",
        developer_id=developer_id,
        details={
            "project_path": project_path,
            "agent_source": agent_source,
            "scan_scope": "FULL",
        },
    )

# Line 18: Log violations found
def log_violations(
    self,
    developer_id: str,
    violations: list[SecurityViolation],
) -> AuditEntry:
    return self.log_event(
        event_type="VIOLATIONS_DETECTED",
        developer_id=developer_id,
        details={
            "violation_count": len(violations),
            "critical_count": sum(1 for v in violations if v.severity == Severity.CRITICAL),
            "violations": [v.to_dict() for v in violations[:10]],  # Limit size
        },
    )

# Line 34: Log override decision
def log_override(
    self,
    developer_id: str,
    violation_id: str,
    justification: str,
    approved_by: Optional[str] = None,
) -> AuditEntry:
    return self.log_event(
        event_type="VIOLATION_OVERRIDDEN",
        developer_id=developer_id,
        details={
            "violation_id": violation_id,
            "justification": justification,
            "approved_by": approved_by or developer_id,
            "risk_accepted": True,
        },
    )
```

---

## 📊 Example Audit Log Output

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2026-01-21T14:30:00.000Z",
  "event_type": "SCAN_STARTED",
  "developer_id": "dev-alice",
  "details": {
    "project_path": "/projects/my-app",
    "agent_source": "windsurf",
    "scan_scope": "FULL"
  },
  "previous_hash": "abc123...",
  "entry_hash": "def456..."
}

{
  "id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
  "timestamp": "2026-01-21T14:30:05.000Z",
  "event_type": "VIOLATIONS_DETECTED",
  "developer_id": "dev-alice",
  "details": {
    "violation_count": 2,
    "critical_count": 1,
    "violations": [...]
  },
  "previous_hash": "def456...",
  "entry_hash": "ghi789..."
}
```

---

## 🔒 Security Best Practices

```python
# Line 1: Best practices for audit logging

# 1. Always use UTC timestamps
timestamp = datetime.now(timezone.utc).isoformat()

# 2. Never log sensitive data directly
def sanitize_for_log(data: dict) -> dict:
    """Remove or mask sensitive fields."""
    sensitive = ("password", "secret", "token", "key", "credential")
    return {
        k: "***REDACTED***" if any(s in k.lower() for s in sensitive) else v
        for k, v in data.items()
    }

# Line 14: 3. Use append-only log files
# Configure log file as append-only on Linux:
# chattr +a security_audit.log

# Line 18: 4. Rotate logs but preserve chain
def rotate_log(self) -> None:
    """Rotate log while preserving hash chain reference."""
    # Store final hash of old log
    final_hash = self._previous_hash
    # Start new log with reference
    self._previous_hash = f"ROTATED:{final_hash}"

# Line 26: 5. Sign entries with asymmetric keys (advanced)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def sign_entry(entry: AuditEntry, private_key) -> bytes:
    """Digitally sign an audit entry."""
    content = entry.compute_hash().encode()
    return private_key.sign(
        content,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
```

---

## 🎯 Check for Understanding

**Question**: Why do we include the previous entry's hash in each new entry?

*Think about what happens if someone tries to modify a middle entry...*

---

## 📚 Interview Prep

**Q: What's the difference between logging and audit logging?**

**A**:
- **Logging**: Debug info, errors, performance metrics - can be deleted/modified
- **Audit logging**: Security events, compliance records - must be immutable

```python
# Line 1: Regular logging - informational
logging.info("Processing request...")  # Can delete later

# Line 4: Audit logging - security event
audit.log_event("ACCESS_GRANTED", user_id, {"resource": "admin"})
# Must be preserved for compliance
```

**Q: How do you ensure audit logs can't be modified?**

**A**: Multiple layers of protection:
1. **Hash chaining**: Each entry references previous hash
2. **Digital signatures**: Sign entries with private key
3. **Append-only storage**: Use `chattr +a` on Linux
4. **Remote storage**: Send to immutable storage (S3 with object lock)
5. **Real-time replication**: Stream to separate audit system

**Q: What should you NOT log in security audit trails?**

**A**: Never log:
- Passwords or secrets (even hashed)
- Full credit card numbers
- Personal health information (PHI)
- Full social security numbers

Instead, log:
- User ID (not username if PII)
- Action taken
- Resource accessed
- Timestamp
- Result (success/failure)

```python
# Line 1: BAD - logs sensitive data
audit.log_event("LOGIN", user, {"password": "hunter2"})  # ❌

# Line 4: GOOD - logs only what's needed
audit.log_event("LOGIN", user_id, {"result": "success", "ip": "10.0.0.1"})  # ✅
```

---

## 🚀 Ready for Lesson 05?

In the next lesson, we'll learn about **Adversarial Testing** - how to break our own security system to make it stronger.

*Remember: If you can't prove it happened, it didn't happen - that's why audit logs exist!* 🛡️🐍
