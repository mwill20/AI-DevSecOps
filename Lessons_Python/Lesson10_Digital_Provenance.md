# 🎓 Lesson 10: Digital Provenance - Proving Code Integrity

## 🎯 Learning Objectives

By the end of this lesson, you'll understand:
- What digital provenance means for code security
- How to implement a cryptographic chain of custody
- How to verify files haven't been tampered with

---

## 🔐 What is Digital Provenance?

Provenance answers: **"Where did this code come from, and has it changed?"**

```
┌─────────────────────────────────────────────────────────────────┐
│                    CHAIN OF CUSTODY                              │
│                                                                  │
│  File Created ──→ Scan Passed ──→ Human Approved ──→ Deployed   │
│       │               │                │                │        │
│    hash_1          hash_2           hash_3          hash_4       │
│       │               │                │                │        │
│       └───────────────┴────────────────┴────────────────┘        │
│                                                                  │
│  Each hash includes the previous hash (blockchain-like chain)    │
│  If ANY hash changes, the chain is broken = TAMPERING DETECTED   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🐍 Content Hashing

```python
# Line 1: src/security_py/core/soc_ledger.py
import hashlib

class SOCLedger:
    """Security Operations Center Ledger."""
    
    @staticmethod
    def _compute_hash(content: str) -> str:
        """
        Compute SHA-256 hash of content.
        
        SHA-256 properties:
        - Deterministic: Same input → same hash
        - One-way: Cannot reverse hash to get content
        - Collision-resistant: Nearly impossible to find two 
          inputs with same hash
        - Avalanche effect: 1-bit change → completely different hash
        """
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

# Line 22: Example
content = "api_key = os.environ.get('API_KEY')"
hash_1 = SOCLedger._compute_hash(content)
# 'a1b2c3d4e5f6...' (64 hex chars)

# Line 27: Change one character
content_modified = "api_key = os.environ.get('API_KEY') "  # Added space
hash_2 = SOCLedger._compute_hash(content_modified)
# 'x9y8z7w6v5u4...' (completely different!)
```

---

## 📋 The Provenance Record

```python
# Line 1: Data structure for provenance
from dataclasses import dataclass
from typing import Optional

@dataclass
class ProvenanceRecord:
    """Chain of custody record for approved files."""
    id: Optional[int] = None
    file_path: str = ""
    content_hash: str = ""       # SHA-256 of file content
    approval_hash: str = ""      # Hash of this approval record
    approved_by: str = ""        # Who approved
    approved_at: str = ""        # When approved (ISO timestamp)
    parent_hash: Optional[str] = None  # Links to previous approval
    scan_id: Optional[int] = None      # Links to security scan
    metadata: str = "{}"         # Additional context (JSON)

# Line 19: The approval_hash includes:
# - file_path
# - content_hash
# - approved_by
# - approved_at
# - parent_hash (links to chain)
#
# This creates an immutable chain where modifying ANY record
# breaks the chain integrity.
```

---

## 🔗 Creating the Chain

```python
# Line 1: Approving a file (adding to chain)
def approve_file(
    self,
    file_path: str,
    content: str,
    approved_by: str,
    scan_id: Optional[int] = None,
    metadata: Optional[dict] = None,
) -> ProvenanceRecord:
    """
    Add file to provenance chain (Chain of Custody).
    
    Creates a cryptographic hash linking to previous approval.
    """
    # Line 15: Hash the content
    content_hash = self._compute_hash(content)
    approved_at = datetime.now(timezone.utc).isoformat()
    
    # Line 19: Get parent hash (previous approval for this file)
    parent_hash = self._get_latest_approval_hash(file_path)
    
    # Line 22: Compute approval hash (includes parent for chaining)
    approval_data = {
        "file_path": file_path,
        "content_hash": content_hash,
        "approved_by": approved_by,
        "approved_at": approved_at,
        "parent_hash": parent_hash,  # Links to chain!
    }
    approval_hash = self._compute_hash(
        json.dumps(approval_data, sort_keys=True)
    )
    
    # Line 34: Store in database
    conn = self._get_conn()
    cursor = conn.execute("""
        INSERT INTO provenance_chain
        (file_path, content_hash, approval_hash, approved_by, 
         approved_at, parent_hash, scan_id, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        file_path, content_hash, approval_hash, approved_by,
        approved_at, parent_hash, scan_id, json.dumps(metadata or {})
    ))
    conn.commit()
    
    return ProvenanceRecord(
        id=cursor.lastrowid,
        file_path=file_path,
        content_hash=content_hash,
        approval_hash=approval_hash,
        approved_by=approved_by,
        approved_at=approved_at,
        parent_hash=parent_hash,
        scan_id=scan_id,
    )
```

---

## ✅ Verifying Provenance

```python
# Line 1: Verify file hasn't been tampered with
def verify_provenance(
    self,
    file_path: str,
    content: str,
) -> tuple[bool, str]:
    """
    Verify file hasn't been tampered with since approval.
    
    Returns:
        (is_valid, message)
    """
    # Line 13: Hash current content
    content_hash = self._compute_hash(content)
    
    # Line 16: Get latest approval record
    conn = self._get_conn()
    row = conn.execute("""
        SELECT * FROM provenance_chain
        WHERE file_path = ?
        ORDER BY approved_at DESC
        LIMIT 1
    """, (file_path,)).fetchone()
    
    # Line 25: No record = never approved
    if not row:
        return False, "No provenance record found for this file"
    
    record = ProvenanceRecord(**dict(row))
    
    # Line 31: Compare hashes
    if record.content_hash != content_hash:
        return False, (
            f"TAMPERING DETECTED: Content hash mismatch!\n"
            f"Expected: {record.content_hash[:16]}...\n"
            f"Got: {content_hash[:16]}...\n"
            f"File has been modified since approval by {record.approved_by}"
        )
    
    # Line 41: Verified!
    return True, (
        f"✅ Verified: File approved by {record.approved_by} "
        f"at {record.approved_at}"
    )
```

---

## 📊 Example: Full Provenance Workflow

```python
# Line 1: Complete provenance workflow
from security_py.core import SOCLedger, SecurityValidator

# Step 1: Scan the file
validator = SecurityValidator()
result = validator.validate_file("app.py")

# Line 8: Step 2: Log the scan
ledger = SOCLedger()
scan_record = ledger.log_scan(
    agent_id="windsurf-cascade",
    source_file="app.py",
    content=Path("app.py").read_text(),
    violation_count=result.total_violations,
    passed=result.passed,
)

# Line 18: Step 3: If passed, approve and add to chain
if result.passed:
    provenance = ledger.approve_file(
        file_path="app.py",
        content=Path("app.py").read_text(),
        approved_by="security-bot",
        scan_id=scan_record.id,
        metadata={"scan_score": 100},
    )
    print(f"Approved! Hash: {provenance.approval_hash[:16]}...")

# Line 30: Step 4: Later, verify before deployment
content = Path("app.py").read_text()
is_valid, message = ledger.verify_provenance("app.py", content)

if is_valid:
    print("✅ Deploying - provenance verified")
else:
    print(f"🚨 BLOCKED: {message}")
    sys.exit(1)
```

---

## 🔍 Viewing the Chain

```python
# Line 1: Get full provenance history
def get_provenance_chain(self, file_path: str) -> list[ProvenanceRecord]:
    """Get full provenance chain for a file."""
    conn = self._get_conn()
    rows = conn.execute("""
        SELECT * FROM provenance_chain
        WHERE file_path = ?
        ORDER BY approved_at DESC
    """, (file_path,)).fetchall()
    
    return [ProvenanceRecord(**dict(row)) for row in rows]

# Line 14: Example output for app.py:
# 
# Chain for app.py (3 approvals):
# 
# [3] 2026-01-21T14:30:00Z by alice
#     Hash: abc123... Parent: def456...
#     Metadata: {"scan_score": 100, "ticket": "SEC-456"}
#     
# [2] 2026-01-15T10:00:00Z by security-bot  
#     Hash: def456... Parent: ghi789...
#     Metadata: {"scan_score": 95}
#     
# [1] 2026-01-10T09:00:00Z by bob (INITIAL)
#     Hash: ghi789... Parent: None
#     Metadata: {"reason": "Initial security review"}
```

---

## 🎯 Check for Understanding

**Question**: Why include `parent_hash` in each approval record?

*Think about what happens if someone modifies a middle record in the chain...*

---

## 📚 Interview Prep

**Q: How is this different from Git commits?**

**A**: Key differences:

| Feature | Git | Provenance Chain |
|---------|-----|------------------|
| Purpose | Version control | Security approval |
| Stored | Code diffs | Approval metadata |
| Who | Developer | Security reviewer |
| When | Any commit | After scan passes |
| Verifies | History | Content + approval |

```python
# Line 1: Git tells you WHO changed WHAT
# Provenance tells you WHO APPROVED that it's SECURE

# Both are valuable - they serve different purposes
# Git: "Alice added this function yesterday"
# Provenance: "Security bot verified no vulnerabilities at 14:30"
```

**Q: What attacks does provenance prevent?**

**A**:
1. **Supply chain attacks**: Verify code came from approved source
2. **Insider threats**: Track who approved what
3. **Tampering**: Detect post-approval modifications
4. **Repudiation**: Immutable audit trail

```python
# Line 1: Attack scenario
# Attacker modifies approved file after deployment
# 
# Without provenance: No way to know file changed
# With provenance: verify_provenance() returns False
#                  "TAMPERING DETECTED: Content hash mismatch"
```

**Q: Why use SHA-256 instead of MD5?**

**A**: MD5 is broken for security:

```python
# Line 1: MD5 collision attack (proven feasible)
# Two different files can have same MD5 hash
# Attacker could substitute malicious file

# SHA-256: No known collision attacks
# 2^256 possible hashes ≈ atoms in observable universe
# Computationally infeasible to find collisions
```

---

## 🔬 Forensic Lab: Investigating a Hypothetical Breach

This section walks through how to use the SQLite Ledger to investigate a security incident. Imagine you've received an alert: **"Unauthorized code change detected in production."**

### Step 1: Connect to the Ledger

```python
# Line 1: Open the forensic investigation
import sqlite3
from datetime import datetime, timedelta
from security_py.core import SOCLedger, ProvenanceStatus

# Connect to the security ledger
ledger = SOCLedger("security_ledger.db")

# Alternative: Direct SQL for forensic queries
conn = sqlite3.connect("security_ledger.db")
conn.row_factory = sqlite3.Row
```

### Step 2: Identify the Compromised File

```python
# Line 1: Find files modified without human approval (SHADOW CODE)
suspicious_files = conn.execute("""
    SELECT 
        sr.source_file,
        sr.agent_id,
        sr.timestamp,
        sr.content_hash,
        sr.human_signoff_hash,
        sr.violation_count
    FROM scan_records sr
    WHERE sr.human_signoff_hash IS NULL
      AND sr.timestamp > datetime('now', '-24 hours')
    ORDER BY sr.timestamp DESC
""").fetchall()

print("🚨 FILES MODIFIED WITHOUT HUMAN APPROVAL (Last 24h):")
for f in suspicious_files:
    print(f"  {f['source_file']}")
    print(f"    Agent: {f['agent_id']}")
    print(f"    Time: {f['timestamp']}")
    print(f"    Hash: {f['content_hash'][:16]}...")
    print(f"    Signoff: {'❌ NONE' if not f['human_signoff_hash'] else '✅'}")
    print()
```

### Step 3: Check Provenance Chain Integrity

```python
# Line 1: Verify the provenance chain hasn't been tampered with
def verify_chain_integrity(file_path: str) -> list[dict]:
    """Walk the chain and verify each link."""
    chain = ledger.get_provenance_chain(file_path)
    issues = []
    
    for i, record in enumerate(chain):
        if i < len(chain) - 1:
            expected_parent = chain[i + 1].approval_hash
            if record.parent_hash != expected_parent:
                issues.append({
                    "type": "CHAIN_BROKEN",
                    "record_id": record.id,
                    "expected_parent": expected_parent,
                    "actual_parent": record.parent_hash,
                })
    
    return issues

# Line 18: Check the suspicious file
for f in suspicious_files:
    issues = verify_chain_integrity(f['source_file'])
    if issues:
        print(f"🔴 CHAIN INTEGRITY FAILED for {f['source_file']}:")
        for issue in issues:
            print(f"    Record #{issue['record_id']}: {issue['type']}")
```

### Step 4: Identify the Rogue Agent

```python
# Line 1: Find which agent made unauthorized changes
rogue_agent_query = conn.execute("""
    SELECT 
        agent_id,
        COUNT(*) as unauthorized_changes,
        GROUP_CONCAT(DISTINCT source_file) as affected_files,
        MIN(timestamp) as first_incident,
        MAX(timestamp) as last_incident
    FROM scan_records
    WHERE human_signoff_hash IS NULL
      AND violation_count = 0  -- Claimed clean but no approval
    GROUP BY agent_id
    ORDER BY unauthorized_changes DESC
""").fetchall()

print("🕵️ AGENTS WITH UNAUTHORIZED CHANGES:")
for agent in rogue_agent_query:
    print(f"\n  Agent: {agent['agent_id']}")
    print(f"  Unauthorized changes: {agent['unauthorized_changes']}")
    print(f"  Affected files: {agent['affected_files']}")
    print(f"  Time window: {agent['first_incident']} to {agent['last_incident']}")
```

### Step 5: Shadow Code Detection

```python
# Line 1: Use the advanced provenance verification
from security_py.core.soc_ledger import ProvenanceStatus

def detect_shadow_code(file_path: str, current_content: str) -> dict:
    """
    Detect unauthorized AI modifications (Shadow Code).
    
    Shadow Code = File modified without human approval
    This is the #1 threat in autonomous AI systems.
    """
    status, message, record = ledger.verify_provenance_with_status(
        file_path, current_content
    )
    
    return {
        "file": file_path,
        "status": status.value,
        "message": message,
        "is_shadow_code": status == ProvenanceStatus.SHADOW_CODE,
        "last_approved_by": record.approved_by if record else None,
        "last_approved_at": record.approved_at if record else None,
    }

# Line 22: Check all production files
from pathlib import Path

production_files = Path("src/").rglob("*.py")
shadow_code_detected = []

for file_path in production_files:
    content = file_path.read_text()
    result = detect_shadow_code(str(file_path), content)
    
    if result["is_shadow_code"]:
        shadow_code_detected.append(result)
        print(f"🚨 SHADOW CODE: {result['file']}")
        print(f"   {result['message']}")

print(f"\nTotal shadow code files: {len(shadow_code_detected)}")
```

### Step 6: Generate Forensic Report

```python
# Line 1: Generate a complete forensic report
import json
from datetime import datetime

def generate_forensic_report(investigation_id: str) -> dict:
    """Generate a forensic report for incident response."""
    
    report = {
        "investigation_id": investigation_id,
        "generated_at": datetime.now().isoformat(),
        "findings": {
            "shadow_code_files": [],
            "chain_integrity_issues": [],
            "suspicious_agents": [],
            "timeline": [],
        },
        "recommendations": [],
    }
    
    # Collect all scan records from last 7 days
    recent_scans = conn.execute("""
        SELECT * FROM scan_records
        WHERE timestamp > datetime('now', '-7 days')
        ORDER BY timestamp ASC
    """).fetchall()
    
    # Build timeline
    for scan in recent_scans:
        report["findings"]["timeline"].append({
            "timestamp": scan["timestamp"],
            "agent": scan["agent_id"],
            "file": scan["source_file"],
            "had_approval": bool(scan["human_signoff_hash"]),
            "violations": scan["violation_count"],
        })
    
    # Add recommendations based on findings
    if shadow_code_detected:
        report["recommendations"].append(
            "CRITICAL: Revert all shadow code changes and re-scan"
        )
        report["recommendations"].append(
            "CRITICAL: Revoke credentials for suspicious agents"
        )
    
    return report

# Line 42: Save the report
report = generate_forensic_report("INC-2026-001")
Path("forensic_report.json").write_text(json.dumps(report, indent=2))
print("📋 Forensic report saved to forensic_report.json")
```

### Step 7: Remediation

```python
# Line 1: Quarantine and remediate
def quarantine_shadow_code(file_path: str):
    """Quarantine a file with shadow code."""
    
    # 1. Move to quarantine
    quarantine_path = Path("quarantine") / Path(file_path).name
    quarantine_path.parent.mkdir(exist_ok=True)
    Path(file_path).rename(quarantine_path)
    
    # 2. Restore from last approved version
    chain = ledger.get_provenance_chain(file_path)
    if chain:
        last_approved = chain[0]  # Most recent approval
        print(f"Restore from: {last_approved.approved_by} at {last_approved.approved_at}")
        print(f"Content hash: {last_approved.content_hash}")
        # In practice: git checkout <commit> -- <file>
    
    # 3. Log the quarantine action
    ledger.log_scan(
        agent_id="forensic-investigator",
        source_file=file_path,
        content="QUARANTINED",
        violation_count=1,
        critical_count=1,
        passed=False,
    )
    
    print(f"🔒 Quarantined: {file_path}")

# Line 28: Quarantine all shadow code
for result in shadow_code_detected:
    quarantine_shadow_code(result["file"])
```

---

## 🎯 Forensic Lab Takeaways

1. **Always log scans** - You can't investigate what you didn't record
2. **Require human signoff** - `human_signoff_hash` is your proof of approval
3. **Verify chain integrity** - Broken chains = tampering
4. **Monitor for shadow code** - AI changes without human approval = CRITICAL
5. **Keep forensic queries ready** - Have investigation SQL prepared before you need it

```python
# Line 1: The Forensic Investigator's Mantra
# "In a world of autonomous agents, Provenance is Truth."
# 
# If you can't prove WHO changed the code and WHY it was approved,
# you aren't running a SOC - you're just watching a screen.
```

---

## 🚀 Ready for Lesson 11?

In the next lesson, we'll explore **SOC Observability** - monitoring your AI's security behavior in real-time.

*Remember: If you can't prove provenance, you can't prove security!* 🛡️🐍
