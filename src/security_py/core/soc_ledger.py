"""
SOC Ledger - SQLite Persistence & Chain of Custody

Provides immutable audit logging with:
- Scan records with agent attribution
- Chain of custody with cryptographic hashes
- Human sign-off tracking
"""

import hashlib
import json
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from enum import Enum


class SecurityLevel(Enum):
    """Security clearance levels for operations."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class ProvenanceStatus(Enum):
    """Status of provenance verification."""
    VERIFIED = "VERIFIED"                    # Hash matches, human signoff present
    SHADOW_CODE = "SHADOW_CODE"              # Hash changed, NO human signoff (CRITICAL!)
    MODIFIED_APPROVED = "MODIFIED_APPROVED"  # Hash changed, has human signoff
    NO_RECORD = "NO_RECORD"                  # No provenance record exists
    CHAIN_BROKEN = "CHAIN_BROKEN"            # Parent hash doesn't match


@dataclass
class ScanRecord:
    """Record of a security scan."""
    id: Optional[int] = None
    agent_id: str = ""
    source_file: str = ""
    timestamp: str = ""
    security_level: str = SecurityLevel.INTERNAL.value
    violation_count: int = 0
    critical_count: int = 0
    passed: bool = True
    scan_duration_ms: float = 0.0
    human_signoff_hash: Optional[str] = None
    content_hash: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProvenanceRecord:
    """Chain of custody record for approved files."""
    id: Optional[int] = None
    file_path: str = ""
    content_hash: str = ""
    approval_hash: str = ""
    approved_by: str = ""
    approved_at: str = ""
    parent_hash: Optional[str] = None  # Links to previous approval
    scan_id: Optional[int] = None
    metadata: str = "{}"
    
    def to_dict(self) -> dict:
        return asdict(self)


class SOCLedger:
    """
    Security Operations Center Ledger.
    
    SQLite-based persistence for:
    - Scan records with agent attribution
    - Chain of custody provenance
    - Human sign-off verification
    """
    
    DEFAULT_DB_PATH = "security_ledger.db"
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or self.DEFAULT_DB_PATH
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()
    
    def _get_conn(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn
    
    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = self._get_conn()
        conn.executescript("""
            -- Scan Records Table
            CREATE TABLE IF NOT EXISTS scan_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                source_file TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                security_level TEXT DEFAULT 'INTERNAL',
                violation_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                passed BOOLEAN DEFAULT 1,
                scan_duration_ms REAL DEFAULT 0.0,
                human_signoff_hash TEXT,
                content_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Provenance Chain Table
            CREATE TABLE IF NOT EXISTS provenance_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                approval_hash TEXT NOT NULL UNIQUE,
                approved_by TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                parent_hash TEXT,
                scan_id INTEGER,
                metadata TEXT DEFAULT '{}',
                FOREIGN KEY (scan_id) REFERENCES scan_records(id),
                FOREIGN KEY (parent_hash) REFERENCES provenance_chain(approval_hash)
            );
            
            -- Violations Detail Table
            CREATE TABLE IF NOT EXISTS violations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                file_path TEXT,
                line_number INTEGER,
                code_snippet TEXT,
                recommendation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_records(id)
            );
            
            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_scan_agent ON scan_records(agent_id);
            CREATE INDEX IF NOT EXISTS idx_scan_file ON scan_records(source_file);
            CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_records(timestamp);
            CREATE INDEX IF NOT EXISTS idx_provenance_file ON provenance_chain(file_path);
            CREATE INDEX IF NOT EXISTS idx_provenance_hash ON provenance_chain(content_hash);
        """)
        conn.commit()
    
    # =========================================================================
    # SCAN RECORDS
    # =========================================================================
    
    def log_scan(
        self,
        agent_id: str,
        source_file: str,
        content: str,
        violation_count: int = 0,
        critical_count: int = 0,
        passed: bool = True,
        scan_duration_ms: float = 0.0,
        security_level: SecurityLevel = SecurityLevel.INTERNAL,
    ) -> ScanRecord:
        """Log a security scan to the ledger."""
        content_hash = self._compute_hash(content)
        timestamp = datetime.now(timezone.utc).isoformat()
        
        conn = self._get_conn()
        cursor = conn.execute("""
            INSERT INTO scan_records 
            (agent_id, source_file, timestamp, security_level, violation_count,
             critical_count, passed, scan_duration_ms, content_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            agent_id, source_file, timestamp, security_level.value,
            violation_count, critical_count, passed, scan_duration_ms, content_hash
        ))
        conn.commit()
        
        return ScanRecord(
            id=cursor.lastrowid,
            agent_id=agent_id,
            source_file=source_file,
            timestamp=timestamp,
            security_level=security_level.value,
            violation_count=violation_count,
            critical_count=critical_count,
            passed=passed,
            scan_duration_ms=scan_duration_ms,
            content_hash=content_hash,
        )
    
    def add_human_signoff(
        self,
        scan_id: int,
        approver_id: str,
        justification: str = "",
    ) -> str:
        """Add human sign-off to a scan record."""
        signoff_data = {
            "scan_id": scan_id,
            "approver_id": approver_id,
            "justification": justification,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        signoff_hash = self._compute_hash(json.dumps(signoff_data, sort_keys=True))
        
        conn = self._get_conn()
        conn.execute("""
            UPDATE scan_records SET human_signoff_hash = ? WHERE id = ?
        """, (signoff_hash, scan_id))
        conn.commit()
        
        return signoff_hash
    
    def get_scan(self, scan_id: int) -> Optional[ScanRecord]:
        """Retrieve a scan record by ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM scan_records WHERE id = ?", (scan_id,)
        ).fetchone()
        
        if row:
            return ScanRecord(**dict(row))
        return None
    
    def get_scans_by_agent(
        self,
        agent_id: str,
        limit: int = 100,
    ) -> list[ScanRecord]:
        """Get recent scans by agent ID."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM scan_records 
            WHERE agent_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (agent_id, limit)).fetchall()
        
        return [ScanRecord(**dict(row)) for row in rows]
    
    # =========================================================================
    # PROVENANCE CHAIN
    # =========================================================================
    
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
        content_hash = self._compute_hash(content)
        approved_at = datetime.now(timezone.utc).isoformat()
        
        # Get parent hash (previous approval for this file)
        parent_hash = self._get_latest_approval_hash(file_path)
        
        # Compute approval hash (includes parent for chain integrity)
        approval_data = {
            "file_path": file_path,
            "content_hash": content_hash,
            "approved_by": approved_by,
            "approved_at": approved_at,
            "parent_hash": parent_hash,
        }
        approval_hash = self._compute_hash(json.dumps(approval_data, sort_keys=True))
        
        conn = self._get_conn()
        cursor = conn.execute("""
            INSERT INTO provenance_chain
            (file_path, content_hash, approval_hash, approved_by, approved_at,
             parent_hash, scan_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            file_path, content_hash, approval_hash, approved_by, approved_at,
            parent_hash, scan_id, json.dumps(metadata or {})
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
            metadata=json.dumps(metadata or {}),
        )
    
    def verify_provenance(self, file_path: str, content: str) -> tuple[bool, str]:
        """
        Verify file hasn't been tampered with since approval.
        
        Returns:
            (is_valid, message)
        """
        content_hash = self._compute_hash(content)
        
        conn = self._get_conn()
        row = conn.execute("""
            SELECT * FROM provenance_chain
            WHERE file_path = ?
            ORDER BY approved_at DESC
            LIMIT 1
        """, (file_path,)).fetchone()
        
        if not row:
            return False, "No provenance record found for this file"
        
        record = ProvenanceRecord(**dict(row))
        
        if record.content_hash != content_hash:
            return False, f"Content hash mismatch: file has been modified since approval"
        
        return True, f"Verified: approved by {record.approved_by} at {record.approved_at}"
    
    def verify_provenance_with_status(
        self,
        file_path: str,
        content: str,
    ) -> tuple[ProvenanceStatus, str, Optional[ProvenanceRecord]]:
        """
        Advanced provenance verification with Shadow Code detection.
        
        CRITICAL: If a file's hash changes but has NO Human_Signoff_Hash,
        this is "Shadow Code" - unauthorized AI modifications.
        
        Returns:
            (status, message, record)
        """
        content_hash = self._compute_hash(content)
        
        conn = self._get_conn()
        
        # Get latest provenance record
        prov_row = conn.execute("""
            SELECT * FROM provenance_chain
            WHERE file_path = ?
            ORDER BY approved_at DESC
            LIMIT 1
        """, (file_path,)).fetchone()
        
        if not prov_row:
            return (
                ProvenanceStatus.NO_RECORD,
                "No provenance record exists for this file",
                None
            )
        
        record = ProvenanceRecord(**dict(prov_row))
        
        # Check if content matches
        if record.content_hash == content_hash:
            return (
                ProvenanceStatus.VERIFIED,
                f"Verified: approved by {record.approved_by} at {record.approved_at}",
                record
            )
        
        # Content has changed! Check for human signoff
        # Find the scan record associated with this provenance
        scan_row = conn.execute("""
            SELECT * FROM scan_records
            WHERE source_file = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (file_path,)).fetchone()
        
        if scan_row:
            scan_record = ScanRecord(**dict(scan_row))
            
            # SHADOW CODE DETECTION: Hash changed but NO human signoff
            if not scan_record.human_signoff_hash:
                return (
                    ProvenanceStatus.SHADOW_CODE,
                    f"🚨 SHADOW CODE DETECTED: File modified without human approval! "
                    f"Last approved hash: {record.content_hash[:16]}... "
                    f"Current hash: {content_hash[:16]}... "
                    f"Last agent: {scan_record.agent_id}",
                    record
                )
            else:
                return (
                    ProvenanceStatus.MODIFIED_APPROVED,
                    f"File modified but has human signoff: {scan_record.human_signoff_hash[:16]}...",
                    record
                )
        
        # No scan record but provenance exists - hash mismatch
        return (
            ProvenanceStatus.SHADOW_CODE,
            f"🚨 SHADOW CODE DETECTED: File modified with no scan record! "
            f"Last approved hash: {record.content_hash[:16]}...",
            record
        )
    
    def generate_cryptographic_proof(
        self,
        file_path: str,
        content: str,
        scan_id: int,
        agent_id: str,
    ) -> dict:
        """
        Generate a cryptographic proof for a scan.
        
        This proof can be used to verify:
        1. The exact content that was scanned
        2. When it was scanned
        3. Who/what scanned it
        4. The chain of custody
        
        Returns a proof dictionary that can be stored or transmitted.
        """
        content_hash = self._compute_hash(content)
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Get provenance chain
        chain = self.get_provenance_chain(file_path)
        chain_hashes = [r.approval_hash for r in chain]
        
        # Build proof
        proof_data = {
            "file_path": file_path,
            "content_hash": content_hash,
            "scan_id": scan_id,
            "agent_id": agent_id,
            "timestamp": timestamp,
            "provenance_chain_length": len(chain),
            "chain_tip": chain_hashes[0] if chain_hashes else None,
        }
        
        # Sign the proof (hash of all proof data)
        proof_signature = self._compute_hash(json.dumps(proof_data, sort_keys=True))
        proof_data["proof_signature"] = proof_signature
        
        return proof_data
    
    def validate_cryptographic_proof(self, proof: dict, content: str) -> tuple[bool, str]:
        """
        Validate a cryptographic proof against current content.
        
        Returns:
            (is_valid, message)
        """
        # Verify content hash
        current_hash = self._compute_hash(content)
        if proof.get("content_hash") != current_hash:
            return False, "Content hash mismatch - file has been modified"
        
        # Verify proof signature
        proof_copy = {k: v for k, v in proof.items() if k != "proof_signature"}
        expected_sig = self._compute_hash(json.dumps(proof_copy, sort_keys=True))
        
        if proof.get("proof_signature") != expected_sig:
            return False, "Proof signature invalid - proof has been tampered with"
        
        # Verify chain tip still exists
        if proof.get("chain_tip"):
            conn = self._get_conn()
            row = conn.execute("""
                SELECT 1 FROM provenance_chain WHERE approval_hash = ?
            """, (proof["chain_tip"],)).fetchone()
            
            if not row:
                return False, "Provenance chain tip not found - chain may have been tampered"
        
        return True, f"Proof valid: scan #{proof.get('scan_id')} by {proof.get('agent_id')}"
    
    def get_provenance_chain(self, file_path: str) -> list[ProvenanceRecord]:
        """Get full provenance chain for a file."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM provenance_chain
            WHERE file_path = ?
            ORDER BY approved_at DESC
        """, (file_path,)).fetchall()
        
        return [ProvenanceRecord(**dict(row)) for row in rows]
    
    def _get_latest_approval_hash(self, file_path: str) -> Optional[str]:
        """Get the most recent approval hash for a file."""
        conn = self._get_conn()
        row = conn.execute("""
            SELECT approval_hash FROM provenance_chain
            WHERE file_path = ?
            ORDER BY approved_at DESC
            LIMIT 1
        """, (file_path,)).fetchone()
        
        return row["approval_hash"] if row else None
    
    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def get_agent_stats(self) -> list[dict]:
        """Get violation statistics by agent."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT 
                agent_id,
                COUNT(*) as total_scans,
                SUM(violation_count) as total_violations,
                SUM(critical_count) as total_critical,
                AVG(scan_duration_ms) as avg_duration_ms
            FROM scan_records
            GROUP BY agent_id
            ORDER BY total_violations DESC
        """).fetchall()
        
        return [dict(row) for row in rows]
    
    def get_most_frequent_violator(self) -> Optional[dict]:
        """Get the agent/user with the most violations."""
        stats = self.get_agent_stats()
        return stats[0] if stats else None
    
    def get_recent_activity(self, hours: int = 24) -> list[ScanRecord]:
        """Get recent scan activity."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM scan_records
            WHERE timestamp >= datetime('now', ?)
            ORDER BY timestamp DESC
        """, (f'-{hours} hours',)).fetchall()
        
        return [ScanRecord(**dict(row)) for row in rows]
    
    # =========================================================================
    # UTILITIES
    # =========================================================================
    
    @staticmethod
    def _compute_hash(content: str) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
