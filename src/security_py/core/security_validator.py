"""
Security Validator - 5-Layer Hybrid Governance Engine

Orchestrates the deterministic, semantic, operational, AI auditor, and persistence
layers to provide comprehensive security scanning for Python code.

Persistence Bridge:
- AUTO_BLOCKED: Both AIAuditor and TaintVisitor agree on CRITICAL
- NEEDS_HUMAN_REVIEW: AIAuditor and TaintVisitor disagree

Returns sys.exit(1) on any CRITICAL violation.
"""

import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from ..types.violations import (
    SecurityViolation,
    SemanticViolation,
    OperationalViolation,
    Severity,
    ScanContext,
    ValidationResult,
)
from .scan_engine import ScanEngine
from .taint_visitor import TaintVisitor
from .shell_guard import ShellGuard


class ReviewStatus(str, Enum):
    """Status flags for SOC Ledger entries."""
    AUTO_BLOCKED = "AUTO_BLOCKED"           # Both AI and AST agree: CRITICAL
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"  # AI and AST disagree
    AUTO_APPROVED = "AUTO_APPROVED"         # Both agree: safe
    PENDING = "PENDING"                     # Not yet reviewed


@dataclass
class ValidatorConfig:
    """Configuration for the SecurityValidator."""
    enable_deterministic: bool = True
    enable_semantic: bool = True
    enable_operational: bool = True
    enable_ai_auditor: bool = False      # AI Auditor (requires Ollama)
    enable_persistence: bool = True      # SOC Ledger logging
    enforcement_mode: str = "STRICT"     # STRICT, ADVISORY, DISABLED
    exit_on_critical: bool = True
    max_scan_duration_ms: int = 60000
    file_extensions: tuple[str, ...] = (".py",)
    agent_id: str = "security-validator"  # Agent attribution for SOC Ledger
    db_path: str = "security_ledger.db"   # SQLite database path


@dataclass
class LayerBreakdown:
    """Violation counts per layer."""
    deterministic: int = 0
    semantic: int = 0
    operational: int = 0

    @property
    def total(self) -> int:
        return self.deterministic + self.semantic + self.operational


@dataclass
class EnhancedValidationResult(ValidationResult):
    """Extended validation result with layer breakdown and review status."""
    layer_breakdown: LayerBreakdown = field(default_factory=LayerBreakdown)
    deterministic_violations: list[SecurityViolation] = field(default_factory=list)
    semantic_violations: list[SemanticViolation] = field(default_factory=list)
    operational_violations: list[OperationalViolation] = field(default_factory=list)
    review_status: ReviewStatus = ReviewStatus.PENDING
    ai_confidence: float = 0.0
    ai_agrees_with_ast: bool = True
    scan_record_id: Optional[int] = None  # SOC Ledger record ID


class SecurityValidator:
    """
    5-Layer Hybrid Governance Validator for Python code.
    
    Orchestrates:
    - Layer 1: Deterministic pattern matching (OWASP LLM patterns)
    - Layer 2: Semantic AST analysis (taint tracking)
    - Layer 3: Operational guardrails (shell command protection)
    - Layer 4: AI Auditor (DeepSeek-R1 via Ollama)
    - Layer 5: Persistence (SOC Ledger with review status)
    
    Persistence Bridge Logic:
    - AUTO_BLOCKED: Both AI and AST agree violation is CRITICAL
    - NEEDS_HUMAN_REVIEW: AI and AST disagree on severity
    - AUTO_APPROVED: Both agree code is safe
    
    Example usage:
        validator = SecurityValidator()
        result = validator.validate_file("app.py")
        # Result logged to SOC Ledger with review_status
    """

    def __init__(self, config: Optional[ValidatorConfig] = None):
        self.config = config or ValidatorConfig()
        
        # Layer 1-3: Core security layers
        self._scan_engine = ScanEngine() if self.config.enable_deterministic else None
        self._taint_visitor = TaintVisitor() if self.config.enable_semantic else None
        self._shell_guard = ShellGuard(
            enforcement_mode=self.config.enforcement_mode
        ) if self.config.enable_operational else None
        
        # Layer 4: AI Auditor (lazy initialization)
        self._ai_auditor = None
        
        # Layer 5: SOC Ledger (lazy initialization)
        self._soc_ledger = None
        
        self._is_scanning = False

    def validate_content(
        self,
        content: str,
        context: ScanContext,
        file_path: str = "<string>",
    ) -> EnhancedValidationResult:
        """
        Validate Python source code content through all layers.
        
        Args:
            content: Python source code
            context: Scan context with metadata
            file_path: Path to the source file
            
        Returns:
            EnhancedValidationResult with violations from all layers
        """
        start_time = time.time()
        
        deterministic_violations: list[SecurityViolation] = []
        semantic_violations: list[SemanticViolation] = []
        operational_violations: list[OperationalViolation] = []

        # Layer 1: Deterministic Pattern Matching
        if self._scan_engine:
            print("🔍 Layer 1: Deterministic Pattern Matching")
            deterministic_violations = self._scan_engine.scan_content(
                content, file_path, context
            )
            print(f"   Found {len(deterministic_violations)} deterministic violations")

        # Layer 2: Semantic AST Analysis
        if self._taint_visitor:
            print("🧠 Layer 2: Semantic AST Analysis")
            semantic_violations = self._taint_visitor.analyze(
                content, context, file_path
            )
            print(f"   Found {len(semantic_violations)} semantic violations")

        # Layer 3: Operational Guardrails (scan for shell commands in code)
        if self._shell_guard:
            print("🔒 Layer 3: Operational Guardrails")
            operational_violations = self._scan_shell_commands(content, file_path)
            print(f"   Found {len(operational_violations)} operational violations")

        # Combine all violations
        all_violations: list[SecurityViolation] = [
            *deterministic_violations,
            *semantic_violations,
            *operational_violations,
        ]

        scan_duration_ms = (time.time() - start_time) * 1000
        
        # Check for CRITICAL violations from AST (deterministic + semantic)
        ast_has_critical = any(
            v.severity == Severity.CRITICAL 
            for v in [*deterministic_violations, *semantic_violations]
        )
        
        # Layer 4: AI Auditor (if enabled)
        ai_confidence = 0.0
        ai_agrees_with_ast = True
        ai_has_critical = False
        
        if self.config.enable_ai_auditor:
            ai_result = self._run_ai_audit(content, all_violations, context)
            if ai_result:
                ai_confidence = ai_result.get("confidence", 0.0)
                ai_has_critical = ai_result.get("is_critical", False)
                ai_agrees_with_ast = (ast_has_critical == ai_has_critical)
        
        # Determine review status based on AI + AST agreement
        review_status = self._determine_review_status(
            ast_has_critical, ai_has_critical, ai_agrees_with_ast, all_violations
        )
        
        # Build result
        has_blocking = any(
            v.severity in (Severity.CRITICAL, Severity.HIGH) 
            for v in all_violations
        )
        
        result = EnhancedValidationResult(
            passed=len(all_violations) == 0,
            violations=all_violations,
            scan_duration_ms=scan_duration_ms,
            can_proceed=not has_blocking,
            requires_override=has_blocking,
            layer_breakdown=LayerBreakdown(
                deterministic=len(deterministic_violations),
                semantic=len(semantic_violations),
                operational=len(operational_violations),
            ),
            deterministic_violations=deterministic_violations,
            semantic_violations=semantic_violations,
            operational_violations=operational_violations,
            review_status=review_status,
            ai_confidence=ai_confidence,
            ai_agrees_with_ast=ai_agrees_with_ast,
        )

        # Layer 5: Persistence - Log to SOC Ledger
        if self.config.enable_persistence:
            scan_record_id = self._log_to_soc_ledger(
                content, file_path, result, context
            )
            result.scan_record_id = scan_record_id

        # Exit on CRITICAL if configured
        if self.config.exit_on_critical and result.has_critical:
            self._print_critical_report(result)
            sys.exit(1)

        return result

    def validate_file(
        self,
        file_path: Path | str,
        context: Optional[ScanContext] = None,
    ) -> EnhancedValidationResult:
        """
        Validate a Python file through all security layers.
        
        Args:
            file_path: Path to the Python file
            context: Optional scan context
            
        Returns:
            EnhancedValidationResult with violations
        """
        file_path = Path(file_path)
        
        if context is None:
            context = ScanContext(
                project_path=str(file_path.parent),
                phase="SCAN",
                developer_id="system",
                modified_files=[str(file_path)],
            )

        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            return EnhancedValidationResult(
                passed=False,
                violations=[
                    SecurityViolation(
                        severity=Severity.MEDIUM,
                        category="FILE_ERROR",
                        title="Could not read file",
                        description=str(e),
                        file=str(file_path),
                        line=0,
                        code_snippet="",
                        recommendation="Check file exists and is readable",
                    )
                ],
                scan_duration_ms=0,
                can_proceed=True,
                requires_override=False,
            )

        return self.validate_content(content, context, str(file_path))

    def validate_directory(
        self,
        directory: Path | str,
        context: Optional[ScanContext] = None,
    ) -> EnhancedValidationResult:
        """
        Validate all Python files in a directory.
        
        Args:
            directory: Root directory to scan
            context: Optional scan context
            
        Returns:
            Combined EnhancedValidationResult
        """
        directory = Path(directory)
        
        if context is None:
            context = ScanContext(
                project_path=str(directory),
                phase="SCAN",
                developer_id="system",
            )

        start_time = time.time()
        all_deterministic: list[SecurityViolation] = []
        all_semantic: list[SemanticViolation] = []
        all_operational: list[OperationalViolation] = []

        file_count = 0
        for file_path in directory.rglob("*"):
            if file_path.suffix not in self.config.file_extensions:
                continue
            if not file_path.is_file():
                continue
            # Skip common non-source directories
            if any(part in file_path.parts for part in 
                   ("venv", ".venv", "node_modules", "__pycache__", ".git")):
                continue

            file_count += 1
            result = self.validate_file(file_path, context)
            all_deterministic.extend(result.deterministic_violations)
            all_semantic.extend(result.semantic_violations)
            all_operational.extend(result.operational_violations)

        print(f"\n📊 Scanned {file_count} Python files")

        all_violations = [*all_deterministic, *all_semantic, *all_operational]
        scan_duration_ms = (time.time() - start_time) * 1000
        
        has_blocking = any(
            v.severity in (Severity.CRITICAL, Severity.HIGH) 
            for v in all_violations
        )

        return EnhancedValidationResult(
            passed=len(all_violations) == 0,
            violations=all_violations,
            scan_duration_ms=scan_duration_ms,
            can_proceed=not has_blocking,
            requires_override=has_blocking,
            layer_breakdown=LayerBreakdown(
                deterministic=len(all_deterministic),
                semantic=len(all_semantic),
                operational=len(all_operational),
            ),
            deterministic_violations=all_deterministic,
            semantic_violations=all_semantic,
            operational_violations=all_operational,
        )

    def validate_shell_command(
        self,
        command: str,
        working_directory: str = ".",
    ) -> Optional[OperationalViolation]:
        """
        Validate a shell command before execution.
        
        Args:
            command: Shell command to validate
            working_directory: Current working directory
            
        Returns:
            OperationalViolation if command is blocked, None if allowed
        """
        if not self._shell_guard:
            return None

        result = self._shell_guard.intercept(command, working_directory)
        return result.violation

    def _scan_shell_commands(
        self,
        content: str,
        file_path: str,
    ) -> list[OperationalViolation]:
        """
        Scan code for shell command invocations.
        
        Looks for os.system(), subprocess calls with dangerous commands.
        """
        violations: list[OperationalViolation] = []
        
        if not self._shell_guard:
            return violations

        # Patterns that indicate shell command usage
        import re
        
        # Find os.system() calls
        os_system_pattern = re.compile(
            r'os\.system\s*\(\s*["\']([^"\']+)["\']',
            re.MULTILINE
        )
        for match in os_system_pattern.finditer(content):
            command = match.group(1)
            result = self._shell_guard.intercept(command)
            if not result.allowed and result.violation:
                # Update file/line info
                line_num = content[:match.start()].count('\n') + 1
                violations.append(OperationalViolation(
                    severity=result.violation.severity,
                    category="OPERATIONAL",
                    title=result.violation.title,
                    description=f"os.system() with dangerous command: {result.violation.description}",
                    file=file_path,
                    line=line_num,
                    code_snippet=match.group(0)[:80],
                    recommendation=result.violation.recommendation,
                    cwe_reference="CWE-78",
                    command=result.violation.command,
                    args=result.violation.args,
                    working_directory=file_path,
                    operational_risk=result.violation.operational_risk,
                    shell_context="Static analysis of source code",
                ))

        # Find subprocess calls with shell commands
        subprocess_pattern = re.compile(
            r'subprocess\.(?:run|call|Popen)\s*\(\s*["\']([^"\']+)["\']',
            re.MULTILINE
        )
        for match in subprocess_pattern.finditer(content):
            command = match.group(1)
            result = self._shell_guard.intercept(command)
            if not result.allowed and result.violation:
                line_num = content[:match.start()].count('\n') + 1
                violations.append(OperationalViolation(
                    severity=result.violation.severity,
                    category="OPERATIONAL",
                    title=result.violation.title,
                    description=f"subprocess with dangerous command: {result.violation.description}",
                    file=file_path,
                    line=line_num,
                    code_snippet=match.group(0)[:80],
                    recommendation=result.violation.recommendation,
                    cwe_reference="CWE-78",
                    command=result.violation.command,
                    args=result.violation.args,
                    working_directory=file_path,
                    operational_risk=result.violation.operational_risk,
                    shell_context="Static analysis of source code",
                ))

        return violations

    def _run_ai_audit(
        self,
        content: str,
        violations: list[SecurityViolation],
        context: ScanContext,
    ) -> Optional[dict]:
        """
        Run AI Auditor analysis (Layer 4).
        
        Returns dict with 'confidence' and 'is_critical' keys.
        """
        try:
            if self._ai_auditor is None:
                from .ai_auditor import AIAuditor
                self._ai_auditor = AIAuditor()
            
            if not self._ai_auditor.llm_available:
                print("🤖 Layer 4: AI Auditor (skipped - Ollama unavailable)")
                return None
            
            print("🤖 Layer 4: AI Auditor Analysis")
            audit_result = self._ai_auditor.audit(content, violations, context)
            
            is_critical = False
            if audit_result.llm_response:
                is_critical = (
                    audit_result.llm_response.vulnerability and 
                    audit_result.llm_response.severity == "CRITICAL"
                )
            
            print(f"   AI Confidence: {audit_result.confidence:.2f}")
            print(f"   AI Decision: {audit_result.decision.value}")
            
            return {
                "confidence": audit_result.confidence,
                "is_critical": is_critical,
                "decision": audit_result.decision.value,
            }
        except Exception as e:
            print(f"🤖 Layer 4: AI Auditor (error: {e})")
            return None

    def _determine_review_status(
        self,
        ast_has_critical: bool,
        ai_has_critical: bool,
        ai_agrees_with_ast: bool,
        violations: list[SecurityViolation],
    ) -> ReviewStatus:
        """
        Determine review status based on AI + AST agreement.
        
        Logic:
        - AUTO_BLOCKED: Both AI and AST agree on CRITICAL
        - NEEDS_HUMAN_REVIEW: AI and AST disagree
        - AUTO_APPROVED: Both agree code is safe (no violations)
        - PENDING: Default state
        """
        if not violations:
            return ReviewStatus.AUTO_APPROVED
        
        if ast_has_critical and ai_has_critical and ai_agrees_with_ast:
            print("   📋 Review Status: AUTO_BLOCKED (AI + AST agree: CRITICAL)")
            return ReviewStatus.AUTO_BLOCKED
        
        if not ai_agrees_with_ast:
            print("   📋 Review Status: NEEDS_HUMAN_REVIEW (AI and AST disagree)")
            return ReviewStatus.NEEDS_HUMAN_REVIEW
        
        if ast_has_critical:
            # AST found critical, AI not enabled or unavailable
            return ReviewStatus.AUTO_BLOCKED
        
        return ReviewStatus.PENDING

    def _log_to_soc_ledger(
        self,
        content: str,
        file_path: str,
        result: EnhancedValidationResult,
        context: ScanContext,
    ) -> Optional[int]:
        """
        Log scan result to SOC Ledger (Layer 5).
        
        Returns the scan record ID.
        """
        try:
            if self._soc_ledger is None:
                from .soc_ledger import SOCLedger, SecurityLevel
                self._soc_ledger = SOCLedger(self.config.db_path)
            
            print("📝 Layer 5: SOC Ledger Persistence")
            
            # Determine security level based on review status
            from .soc_ledger import SecurityLevel
            if result.review_status == ReviewStatus.AUTO_BLOCKED:
                security_level = SecurityLevel.RESTRICTED
            elif result.review_status == ReviewStatus.NEEDS_HUMAN_REVIEW:
                security_level = SecurityLevel.CONFIDENTIAL
            else:
                security_level = SecurityLevel.INTERNAL
            
            # Count critical violations
            critical_count = sum(
                1 for v in result.violations if v.severity == Severity.CRITICAL
            )
            
            # Log the scan
            record = self._soc_ledger.log_scan(
                agent_id=self.config.agent_id,
                source_file=file_path,
                content=content,
                violation_count=len(result.violations),
                critical_count=critical_count,
                passed=result.passed,
                scan_duration_ms=result.scan_duration_ms,
                security_level=security_level,
            )
            
            print(f"   Logged scan #{record.id} (status: {result.review_status.value})")
            return record.id
            
        except Exception as e:
            print(f"📝 Layer 5: SOC Ledger (error: {e})")
            return None

    def _print_critical_report(self, result: EnhancedValidationResult) -> None:
        """Print a report of critical violations before exit."""
        print("\n" + "=" * 60)
        print("🚨 CRITICAL SECURITY VIOLATIONS DETECTED")
        print("=" * 60)
        
        critical_violations = [
            v for v in result.violations 
            if v.severity == Severity.CRITICAL
        ]
        
        for i, violation in enumerate(critical_violations, 1):
            print(f"\n{i}. [{violation.severity.value}] {violation.title}")
            print(f"   File: {violation.file}:{violation.line}")
            print(f"   {violation.description}")
            print(f"   Code: {violation.code_snippet[:60]}...")
            print(f"   Fix: {violation.recommendation}")
        
        print("\n" + "=" * 60)
        print(f"Total: {len(critical_violations)} CRITICAL violations")
        print("Exiting with code 1 - fix violations before proceeding")
        print("=" * 60 + "\n")

    def get_security_score(self, result: EnhancedValidationResult) -> int:
        """
        Calculate security score (0-100) based on violations.
        
        Deductions:
        - CRITICAL: 25 points
        - HIGH: 15 points
        - MEDIUM: 10 points
        - LOW: 5 points
        """
        score = 100
        deductions = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
        }
        
        for violation in result.violations:
            score -= deductions.get(violation.severity, 0)
        
        return max(0, score)

    def generate_report(self, result: EnhancedValidationResult) -> str:
        """Generate a formatted security report."""
        lines = [
            "=" * 60,
            "🛡️ SECURITY VALIDATION REPORT",
            "=" * 60,
            f"Status: {'✅ PASSED' if result.passed else '❌ FAILED'}",
            f"Security Score: {self.get_security_score(result)}/100",
            f"Scan Duration: {result.scan_duration_ms:.2f}ms",
            "",
            "📊 LAYER BREAKDOWN:",
            f"   Deterministic: {result.layer_breakdown.deterministic} violations",
            f"   Semantic:      {result.layer_breakdown.semantic} violations",
            f"   Operational:   {result.layer_breakdown.operational} violations",
            f"   Total:         {result.layer_breakdown.total} violations",
            "",
        ]

        if result.violations:
            lines.append("🚨 VIOLATIONS:")
            for i, v in enumerate(result.violations, 1):
                lines.extend([
                    f"\n{i}. [{v.severity.value}] {v.title}",
                    f"   File: {v.file}:{v.line}",
                    f"   {v.description}",
                    f"   Fix: {v.recommendation}",
                ])
        else:
            lines.append("✅ No security violations detected!")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)


def main():
    """CLI entry point for security validation."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Python Security Validator - 3-Layer Security Mesh"
    )
    parser.add_argument(
        "path",
        help="File or directory to scan",
    )
    parser.add_argument(
        "--no-exit",
        action="store_true",
        help="Don't exit on CRITICAL violations",
    )
    parser.add_argument(
        "--mode",
        choices=["STRICT", "ADVISORY", "DISABLED"],
        default="STRICT",
        help="Enforcement mode",
    )
    
    args = parser.parse_args()
    
    config = ValidatorConfig(
        exit_on_critical=not args.no_exit,
        enforcement_mode=args.mode,
    )
    
    validator = SecurityValidator(config)
    path = Path(args.path)
    
    if path.is_file():
        result = validator.validate_file(path)
    else:
        result = validator.validate_directory(path)
    
    print(validator.generate_report(result))
    
    if not result.passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
