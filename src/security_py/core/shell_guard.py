"""
Operational Layer - Shell Command Protection

Uses shlex.split() and subprocess.run(shell=False) to prevent command injection
while enforcing an allow_list.json policy. Intercepts and validates all shell
commands before execution.
"""

import json
import shlex
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..types.violations import (
    OperationalViolation,
    OperationalRisk,
    Severity,
)


@dataclass
class AllowedCommand:
    """Definition of an allowed command."""
    command: str
    description: str
    risk_level: Severity
    requires_approval: bool = False
    allowed_args: tuple[str, ...] = field(default_factory=tuple)
    blocked_args: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class BlockedCommand:
    """Definition of a blocked command."""
    command: str
    description: str
    reason: str
    severity: Severity


@dataclass
class ContextualRule:
    """Directory-specific command rules."""
    directory: str
    allowed_commands: tuple[str, ...] = field(default_factory=tuple)
    blocked_commands: tuple[str, ...] = field(default_factory=tuple)
    requires_approval: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class ShellAllowList:
    """Complete allow list configuration."""
    version: str
    enforcement_mode: str  # STRICT, ADVISORY, DISABLED
    allowed_commands: tuple[AllowedCommand, ...]
    blocked_commands: tuple[BlockedCommand, ...]
    contextual_rules: tuple[ContextualRule, ...]


@dataclass
class CommandResult:
    """Result of a command interception."""
    allowed: bool
    violation: Optional[OperationalViolation] = None
    requires_approval: bool = False
    approval_reason: str = ""


class ShellGuard:
    """
    Operational Layer: Intercepts and validates shell commands.
    
    Uses shlex for safe command parsing and enforces an allow list
    to prevent command injection and dangerous operations.
    
    Example usage:
        guard = ShellGuard()
        result = guard.intercept("rm -rf /important")
        if not result.allowed:
            print(f"Blocked: {result.violation.description}")
    """

    # Default blocked commands (CRITICAL security risks)
    DEFAULT_BLOCKED: tuple[BlockedCommand, ...] = (
        BlockedCommand("rm", "Remove files/directories", "Data destruction", Severity.CRITICAL),
        BlockedCommand("rmdir", "Remove directories", "Data destruction", Severity.CRITICAL),
        BlockedCommand("del", "Windows delete", "Data destruction", Severity.CRITICAL),
        BlockedCommand("format", "Format disk", "Data destruction", Severity.CRITICAL),
        BlockedCommand("mkfs", "Make filesystem", "Data destruction", Severity.CRITICAL),
        BlockedCommand("dd", "Disk duplicator", "Data destruction", Severity.CRITICAL),
        BlockedCommand("sudo", "Superuser execution", "Privilege escalation", Severity.CRITICAL),
        BlockedCommand("su", "Switch user", "Privilege escalation", Severity.CRITICAL),
        BlockedCommand("chmod", "Change permissions", "Security bypass", Severity.HIGH),
        BlockedCommand("chown", "Change ownership", "Privilege escalation", Severity.CRITICAL),
        BlockedCommand("kill", "Terminate process", "System modification", Severity.HIGH),
        BlockedCommand("killall", "Terminate processes", "System modification", Severity.HIGH),
        BlockedCommand("shutdown", "Shutdown system", "System modification", Severity.CRITICAL),
        BlockedCommand("reboot", "Reboot system", "System modification", Severity.CRITICAL),
        BlockedCommand("halt", "Halt system", "System modification", Severity.CRITICAL),
        BlockedCommand("init", "Change runlevel", "System modification", Severity.CRITICAL),
        BlockedCommand("systemctl", "System control", "System modification", Severity.HIGH),
        BlockedCommand("service", "Service control", "System modification", Severity.HIGH),
        BlockedCommand("passwd", "Change password", "Security bypass", Severity.CRITICAL),
        BlockedCommand("useradd", "Add user", "Privilege escalation", Severity.CRITICAL),
        BlockedCommand("userdel", "Delete user", "Privilege escalation", Severity.CRITICAL),
        BlockedCommand("curl", "HTTP client", "Data exfiltration", Severity.MEDIUM),
        BlockedCommand("wget", "HTTP download", "Data exfiltration", Severity.MEDIUM),
        BlockedCommand("nc", "Netcat", "Network backdoor", Severity.CRITICAL),
        BlockedCommand("netcat", "Netcat", "Network backdoor", Severity.CRITICAL),
        BlockedCommand("ssh", "SSH client", "Remote access", Severity.HIGH),
        BlockedCommand("scp", "Secure copy", "Data exfiltration", Severity.HIGH),
        BlockedCommand("rsync", "Remote sync", "Data exfiltration", Severity.HIGH),
    )

    # Default allowed commands (safe operations)
    DEFAULT_ALLOWED: tuple[AllowedCommand, ...] = (
        AllowedCommand(
            "python", "Python interpreter", Severity.MEDIUM,
            allowed_args=("-m", "-c", "--version"),
            blocked_args=("-m", "http.server"),  # Block serving files
        ),
        AllowedCommand(
            "pip", "Python package manager", Severity.MEDIUM,
            allowed_args=("install", "list", "show", "freeze", "--version"),
            blocked_args=("uninstall",),
        ),
        AllowedCommand(
            "git", "Version control", Severity.LOW,
            allowed_args=("status", "log", "diff", "show", "branch", "add", "commit", "push", "pull"),
            blocked_args=("reset", "--hard", "clean", "-fd"),
        ),
        AllowedCommand("ls", "List directory", Severity.LOW),
        AllowedCommand("dir", "List directory (Windows)", Severity.LOW),
        AllowedCommand("cat", "Display file", Severity.LOW),
        AllowedCommand("type", "Display file (Windows)", Severity.LOW),
        AllowedCommand("head", "Display file start", Severity.LOW),
        AllowedCommand("tail", "Display file end", Severity.LOW),
        AllowedCommand("grep", "Search text", Severity.LOW),
        AllowedCommand("find", "Find files", Severity.LOW),
        AllowedCommand("echo", "Echo text", Severity.LOW),
        AllowedCommand("pwd", "Print working directory", Severity.LOW),
        AllowedCommand("cd", "Change directory", Severity.LOW),
        AllowedCommand("mkdir", "Create directory", Severity.LOW, allowed_args=("-p",)),
        AllowedCommand("touch", "Create empty file", Severity.LOW),
        AllowedCommand("pytest", "Run tests", Severity.LOW),
        AllowedCommand("mypy", "Type checking", Severity.LOW),
        AllowedCommand("ruff", "Linting", Severity.LOW),
        AllowedCommand("black", "Code formatting", Severity.LOW),
    )

    # Risk mapping for commands
    RISK_MAP: dict[str, OperationalRisk] = {
        "rm": OperationalRisk.DATA_DESTRUCTION,
        "rmdir": OperationalRisk.DATA_DESTRUCTION,
        "del": OperationalRisk.DATA_DESTRUCTION,
        "format": OperationalRisk.DATA_DESTRUCTION,
        "dd": OperationalRisk.DATA_DESTRUCTION,
        "sudo": OperationalRisk.PRIVILEGE_ESCALATION,
        "su": OperationalRisk.PRIVILEGE_ESCALATION,
        "chown": OperationalRisk.PRIVILEGE_ESCALATION,
        "useradd": OperationalRisk.PRIVILEGE_ESCALATION,
        "chmod": OperationalRisk.SECURITY_BYPASS,
        "passwd": OperationalRisk.SECURITY_BYPASS,
        "kill": OperationalRisk.SYSTEM_MODIFICATION,
        "shutdown": OperationalRisk.SYSTEM_MODIFICATION,
        "reboot": OperationalRisk.SYSTEM_MODIFICATION,
    }

    def __init__(
        self,
        allow_list_path: Optional[Path] = None,
        enforcement_mode: str = "STRICT",
    ):
        """
        Initialize ShellGuard with optional custom allow list.
        
        Args:
            allow_list_path: Path to allow_list.json (optional)
            enforcement_mode: STRICT (block), ADVISORY (warn), DISABLED
        """
        self._enforcement_mode = enforcement_mode
        self._allowed = {cmd.command: cmd for cmd in self.DEFAULT_ALLOWED}
        self._blocked = {cmd.command: cmd for cmd in self.DEFAULT_BLOCKED}
        self._contextual_rules: list[ContextualRule] = []

        if allow_list_path and allow_list_path.exists():
            self._load_allow_list(allow_list_path)

    def _load_allow_list(self, path: Path) -> None:
        """Load allow list from JSON file."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            
            # Update enforcement mode
            self._enforcement_mode = data.get("enforcement_mode", self._enforcement_mode)

            # Load allowed commands
            for cmd_data in data.get("allowed_commands", []):
                cmd = AllowedCommand(
                    command=cmd_data["command"],
                    description=cmd_data.get("description", ""),
                    risk_level=Severity[cmd_data.get("risk_level", "MEDIUM")],
                    requires_approval=cmd_data.get("requires_approval", False),
                    allowed_args=tuple(cmd_data.get("allowed_args", [])),
                    blocked_args=tuple(cmd_data.get("blocked_args", [])),
                )
                self._allowed[cmd.command] = cmd

            # Load blocked commands
            for cmd_data in data.get("blocked_commands", []):
                cmd = BlockedCommand(
                    command=cmd_data["command"],
                    description=cmd_data.get("description", ""),
                    reason=cmd_data.get("reason", ""),
                    severity=Severity[cmd_data.get("severity", "HIGH")],
                )
                self._blocked[cmd.command] = cmd

            # Load contextual rules
            for rule_data in data.get("contextual_rules", []):
                rule = ContextualRule(
                    directory=rule_data["directory"],
                    allowed_commands=tuple(rule_data.get("allowed_commands", [])),
                    blocked_commands=tuple(rule_data.get("blocked_commands", [])),
                    requires_approval=tuple(rule_data.get("requires_approval", [])),
                )
                self._contextual_rules.append(rule)

        except (json.JSONDecodeError, KeyError) as e:
            # Keep defaults on parse error
            pass

    def parse_command(self, command_string: str) -> tuple[str, list[str]]:
        """
        Safely parse a command string using shlex.
        
        This prevents shell injection by properly handling quotes,
        escapes, and special characters.
        
        Args:
            command_string: Raw command string
            
        Returns:
            Tuple of (command, args)
        """
        try:
            parts = shlex.split(command_string)
            if not parts:
                return ("", [])
            return (parts[0], parts[1:])
        except ValueError:
            # Malformed command string
            return (command_string.split()[0] if command_string else "", [])

    def intercept(
        self,
        command_string: str,
        working_directory: str = ".",
        user_id: str = "unknown",
        session_id: str = "unknown",
    ) -> CommandResult:
        """
        Intercept and validate a shell command.
        
        Args:
            command_string: The command to validate
            working_directory: Current working directory
            user_id: User executing the command
            session_id: Session identifier
            
        Returns:
            CommandResult with allowed status and optional violation
        """
        if self._enforcement_mode == "DISABLED":
            return CommandResult(allowed=True)

        command, args = self.parse_command(command_string)
        
        if not command:
            return CommandResult(allowed=True)

        # Step 1: Check if command is blocked
        if command in self._blocked:
            blocked_cmd = self._blocked[command]
            violation = self._create_violation(
                command=command,
                args=args,
                working_directory=working_directory,
                violation_type="BLOCKED_COMMAND",
                description=f"Blocked command: {blocked_cmd.description}",
                severity=blocked_cmd.severity,
                risk=self.RISK_MAP.get(command, OperationalRisk.SECURITY_BYPASS),
            )
            return CommandResult(allowed=False, violation=violation)

        # Step 2: Check if command is allowed
        if command not in self._allowed:
            violation = self._create_violation(
                command=command,
                args=args,
                working_directory=working_directory,
                violation_type="UNAUTHORIZED_COMMAND",
                description=f"Command not in allow list: {command}",
                severity=Severity.HIGH,
                risk=OperationalRisk.SECURITY_BYPASS,
            )
            return CommandResult(allowed=False, violation=violation)

        allowed_cmd = self._allowed[command]

        # Step 3: Check for blocked arguments
        for blocked_arg in allowed_cmd.blocked_args:
            if blocked_arg in args or any(blocked_arg in arg for arg in args):
                violation = self._create_violation(
                    command=command,
                    args=args,
                    working_directory=working_directory,
                    violation_type="BLOCKED_ARGUMENT",
                    description=f"Blocked argument: {blocked_arg}",
                    severity=Severity.HIGH,
                    risk=OperationalRisk.SECURITY_BYPASS,
                )
                return CommandResult(allowed=False, violation=violation)

        # Step 4: Check contextual rules
        for rule in self._contextual_rules:
            if rule.directory in working_directory:
                if command in rule.blocked_commands:
                    violation = self._create_violation(
                        command=command,
                        args=args,
                        working_directory=working_directory,
                        violation_type="CONTEXTUALLY_BLOCKED",
                        description=f"Command blocked in {rule.directory}: {command}",
                        severity=Severity.HIGH,
                        risk=OperationalRisk.SECURITY_BYPASS,
                    )
                    return CommandResult(allowed=False, violation=violation)

                if command in rule.requires_approval:
                    return CommandResult(
                        allowed=False,
                        requires_approval=True,
                        approval_reason=f"Requires approval in {rule.directory}",
                    )

        # Step 5: Check if approval is required
        if allowed_cmd.requires_approval:
            return CommandResult(
                allowed=False,
                requires_approval=True,
                approval_reason=f"Command {command} requires approval",
            )

        # Command is allowed
        return CommandResult(allowed=True)

    def execute_safe(
        self,
        command_string: str,
        working_directory: str = ".",
        timeout: int = 30,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess:
        """
        Execute a command safely using subprocess with shell=False.
        
        This method first validates the command, then executes it
        using subprocess.run with shell=False to prevent injection.
        
        Args:
            command_string: Command to execute
            working_directory: Working directory for the command
            timeout: Timeout in seconds
            capture_output: Whether to capture stdout/stderr
            
        Returns:
            subprocess.CompletedProcess result
            
        Raises:
            PermissionError: If command is blocked
            subprocess.TimeoutExpired: If command times out
        """
        result = self.intercept(command_string, working_directory)
        
        if not result.allowed:
            raise PermissionError(
                f"Command blocked: {result.violation.description if result.violation else 'Unknown'}"
            )

        command, args = self.parse_command(command_string)
        
        # Execute with shell=False for security
        return subprocess.run(
            [command, *args],
            cwd=working_directory,
            shell=False,
            timeout=timeout,
            capture_output=capture_output,
            text=True,
        )

    def _create_violation(
        self,
        command: str,
        args: list[str],
        working_directory: str,
        violation_type: str,
        description: str,
        severity: Severity,
        risk: OperationalRisk,
    ) -> OperationalViolation:
        """Create an OperationalViolation record."""
        return OperationalViolation(
            severity=severity,
            category="OPERATIONAL",
            title=f"Shell Command: {violation_type}",
            description=description,
            file=working_directory,
            line=1,
            code_snippet=f"{command} {' '.join(args)}"[:80],
            recommendation=self._get_recommendation(violation_type, command),
            cwe_reference="CWE-78",
            command=command,
            args=tuple(args),
            working_directory=working_directory,
            operational_risk=risk,
            shell_context=f"Intercepted at {datetime.now().isoformat()}",
        )

    def _get_recommendation(self, violation_type: str, command: str) -> str:
        """Get recommendation for a violation type."""
        recommendations = {
            "BLOCKED_COMMAND": f"Command '{command}' is blocked. Use a safer alternative.",
            "UNAUTHORIZED_COMMAND": f"Add '{command}' to allow_list.json if needed.",
            "BLOCKED_ARGUMENT": "Remove the blocked argument and retry.",
            "CONTEXTUALLY_BLOCKED": "Move to an appropriate directory or request access.",
        }
        return recommendations.get(violation_type, "Review command and ensure compliance.")

    def generate_allow_list_template(self) -> str:
        """Generate a template allow_list.json."""
        template = {
            "version": "1.0.0",
            "enforcement_mode": "STRICT",
            "allowed_commands": [
                {
                    "command": cmd.command,
                    "description": cmd.description,
                    "risk_level": cmd.risk_level.value,
                    "requires_approval": cmd.requires_approval,
                    "allowed_args": list(cmd.allowed_args),
                    "blocked_args": list(cmd.blocked_args),
                }
                for cmd in self.DEFAULT_ALLOWED[:5]
            ],
            "blocked_commands": [
                {
                    "command": cmd.command,
                    "description": cmd.description,
                    "reason": cmd.reason,
                    "severity": cmd.severity.value,
                }
                for cmd in self.DEFAULT_BLOCKED[:5]
            ],
            "contextual_rules": [
                {
                    "directory": "/src/security",
                    "allowed_commands": ["cat", "ls", "grep"],
                    "blocked_commands": ["rm", "mv"],
                    "requires_approval": ["git"],
                }
            ],
        }
        return json.dumps(template, indent=2)
