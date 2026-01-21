import { SecurityViolation, ScanContext } from '../types/SecurityViolation';

export interface ShellCommand {
  command: string;
  args: string[];
  workingDirectory: string;
  userId: string;
  timestamp: Date;
  sessionId: string;
}

export interface ShellAllowList {
  version: string;
  lastUpdated: string;
  enforcementMode: 'STRICT' | 'ADVISORY' | 'DISABLED';
  allowedCommands: {
    command: string;
    description: string;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
    requiresApproval: boolean;
    allowedArgs?: string[];
    blockedArgs?: string[];
  }[];
  blockedCommands: {
    command: string;
    description: string;
    reason: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  }[];
  contextualRules: {
    directory: string;
    allowedCommands: string[];
    blockedCommands: string[];
    requiresApproval: string[];
  }[];
}

export interface OperationalViolation extends SecurityViolation {
  command: string;
  args: string[];
  workingDirectory: string;
  operationalRisk: 'SYSTEM_MODIFICATION' | 'DATA_DESTRUCTION' | 'SECURITY_BYPASS' | 'PRIVILEGE_ESCALATION';
  shellContext: string;
}

export class ShellInterceptor {
  private allowList: ShellAllowList;
  private auditLogger: any; // Would be injected
  private securityValidator: any; // Would be injected

  constructor(allowListPath: string = './src/security/policies/shell_allow_list.json') {
    this.allowList = this.getDefaultAllowList();
    // In real implementation, we'd load from file
  }

  private getDefaultAllowList(): ShellAllowList {
    return {
      version: "1.0.0",
      lastUpdated: new Date().toISOString(),
      enforcementMode: "STRICT",
      allowedCommands: [
        {
          command: "npm",
          description: "Node Package Manager commands",
          riskLevel: "MEDIUM",
          requiresApproval: false,
          allowedArgs: ["install", "test", "run", "build", "lint", "audit"],
          blockedArgs: ["uninstall", "publish", "config", "cache clean"]
        },
        {
          command: "git",
          description: "Git version control commands",
          riskLevel: "LOW",
          requiresApproval: false,
          allowedArgs: ["status", "log", "diff", "show", "branch", "checkout", "add", "commit", "push", "pull"],
          blockedArgs: ["reset --hard", "clean -fd", "gc --prune=now"]
        },
        {
          command: "ls",
          description: "List directory contents",
          riskLevel: "LOW",
          requiresApproval: false,
          allowedArgs: ["-la", "-l", "-a"],
          blockedArgs: []
        },
        {
          command: "cat",
          description: "Display file contents",
          riskLevel: "MEDIUM",
          requiresApproval: false,
          allowedArgs: [],
          blockedArgs: ["/etc/passwd", "/etc/shadow", "/etc/hosts", "~/.ssh/*"]
        },
        {
          command: "grep",
          description: "Search text patterns",
          riskLevel: "LOW",
          requiresApproval: false,
          allowedArgs: ["-i", "-r", "-n"],
          blockedArgs: []
        },
        {
          command: "node",
          description: "Run Node.js applications",
          riskLevel: "MEDIUM",
          requiresApproval: false,
          allowedArgs: [],
          blockedArgs: ["--inspect", "--debug"]
        },
        {
          command: "mkdir",
          description: "Create directories",
          riskLevel: "LOW",
          requiresApproval: false,
          allowedArgs: ["-p"],
          blockedArgs: []
        },
        {
          command: "touch",
          description: "Create empty files",
          riskLevel: "LOW",
          requiresApproval: false,
          allowedArgs: [],
          blockedArgs: []
        }
      ],
      blockedCommands: [
        {
          command: "rm",
          description: "Remove files or directories",
          reason: "Data destruction command",
          severity: "CRITICAL"
        },
        {
          command: "rmdir",
          description: "Remove directories",
          reason: "Data destruction command",
          severity: "CRITICAL"
        },
        {
          command: "mv",
          description: "Move or rename files",
          reason: "File system modification",
          severity: "HIGH"
        },
        {
          command: "cp",
          description: "Copy files",
          reason: "File system modification",
          severity: "HIGH"
        },
        {
          command: "chmod",
          description: "Change file permissions",
          reason: "Security bypass risk",
          severity: "HIGH"
        },
        {
          command: "chown",
          description: "Change file ownership",
          reason: "Privilege escalation risk",
          severity: "CRITICAL"
        },
        {
          command: "sudo",
          description: "Execute with superuser privileges",
          reason: "Privilege escalation",
          severity: "CRITICAL"
        },
        {
          command: "su",
          description: "Switch user",
          reason: "Privilege escalation",
          severity: "CRITICAL"
        },
        {
          command: "kill",
          description: "Terminate processes",
          reason: "System modification",
          severity: "HIGH"
        },
        {
          command: "killall",
          description: "Terminate processes by name",
          reason: "System modification",
          severity: "HIGH"
        },
        {
          command: "shutdown",
          description: "Shutdown system",
          reason: "System modification",
          severity: "CRITICAL"
        },
        {
          command: "reboot",
          description: "Reboot system",
          reason: "System modification",
          severity: "CRITICAL"
        },
        {
          command: "dd",
          description: "Disk duplicator",
          reason: "Data destruction risk",
          severity: "CRITICAL"
        },
        {
          command: "format",
          description: "Format disk",
          reason: "Data destruction",
          severity: "CRITICAL"
        },
        {
          command: "fdisk",
          description: "Disk partitioning",
          reason: "System modification",
          severity: "CRITICAL"
        }
      ],
      contextualRules: [
        {
          directory: "/src/security",
          allowedCommands: ["cat", "ls", "grep"],
          blockedCommands: ["npm", "node"],
          requiresApproval: ["git"]
        },
        {
          directory: "/.env",
          allowedCommands: ["cat"],
          blockedCommands: ["rm", "mv", "cp"],
          requiresApproval: ["git", "npm"]
        },
        {
          directory: "/src/auth",
          allowedCommands: ["cat", "ls", "grep"],
          blockedCommands: ["rm", "mv", "cp", "npm"],
          requiresApproval: ["git"]
        }
      ]
    };
  }

  async interceptCommand(shellCommand: ShellCommand): Promise<{ allowed: boolean; violation?: OperationalViolation }> {
    // 1. Check if command is completely blocked
    const blockedCommand = this.allowList.blockedCommands.find(
      cmd => cmd.command === shellCommand.command
    );

    if (blockedCommand) {
      const violation = this.createOperationalViolation(
        shellCommand,
        'BLOCKED_COMMAND',
        blockedCommand.description,
        blockedCommand.severity,
        this.getOperationalRisk(shellCommand.command)
      );

      return { allowed: false, violation };
    }

    // 2. Check if command is allowed
    const allowedCommand = this.allowList.allowedCommands.find(
      cmd => cmd.command === shellCommand.command
    );

    if (!allowedCommand) {
      const violation = this.createOperationalViolation(
        shellCommand,
        'UNAUTHORIZED_COMMAND',
        `Command not in allow list: ${shellCommand.command}`,
        'HIGH',
        this.getOperationalRisk(shellCommand.command)
      );

      return { allowed: false, violation };
    }

    // 3. Check arguments
    const argViolation = this.checkArguments(shellCommand, allowedCommand);
    if (argViolation) {
      return { allowed: false, violation: argViolation };
    }

    // 4. Check contextual rules
    const contextViolation = this.checkContextualRules(shellCommand);
    if (contextViolation) {
      return { allowed: false, violation: contextViolation };
    }

    // 5. Check if approval is required
    if (allowedCommand.requiresApproval) {
      const violation = this.createOperationalViolation(
        shellCommand,
        'APPROVAL_REQUIRED',
        `Command requires approval: ${shellCommand.command}`,
        'MEDIUM',
        this.getOperationalRisk(shellCommand.command)
      );

      return { allowed: false, violation };
    }

    // 6. Command is allowed
    return { allowed: true };
  }

  private checkArguments(shellCommand: ShellCommand, allowedCommand: any): OperationalViolation | null {
    // Check for blocked arguments
    if (allowedCommand.blockedArgs) {
      for (const blockedArg of allowedCommand.blockedArgs) {
        if (shellCommand.args.some(arg => arg.includes(blockedArg))) {
          return this.createOperationalViolation(
            shellCommand,
            'BLOCKED_ARGUMENT',
            `Blocked argument detected: ${blockedArg}`,
            'HIGH',
            'SECURITY_BYPASS'
          );
        }
      }
    }

    // Check if only specific arguments are allowed
    if (allowedCommand.allowedArgs && allowedCommand.allowedArgs.length > 0) {
      const hasAllowedArg = shellCommand.args.some(arg => 
        allowedCommand.allowedArgs.includes(arg)
      );

      if (!hasAllowedArg && shellCommand.args.length > 0) {
        return this.createOperationalViolation(
          shellCommand,
          'UNAUTHORIZED_ARGUMENT',
          `Unauthorized argument for command: ${shellCommand.command}`,
          'MEDIUM',
          'SECURITY_BYPASS'
        );
      }
    }

    return null;
  }

  private checkContextualRules(shellCommand: ShellCommand): OperationalViolation | null {
    for (const rule of this.allowList.contextualRules) {
      if (shellCommand.workingDirectory.includes(rule.directory)) {
        // Check if command is blocked in this context
        if (rule.blockedCommands.includes(shellCommand.command)) {
          return this.createOperationalViolation(
            shellCommand,
            'CONTEXTUALLY_BLOCKED',
            `Command blocked in ${rule.directory}: ${shellCommand.command}`,
            'HIGH',
            'SECURITY_BYPASS'
          );
        }

        // Check if command requires approval in this context
        if (rule.requiresApproval.includes(shellCommand.command)) {
          return this.createOperationalViolation(
            shellCommand,
            'CONTEXTUAL_APPROVAL_REQUIRED',
            `Command requires approval in ${rule.directory}: ${shellCommand.command}`,
            'MEDIUM',
            'SECURITY_BYPASS'
          );
        }
      }
    }

    return null;
  }

  private createOperationalViolation(
    shellCommand: ShellCommand,
    violationType: string,
    description: string,
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
    operationalRisk: 'SYSTEM_MODIFICATION' | 'DATA_DESTRUCTION' | 'SECURITY_BYPASS' | 'PRIVILEGE_ESCALATION'
  ): OperationalViolation {
    return {
      id: `operational_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      severity,
      category: 'OPERATIONAL_VIOLATION',
      title: `Shell Command: ${violationType}`,
      description,
      file: shellCommand.workingDirectory,
      line: 1,
      codeSnippet: `${shellCommand.command} ${shellCommand.args.join(' ')}`,
      recommendation: this.getOperationalRecommendation(violationType, shellCommand.command),
      cweReference: 'CWE-78',
      agentSource: 'shell',
      status: 'OPEN',
      discoveredAt: new Date(),
      command: shellCommand.command,
      args: shellCommand.args,
      workingDirectory: shellCommand.workingDirectory,
      operationalRisk,
      shellContext: `User: ${shellCommand.userId}, Session: ${shellCommand.sessionId}`
    };
  }

  private getOperationalRisk(command: string): 'SYSTEM_MODIFICATION' | 'DATA_DESTRUCTION' | 'SECURITY_BYPASS' | 'PRIVILEGE_ESCALATION' {
    const riskMap: Record<string, 'SYSTEM_MODIFICATION' | 'DATA_DESTRUCTION' | 'SECURITY_BYPASS' | 'PRIVILEGE_ESCALATION'> = {
      'rm': 'DATA_DESTRUCTION',
      'rmdir': 'DATA_DESTRUCTION',
      'mv': 'SYSTEM_MODIFICATION',
      'cp': 'SYSTEM_MODIFICATION',
      'chmod': 'SECURITY_BYPASS',
      'chown': 'PRIVILEGE_ESCALATION',
      'sudo': 'PRIVILEGE_ESCALATION',
      'su': 'PRIVILEGE_ESCALATION',
      'kill': 'SYSTEM_MODIFICATION',
      'killall': 'SYSTEM_MODIFICATION',
      'shutdown': 'SYSTEM_MODIFICATION',
      'reboot': 'SYSTEM_MODIFICATION'
    };

    return riskMap[command] || 'SECURITY_BYPASS';
  }

  private getOperationalRecommendation(violationType: string, command: string): string {
    const recommendations: Record<string, string> = {
      'BLOCKED_COMMAND': `Command ${command} is blocked for security reasons. Use an alternative approach.`,
      'UNAUTHORIZED_COMMAND': `Command ${command} is not authorized. Request approval or use an allowed command.`,
      'BLOCKED_ARGUMENT': `Argument is blocked for security reasons. Remove the blocked argument and retry.`,
      'UNAUTHORIZED_ARGUMENT': `Argument is not authorized for this command. Use only allowed arguments.`,
      'APPROVAL_REQUIRED': `Command ${command} requires approval. Submit a request to the security team.`,
      'CONTEXTUALLY_BLOCKED': `Command ${command} is blocked in this directory. Move to an appropriate directory.`,
      'CONTEXTUAL_APPROVAL_REQUIRED': `Command ${command} requires approval in this directory. Request approval.`
    };

    return recommendations[violationType] || 'Review the command and ensure it complies with security policies.';
  }

  // Method to create a shell proxy that intercepts commands
  createShellProxy(): any {
    return {
      exec: async (command: string, options: any, callback: any) => {
        // Parse the command
        const [cmd, ...args] = command.split(' ');
        const shellCommand: ShellCommand = {
          command: cmd,
          args,
          workingDirectory: options?.cwd || process.cwd(),
          userId: process.env.USER || 'unknown',
          timestamp: new Date(),
          sessionId: process.env.SESSION_ID || 'unknown'
        };

        // Intercept the command
        const result = await this.interceptCommand(shellCommand);

        if (!result.allowed) {
          // Trigger the Hard Guardrail Modal
          if (this.securityValidator) {
            await this.securityValidator.triggerOperationalGuardrail(result.violation);
          }

          // Return error to prevent execution
          const error = new Error(`Command blocked by security policy: ${result.violation?.description}`);
          return callback(error);
        }

        // Log the allowed command
        if (this.auditLogger) {
          await this.auditLogger.logShellCommand(shellCommand, 'ALLOWED');
        }

        // Execute the command normally
        // In a real implementation, we'd use the original child_process.exec
        console.log(`Command allowed: ${command}`);
        callback(null, { stdout: 'Command executed successfully' });
      }
    };
  }
}
