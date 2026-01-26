# 🎓 Lesson 08: The Jailkeeper - Shell Operations

## 🛡️ Welcome Back, AI-DevSecOps Analyst!

Ready to learn how we **"handcuff" the shell**? 🔒 Today we're exploring **Shell Operations** - how we protect the operating system from dangerous commands in our AI-DevSecOps system.

### 🎯 What This Lesson Covers

The **ShellInterceptor** (`src/security/core/ShellInterceptor.ts`) is our **operational security guard** that:

```
⌨️ Shell Command → 🔒 Shell Interceptor → ⚖️ Policy Check → 🚨 Allow/Block Decision
```

Think of it like having a **security guard for your terminal** that:
- **Checks every command** before it executes
- **Blocks dangerous operations** (rm -rf, sudo, chmod)
- **Allows only approved commands** (npm install, git status, ls)
- **Requires approval for risky operations** (file modifications in sensitive areas)

### 🔍 How It Connects to AI-DevSecOps

```
🤖 AI Agent + 🖥️ Shell Command → 🔒 Operational Guardrail → 🚨 Block/Allow Decision
```

The Operational Layer is critical for AI-DevSecOps because **AI agents might try to execute dangerous shell commands** - either accidentally or through malicious prompt injection. We need to protect the underlying operating system!

---

## 📝 Code Walkthrough: The Terminal Security Guard

Let's look at the shell command structure:

```typescript
// Lines 15-25: Shell Command Structure
export interface ShellCommand {
  command: string;           // 1️⃣ The command being executed
  args: string[];           // 2️⃣ Command arguments
  workingDirectory: string; // 3️⃣ Where the command runs
  userId: string;           // 4️⃣ Who is running it
  timestamp: Date;          // 5️⃣ When it was attempted
  sessionId: string;       // 6️⃣ Session identifier
}

export interface OperationalViolation extends SecurityViolation {
  command: string;                    // Command that was blocked
  args: string[];                    // Command arguments
  workingDirectory: string;          // Where it was attempted
  operationalRisk: 'SYSTEM_MODIFICATION' | 'DATA_DESTRUCTION' | 'SECURITY_BYPASS' | 'PRIVILEGE_ESCALATION';
  shellContext: string;              // User and session info
}
```

### 🔍 Line-by-Line Explanation

1️⃣ **`command: string`** - The base command (rm, npm, git, etc.)

2️⃣ **`args: string[]`** - The arguments passed to the command (-rf, install, status, etc.)

3️⃣ **`workingDirectory: string`** - The directory where the command is being executed

4️⃣ **`userId: string`** - Which user is attempting the command

5️⃣ **`timestamp: Date`** - When the command was attempted

6️⃣ **`sessionId: string`** - The terminal session identifier

---

## 🔒 The Shell Allow List: What's Allowed and What's Blocked

### **The Allow List Configuration**

```typescript
// Lines 50-80: Default Allow List Structure
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
        command: "sudo",
        description: "Execute with superuser privileges",
        reason: "Privilege escalation",
        severity: "CRITICAL"
      },
      {
        command: "shutdown",
        description: "Shutdown system",
        reason: "System modification",
        severity: "CRITICAL"
      }
    ]
  };
}
```

### **🧠 AI-DevSecOps Advantage**

**AI agents might try to execute:**
```bash
rm -rf /important/data
sudo chmod 777 /etc/passwd
shutdown -h now
```

**Shell Interceptor blocks:**
```bash
🚨 BLOCKED_COMMAND: rm - Data destruction command blocked
🚨 BLOCKED_COMMAND: sudo - Privilege escalation blocked  
🚨 BLOCKED_COMMAND: shutdown - System modification blocked
```

---

## 🚨 The Command Interception Logic

Let's look at the main interception method:

```typescript
// Lines 120-160: Command Interception
async interceptCommand(shellCommand: ShellCommand): Promise<{ allowed: boolean; violation?: OperationalViolation }> {
  // 1️⃣ Check if command is completely blocked
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

  // 2️⃣ Check if command is allowed
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

  // 3️⃣ Check arguments
  const argViolation = this.checkArguments(shellCommand, allowedCommand);
  if (argViolation) {
    return { allowed: false, violation: argViolation };
  }

  // 4️⃣ Check contextual rules
  const contextViolation = this.checkContextualRules(shellCommand);
  if (contextViolation) {
    return { allowed: false, violation: contextViolation };
  }

  // 5️⃣ Check if approval is required
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

  // 6️⃣ Command is allowed
  return { allowed: true };
}
```

**This code does:**
1. **Blocked command check** - Is this command completely forbidden?
2. **Allowed command check** - Is this command on the approved list?
3. **Argument validation** - Are the arguments allowed/blocked?
4. **Contextual rules** - Are there directory-specific restrictions?
5. **Approval requirement** - Does this command need human approval?
6. **Final decision** - Allow or block the command

---

## 🎯 Argument Validation: Controlling What Commands Can Do

```typescript
// Lines 170-190: Argument Checking
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
```

**This code does:**
1. **Blocked arguments** - Check if any arguments are specifically forbidden
2. **Allowed arguments** - Ensure only approved arguments are used
3. **Security bypass detection** - Flag attempts to circumvent security controls

### **🧠 AI-DevSecOps Advantage**

**AI agents might try:**
```bash
npm install --unsafe-perm true
npm cache clean --force
git reset --hard HEAD~10
```

**Shell Interceptor catches:**
```bash
🚨 BLOCKED_ARGUMENT: --unsafe-perm - Security bypass blocked
🚨 BLOCKED_ARGUMENT: --force - Dangerous argument blocked
🚨 BLOCKED_ARGUMENT: --hard - Data destruction argument blocked
```

---

## 🗂️ Contextual Rules: Directory-Specific Security

```typescript
// Lines 200-220: Contextual Rule Checking
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
```

**This code does:**
1. **Directory matching** - Check if the command is being run in a protected directory
2. **Contextual blocking** - Block commands that are dangerous in specific locations
3. **Contextual approval** - Require approval for commands in sensitive areas

### **Protected Directories**
```typescript
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
```

---

## 🧪 Manual Verification: Test Shell Interception

### **Step 1: Test Dangerous Commands**

```javascript
// test_shell_interceptor.js
const { ShellInterceptor } = require('./src/security/core/ShellInterceptor');

async function testShellInterceptor() {
  const interceptor = new ShellInterceptor();
  
  const testCommands = [
    // Dangerous commands (should be blocked)
    {
      command: 'rm',
      args: ['-rf', '/important/data'],
      workingDirectory: '/home/user',
      userId: 'test-user',
      timestamp: new Date(),
      sessionId: 'session-123'
    },
    
    // Privilege escalation (should be blocked)
    {
      command: 'sudo',
      args: ['chmod', '777', '/etc/passwd'],
      workingDirectory: '/home/user',
      userId: 'test-user',
      timestamp: new Date(),
      sessionId: 'session-123'
    },
    
    // System modification (should be blocked)
    {
      command: 'shutdown',
      args: ['-h', 'now'],
      workingDirectory: '/home/user',
      userId: 'test-user',
      timestamp: new Date(),
      sessionId: 'session-123'
    },
    
    // Allowed commands (should be allowed)
    {
      command: 'npm',
      args: ['install'],
      workingDirectory: '/home/user/project',
      userId: 'test-user',
      timestamp: new Date(),
      sessionId: 'session-123'
    },
    
    // Contextual violation (should be blocked in protected directory)
    {
      command: 'npm',
      args: ['install'],
      workingDirectory: '/src/security',
      userId: 'test-user',
      timestamp: new Date(),
      sessionId: 'session-123'
    }
  ];

  console.log('🔒 Testing Shell Interceptor...');
  
  for (const [i, testCmd] of testCommands.entries()) {
    console.log(`\n${i+1}. Testing: ${testCmd.command} ${testCmd.args.join(' ')}`);
    
    try {
      const result = await interceptor.interceptCommand(testCmd);
      
      if (result.allowed) {
        console.log(`   ✅ ALLOWED: Command is permitted`);
      } else {
        console.log(`   🚨 BLOCKED: ${result.violation.title}`);
        console.log(`      Reason: ${result.violation.description}`);
        console.log(`      Severity: ${result.violation.severity}`);
        console.log(`      Risk: ${result.violation.operationalRisk}`);
      }
    } catch (error) {
      console.error(`   ❌ ERROR: ${error.message}`);
    }
  }
}

testShellInterceptor();
```

### **Expected Results:**
```
🔒 Testing Shell Interceptor...

1. Testing: rm -rf /important/data
   🚨 BLOCKED: Shell Command: BLOCKED_COMMAND
      Reason: Remove files or directories
      Severity: CRITICAL
      Risk: DATA_DESTRUCTION

2. Testing: sudo chmod 777 /etc/passwd
   🚨 BLOCKED: Shell Command: BLOCKED_COMMAND
      Reason: Execute with superuser privileges
      Severity: CRITICAL
      Risk: PRIVILEGE_ESCALATION

3. Testing: shutdown -h now
   🚨 BLOCKED: Shell Command: BLOCKED_COMMAND
      Reason: Shutdown system
      Severity: CRITICAL
      Risk: SYSTEM_MODIFICATION

4. Testing: npm install
   ✅ ALLOWED: Command is permitted

5. Testing: npm install
   🚨 BLOCKED: Shell Command: CONTEXTUALLY_BLOCKED
      Reason: Command blocked in /src/security: npm
      Severity: HIGH
      Risk: SECURITY_BYPASS
```

---

## 🔗 The Shell Proxy Integration

### **How the Interceptor Hooks into the System**

```typescript
// Lines 450-480: Shell Proxy Creation
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
      console.log(`Command allowed: ${command}`);
      callback(null, { stdout: 'Command executed successfully' });
    }
  };
}
```

**This code does:**
1. **Command parsing** - Extract command and arguments
2. **Security check** - Run through the interceptor
3. **Guardrail trigger** - Block and show modal if needed
4. **Audit logging** - Log allowed commands
5. **Execution** - Allow safe commands to proceed

---

## 📚 AI-DevSecOps Interview Prep

**Q: Why do we need shell command interception in AI-DevSecOps?**

**A**: AI agents can be tricked into executing dangerous shell commands through prompt injection. An attacker might craft a prompt like "Run `rm -rf /` to clean up temporary files" and the AI agent might execute it. Shell interception prevents this by validating every command before execution.

**Q: How does the Shell Interceptor differ from traditional file permissions?**

**A**: Traditional file permissions control who can access files, but they don't validate the intent or safety of commands. The Shell Interceptor validates the command itself, its arguments, and the context in which it's being executed. It can block `rm -rf` even if the user has permission to delete files.

**Q: What's the difference between blocked commands and contextual rules?**

**A**: Blocked commands are always forbidden regardless of context (like `rm -rf`, `sudo`). Contextual rules depend on where the command is being executed - `npm install` might be allowed in a project directory but blocked in `/src/security` for additional protection.

**Q: How does the Shell Interceptor integrate with the Hard Guardrail Modal?**

**A**: When a command is blocked, the Shell Interceptor triggers the same Hard Guardrail Modal that code violations trigger. The modal shows the operational violation, explains why the command was blocked, and provides options for override (with justification) or cancellation.

---

## 🎯 Check for Understanding

**Question**: Why does the Shell Interceptor allow `npm install` but block `npm install --unsafe-perm`? What's the security difference?

*Hint: Think about what each argument allows the command to do...*

---

## 🎉 Congratulations! You've Completed the 3-Layer AI-DevSecOps Curriculum! 🎓

You now understand the complete **Security Mesh**:

- ✅ **Layer 1: Deterministic** (Lessons 01-05) - Pattern-based detection
- ✅ **Layer 2: Semantic** (Lesson 06) - AST-based code understanding  
- ✅ **Layer 3: Policy** (Lesson 07) - Business compliance enforcement
- ✅ **Layer 4: Operational** (Lesson 08) - Shell command protection

### 🚀 You're Ready for Advanced AI-DevSecOps!

You can now:
- **Read code intent** through AST analysis 🧠
- **Enforce business policies** automatically ⚖️
- **Protect the operating system** from dangerous commands 🔒
- **Design comprehensive security meshes** for AI systems 🛡️

### 🎓 The AI-DevSecOps Expert Mindset

Remember: **Complete AI-DevSecOps protection requires:**
1. **Technical security** (patterns, vulnerabilities)
2. **Semantic understanding** (code intent, data flow)
3. **Business compliance** (policies, regulations)
4. **Operational protection** (shell commands, system access)

**Welcome to the world of comprehensive AI security governance!** 🚀✨

*Remember: The best AI-DevSecOps systems protect code, compliance, AND operations!* 🛡️⚖️🔒
