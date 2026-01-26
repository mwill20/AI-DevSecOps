# 🎓 Lesson 07: The Security Lawyer - Policy Engine

## 🛡️ Welcome Back, AI-DevSecOps Analyst!

Ready to become a **security lawyer**? ⚖️ Today we're exploring the **Policy Engine** - the "lawyer layer" that enforces business rules, compliance requirements, and organizational policies in our AI-DevSecOps system.

### 🎯 What This Lesson Covers

The **PolicyEngine** (`src/security/core/PolicyEngine.ts`) is our **automated compliance officer** that:

```
📁 Code + 📋 Policies → ⚖️ Policy Engine → 🚨 Policy Violations → 🏛️ Compliance Enforcement
```

Think of it like having a **legal team for code** that ensures:
- **Business rules are followed** (no hardcoded prices, proper approvals)
- **Compliance requirements are met** (GDPR, PCI DSS, SOX)
- **Organizational standards are enforced** (approved libraries only, security practices)

### 🔍 How It Connects to AI-DevSecOps

```
🤖 AI-Generated Code → 📋 Policy Check → ⚖️ Business Compliance → 🚨 Policy Violations
```

The Policy Layer is essential for AI-DevSecOps because **AI agents don't understand business context** - they might use forbidden libraries, violate compliance rules, or ignore business policies without even knowing it!

---

## 📝 Code Walkthrough: The Security Lawyer

Let's look at the core policy structure:

```typescript
// Lines 8-25: Governance Policy Structure
export interface GovernancePolicy {
  version: string;
  lastUpdated: string;
  enforcementMode: 'STRICT' | 'ADVISORY' | 'DISABLED';
  policies: {
    dependency_control: {
      enabled: boolean;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      description: string;
      rules: {
        allowed_libraries: string[];
        blocked_libraries: string[];
        require_approval_for: string[];
      };
    };
    file_sensitivity: {
      enabled: boolean;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      description: string;
      protected_paths: string[];
      require_human_approval: boolean;
      approval_workflow: string;
    };
    // ... more policy categories
  };
}
```

### 🔍 Line-by-Line Explanation

1️⃣ **`version: string`** - Policy version for tracking updates

2️⃣ **`enforcementMode: 'STRICT' | 'ADVISORY' | 'DISABLED'`** - How strictly to enforce policies

3️⃣ **`dependency_control`** - Controls which libraries can be used

4️⃣ **`file_sensitivity`** - Protects sensitive files like auth and config

---

## ⚖️ The Policy Categories: Different Types of Laws

### **1. Dependency Control - "Approved Vendors Only"**

```typescript
// Lines 200-220: Dependency Control Enforcement
private async checkDependencyControl(content: string, context: ScanContext): Promise<PolicyViolation[]> {
  const violations: PolicyViolation[] = [];
  const policy = this.policy.policies.dependency_control;

  if (!policy.enabled) return violations;

  // Extract import statements
  const imports = this.extractImports(content);
  
  for (const importName of imports) {
    // Check blocked libraries
    if (policy.rules.blocked_libraries.includes(importName)) {
      violations.push(this.createPolicyViolation(
        'dependency_control',
        'BLOCKED_LIBRARY',
        `Blocked library detected: ${importName}`,
        policy.severity,
        context,
        { library: importName, reason: 'blocked_library' }
      ));
    }

    // Check approval requirements
    if (policy.rules.require_approval_for.includes(importName)) {
      violations.push(this.createPolicyViolation(
        'dependency_control',
        'APPROVAL_REQUIRED',
        `Library requires approval: ${importName}`,
        'MEDIUM',
        context,
        { library: importName, reason: 'approval_required' }
      ));
    }
  }

  return violations;
}
```

**This code does:**
1. **`extractImports()`** - Find all import statements in the code
2. **Check blocked libraries** - Look for forbidden packages like `request`, `eval`
3. **Check approval requirements** - Flag libraries that need security approval

### **🧠 AI-DevSecOps Advantage**

**AI agents might use:**
```javascript
import request from 'request';  // Blocked library!
import eval from 'eval';        // Dangerous library!
```

**Policy Engine catches:**
```javascript
🚨 BLOCKED_LIBRARY: request - Security risk, use axios instead
🚨 BLOCKED_LIBRARY: eval - Code execution risk, forbidden
```

---

### **2. File Sensitivity - "Protected Areas Only"**

```typescript
// Lines 230-250: File Sensitivity Protection
private async checkFileSensitivity(context: ScanContext): Promise<PolicyViolation[]> {
  const violations: PolicyViolation[] = [];
  const policy = this.policy.policies.file_sensitivity;

  if (!policy.enabled) return violations;

  // Check if file is in protected path
  const filePath = context.projectPath;
  const isProtected = policy.protected_paths.some(protectedPath => 
    filePath.includes(protectedPath)
  );

  if (isProtected && policy.require_human_approval) {
    violations.push(this.createPolicyViolation(
      'file_sensitivity',
      'SENSITIVE_FILE_CHANGE',
      `Sensitive file modified: ${filePath}`,
      policy.severity,
      context,
      { filePath, protectedPath: policy.protected_paths.find(p => filePath.includes(p)) }
    ));
  }

  return violations;
}
```

**This code does:**
1. **Check protected paths** - `/src/auth`, `/.env`, `/config/database.js`
2. **Require human approval** - Any changes to sensitive areas need security review
3. **Track file context** - Know exactly which protected area was modified

### **🧠 AI-DevSecOps Advantage**

**AI agents might modify:**
```javascript
// /src/auth/login.js - Sensitive file!
const login = (user, pass) => { /* AI-generated auth logic */ };
```

**Policy Engine catches:**
```javascript
🚨 SENSITIVE_FILE_CHANGE: /src/auth/login.js - Requires human approval
```

---

### **3. Data Protection - "Privacy Laws Matter"**

```typescript
// Lines 260-280: Data Protection Compliance
private async checkDataProtection(content: string, context: ScanContext): Promise<PolicyViolation[]> {
  const violations: PolicyViolation[] = [];
  const policy = this.policy.policies.data_protection;

  if (!policy.enabled) return violations;

  // Check for personal data in exports
  for (const field of policy.rules.personal_data_fields) {
    const regex = new RegExp(`\\b${field}\\b`, 'gi');
    const matches = content.match(regex);
    
    if (matches) {
      // Check if personal data is being exported
      const exportContexts = ['res.json', 'res.send', 'return', 'console.log'];
      for (const exportContext of exportContexts) {
        if (content.includes(exportContext) && content.toLowerCase().includes(field.toLowerCase())) {
          violations.push(this.createPolicyViolation(
            'data_protection',
            'PERSONAL_DATA_EXPOSURE',
            `Personal data field exposure detected: ${field}`,
            policy.severity,
            context,
            { field, exportContext, matches: matches.length }
          ));
        }
      }
    }
  }

  return violations;
}
```

**This code does:**
1. **Personal data detection** - Look for `ssn`, `email`, `creditcard` fields
2. **Export context checking** - See if personal data is being sent to clients
3. **Compliance enforcement** - GDPR, PCI DSS, privacy law requirements

### **🧠 AI-DevSecOps Advantage**

**AI agents might create:**
```javascript
function getUserProfile(id) {
  return {
    id: id,
    ssn: user.socialSecurityNumber,  // GDPR violation!
    email: user.email
  };
}
```

**Policy Engine catches:**
```javascript
🚨 PERSONAL_DATA_EXPOSURE: ssn - GDPR compliance violation
🚨 PERSONAL_DATA_EXPOSURE: email - Privacy law violation
```

---

## 🧪 Manual Verification: Test Policy Enforcement

### **Step 1: Create Policy Test Files**

Create `test_policy_violations.js`:

```javascript
// 1. Dependency Control Violations
import request from 'request';        // Blocked library
import eval from 'eval';              // Dangerous library
import axios from 'axios';            // Requires approval

// 2. Data Protection Violations
function exportUserData(userId) {
  const user = getUserById(userId);
  
  // GDPR violation - personal data in API response
  return {
    id: user.id,
    ssn: user.socialSecurityNumber,  // Personal data!
    creditCard: user.creditCard,     // PCI DSS violation!
    email: user.email
  };
}

// 3. Business Logic Violations
const pricing = {
  basic: 9.99,        // Hardcoded business value
  premium: 29.99,     // Should be in config
  maxUsers: 100       // Business rule hardcoded
};

// 4. Security Standards Violations
function processInput(userInput) {
  // Forbidden pattern
  const result = eval(userInput);  // Code execution risk!
  
  // Insecure output
  document.innerHTML = userInput;  // XSS risk!
  
  return result;
}

// 5. AI Governance Violations
function makeFinancialDecision(amount) {
  // No human oversight for financial decision!
  if (amount > 10000) {
    return approveLargeTransaction(amount);
  }
}
```

### **Step 2: Test the Policy Engine**

```javascript
// test_policy_engine.js
const { PolicyEngine } = require('./src/security/core/PolicyEngine');

async function testPolicyEngine() {
  const policyEngine = new PolicyEngine();
  const content = require('fs').readFileSync('test_policy_violations.js', 'utf8');
  
  const context = {
    projectPath: './test_policy_violations.js',
    phase: 'WINDSURF',
    developerId: 'test-developer',
    agentSource: 'windsurf'
  };

  try {
    console.log('⚖️ Running Policy Engine Analysis...');
    const violations = await policyEngine.evaluatePolicy(content, context);
    
    console.log(`📊 Found ${violations.length} policy violations:`);
    violations.forEach((violation, i) => {
      console.log(`${i+1}. [${violation.severity}] ${violation.title}`);
      console.log(`   Policy: ${violation.policyId}`);
      console.log(`   Description: ${violation.description}`);
      console.log(`   Business Impact: ${violation.businessImpact}`);
      console.log(`   Remediation: ${violation.remediationComplexity}`);
      console.log(`   Code: ${violation.codeSnippet}`);
      console.log('');
    });

  } catch (error) {
    console.error('❌ Policy engine analysis failed:', error);
  }
}

testPolicyEngine();
```

### **Expected Results:**
```
📊 Found 8 policy violations:
1. [HIGH] dependency_control: BLOCKED_LIBRARY
   Policy: dependency_control
   Description: Blocked library detected: request
   Business Impact: MEDIUM
   Remediation: MODERATE
   Code: {"library": "request", "reason": "blocked_library"}

2. [CRITICAL] dependency_control: BLOCKED_LIBRARY
   Policy: dependency_control
   Description: Blocked library detected: eval
   Business Impact: MEDIUM
   Remediation: MODERATE
   Code: {"library": "eval", "reason": "blocked_library"}

3. [MEDIUM] dependency_control: APPROVAL_REQUIRED
   Policy: dependency_control
   Description: Library requires approval: axios
   Business Impact: MEDIUM
   Remediation: SIMPLE
   Code: {"library": "axios", "reason": "approval_required"}

4. [CRITICAL] data_protection: PERSONAL_DATA_EXPOSURE
   Policy: data_protection
   Description: Personal data field exposure detected: ssn
   Business Impact: HIGH
   Remediation: MODERATE
   Code: {"field": "ssn", "exportContext": "return", "matches": 1}

5. [CRITICAL] data_protection: PERSONAL_DATA_EXPOSURE
   Policy: data_protection
   Description: Personal data field exposure detected: creditCard
   Business Impact: HIGH
   Remediation: MODERATE
   Code: {"field": "creditCard", "exportContext": "return", "matches": 1}

6. [MEDIUM] business_logic: HARDCODED_BUSINESS_VALUE
   Policy: business_logic
   Description: Hardcoded business value detected: prices
   Business Impact: LOW
   Remediation: SIMPLE
   Code: {"valueType": "prices", "matches": 2}

7. [HIGH] security_standards: FORBIDDEN_PATTERN
   Policy: security_standards
   Description: Forbidden security pattern detected: eval(
   Business Impact: HIGH
   Remediation: MODERATE
   Code: {"pattern": "eval("}

8. [HIGH] security_standards: FORBIDDEN_PATTERN
   Policy: security_standards
   Description: Forbidden security pattern detected: innerHTML
   Business Impact: HIGH
   Remediation: MODERATE
   Code: {"pattern": "innerHTML"}
```

---

## 🏛️ The Governance Policy Configuration

### **Policy Configuration Structure**

The policy engine is driven by `governance_policy.json`:

```json
{
  "version": "1.0.0",
  "enforcementMode": "STRICT",
  "policies": {
    "dependency_control": {
      "enabled": true,
      "severity": "HIGH",
      "rules": {
        "allowed_libraries": ["axios", "lodash", "express"],
        "blocked_libraries": ["request", "eval", "vm2"],
        "require_approval_for": ["axios", "lodash"]
      }
    },
    "file_sensitivity": {
      "enabled": true,
      "severity": "CRITICAL",
      "protected_paths": ["/src/auth", "/.env", "/config"],
      "require_human_approval": true
    },
    "data_protection": {
      "enabled": true,
      "severity": "CRITICAL",
      "rules": {
        "personal_data_fields": ["ssn", "creditcard", "email"],
        "blocked_exports": ["api_response", "console_log"]
      }
    }
  },
  "compliance": {
    "gdpr": { "enabled": true, "data_subject_rights": true },
    "pci_dss": { "enabled": true, "card_data_protection": true },
    "sox": { "enabled": true, "financial_data_protection": true }
  }
}
```

### **Policy Categories Explained**

1. **Dependency Control** - Which libraries are allowed/blocked
2. **File Sensitivity** - Protected areas requiring human approval
3. **AI Governance** - AI model usage and oversight requirements
4. **Data Protection** - GDPR, PCI DSS, privacy compliance
5. **Business Logic** - Business rules and operational policies
6. **Security Standards** - Security coding standards and practices

---

## 📚 AI-DevSecOps Interview Prep

**Q: How does the Policy Engine differ from traditional security scanning?**

**A**: Traditional security scanning looks for technical vulnerabilities (SQL injection, XSS). The Policy Engine looks for business and compliance violations (GDPR breaches, forbidden libraries, business rule violations). It's the difference between "is this code insecure?" and "is this code compliant with our business rules?"

**Q: Why is policy enforcement especially important for AI-generated code?**

**A**: AI agents don't understand business context, compliance requirements, or organizational policies. They might use a blocked library because it's in their training data, expose personal data because they don't understand privacy laws, or hardcode business values because they don't know about configuration management. The Policy Engine provides the business context that AI agents lack.

**Q: How does the Policy Engine handle exceptions and overrides?**

**A**: The Policy Engine supports contextual exceptions (development vs production), emergency overrides (with time limits and approval requirements), and compliance framework variations. Each violation includes business impact assessment and remediation complexity to help with override decisions.

**Q: What's the relationship between Policy Engine violations and the Hard Guardrail?**

**A**: Policy violations feed into the same Hard Guardrail system as technical violations. A GDPR data exposure violation or a blocked library violation will block phase transitions just like a hardcoded secret would. The Hard Guardrail doesn't care if the violation is technical or policy-based - if it's critical or high severity, it blocks deployment.

---

## 🎯 Check for Understanding

**Question**: Why does the Policy Engine check both the library name AND the approval requirements? Why not just block everything not on the allowed list?

*Hint: Think about developer productivity vs. security control...*

---

## 🚀 Ready for Lesson 08?

Next up, we'll explore **Shell Operations** - how we "handcuff" the shell to protect the operating system from dangerous commands. Get ready to see operational security in action! 🔒

*Remember: Good AI-DevSecOps analysts enforce both technical security AND business compliance!* ⚖️🛡️
