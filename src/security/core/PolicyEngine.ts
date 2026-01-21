import { SecurityViolation, ScanContext } from '../types/SecurityViolation';

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
    ai_governance: {
      enabled: boolean;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      description: string;
      rules: {
        approved_ai_models: string[];
        require_human_oversight: string[];
        max_token_limit: number;
        require_documentation: boolean;
      };
    };
    data_protection: {
      enabled: boolean;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      description: string;
      rules: {
        personal_data_fields: string[];
        blocked_exports: string[];
        encryption_required: string[];
      };
    };
    business_logic: {
      enabled: boolean;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      description: string;
      rules: {
        no_hardcoded_business_values: string[];
        require_error_handling: string[];
        require_logging: string[];
      };
    };
    security_standards: {
      enabled: boolean;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      description: string;
      rules: {
        forbidden_patterns: string[];
        required_security_headers: string[];
        require_authentication: string[];
      };
    };
  };
  exceptions: {
    development_environment: {
      enabled: boolean;
      conditions: {
        branch: string[];
        environment: string;
      };
      relaxed_policies: string[];
    };
    emergency_override: {
      enabled: boolean;
      conditions: {
        requires_approval: boolean;
        approval_role: string;
        time_limit: string;
      };
      allowed_overrides: string[];
    };
  };
  compliance: {
    gdpr: {
      enabled: boolean;
      data_subject_rights: boolean;
      consent_required: boolean;
      data_minimization: boolean;
      right_to_erasure: boolean;
    };
    pci_dss: {
      enabled: boolean;
      card_data_protection: boolean;
      encryption_required: boolean;
      access_control: boolean;
      audit_logging: boolean;
    };
    sox: {
      enabled: boolean;
      financial_data_protection: boolean;
      change_management: boolean;
      audit_trail: boolean;
      segregation_of_duties: boolean;
    };
  };
  monitoring: {
    alert_thresholds: {
      policy_violations_per_hour: number;
      critical_violations_per_day: number;
      override_requests_per_week: number;
    };
    escalation_rules: {
      critical_policy_violation: {
        notify: string[];
        escalation_time: string;
      };
      repeated_violations: {
        notify: string[];
        threshold: number;
        time_window: string;
      };
    };
  };
}

export interface PolicyViolation extends SecurityViolation {
  policyId: string;
  policyCategory: string;
  complianceFramework?: string;
  businessImpact: 'HIGH' | 'MEDIUM' | 'LOW';
  remediationComplexity: 'SIMPLE' | 'MODERATE' | 'COMPLEX';
}

export class PolicyEngine {
  private policy: GovernancePolicy;
  private policyPath: string;

  constructor(policyPath: string = './src/security/policies/governance_policy.json') {
    this.policyPath = policyPath;
    this.policy = this.getDefaultPolicy(); // Initialize with default policy
    this.loadPolicy();
  }

  private loadPolicy(): void {
    try {
      // In a real implementation, we'd use fs.readFileSync here
      // For now, we'll use the default policy
      console.log('Policy loading would happen here');
    } catch (error) {
      console.warn('Policy file not found, using default policy');
      this.policy = this.getDefaultPolicy();
    }
  }

  private getDefaultPolicy(): GovernancePolicy {
    return {
      version: "1.0.0",
      lastUpdated: new Date().toISOString(),
      enforcementMode: "STRICT",
      policies: {
        dependency_control: {
          enabled: true,
          severity: "HIGH",
          description: "Control which libraries can be used in the project",
          rules: {
            allowed_libraries: ["axios", "lodash", "express", "react", "typescript", "@types/node", "jest", "eslint"],
            blocked_libraries: ["request", "eval", "vm2", "child_process"],
            require_approval_for: ["axios", "lodash"]
          }
        },
        file_sensitivity: {
          enabled: true,
          severity: "CRITICAL",
          description: "Mandate human approval for sensitive file changes",
          protected_paths: ["/src/auth", "/.env", "/config/database.js", "/config/keys.json", "/src/security"],
          require_human_approval: true,
          approval_workflow: "SECURITY_REVIEW"
        },
        ai_governance: {
          enabled: true,
          severity: "HIGH",
          description: "AI model usage and governance policies",
          rules: {
            approved_ai_models: ["gpt-3.5-turbo", "gpt-4", "claude-3"],
            require_human_oversight: ["financial_decisions", "user_authentication", "data_deletion"],
            max_token_limit: 4000,
            require_documentation: true
          }
        },
        data_protection: {
          enabled: true,
          severity: "CRITICAL",
          description: "Data protection and privacy compliance",
          rules: {
            personal_data_fields: ["ssn", "socialSecurityNumber", "creditcard", "creditCard", "email", "phoneNumber", "address"],
            blocked_exports: ["api_response", "console_log", "third_party_api"],
            encryption_required: ["database_storage", "api_transmission", "file_storage"]
          }
        },
        business_logic: {
          enabled: true,
          severity: "MEDIUM",
          description: "Business logic and operational policies",
          rules: {
            no_hardcoded_business_values: ["prices", "limits", "timeouts", "thresholds"],
            require_error_handling: ["api_calls", "database_operations", "file_operations"],
            require_logging: ["authentication_events", "payment_processing", "data_modification"]
          }
        },
        security_standards: {
          enabled: true,
          severity: "HIGH",
          description: "Security coding standards and practices",
          rules: {
            forbidden_patterns: ["eval(", "new Function(", "document.write(", "innerHTML", "outerHTML"],
            required_security_headers: ["X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"],
            require_authentication: ["admin_endpoints", "data_modification", "config_changes"]
          }
        }
      },
      exceptions: {
        development_environment: {
          enabled: true,
          conditions: {
            branch: ["feature/*", "dev/*"],
            environment: "development"
          },
          relaxed_policies: ["file_sensitivity", "business_logic"]
        },
        emergency_override: {
          enabled: true,
          conditions: {
            requires_approval: true,
            approval_role: "SECURITY_LEAD",
            time_limit: "24h"
          },
          allowed_overrides: ["dependency_control", "security_standards"]
        }
      },
      compliance: {
        gdpr: {
          enabled: true,
          data_subject_rights: true,
          consent_required: true,
          data_minimization: true,
          right_to_erasure: true
        },
        pci_dss: {
          enabled: true,
          card_data_protection: true,
          encryption_required: true,
          access_control: true,
          audit_logging: true
        },
        sox: {
          enabled: true,
          financial_data_protection: true,
          change_management: true,
          audit_trail: true,
          segregation_of_duties: true
        }
      },
      monitoring: {
        alert_thresholds: {
          policy_violations_per_hour: 10,
          critical_violations_per_day: 5,
          override_requests_per_week: 3
        },
        escalation_rules: {
          critical_policy_violation: {
            notify: ["security_team", "dev_lead"],
            escalation_time: "15m"
          },
          repeated_violations: {
            notify: ["security_team", "management"],
            threshold: 3,
            time_window: "1h"
          }
        }
      }
    };
  }

  async evaluatePolicy(content: string, context: ScanContext): Promise<PolicyViolation[]> {
    const violations: PolicyViolation[] = [];

    // 1. Check dependency control
    const dependencyViolations = await this.checkDependencyControl(content, context);
    violations.push(...dependencyViolations);

    // 2. Check file sensitivity
    const fileViolations = await this.checkFileSensitivity(context);
    violations.push(...fileViolations);

    // 3. Check data protection
    const dataViolations = await this.checkDataProtection(content, context);
    violations.push(...dataViolations);

    // 4. Check business logic
    const businessViolations = await this.checkBusinessLogic(content, context);
    violations.push(...businessViolations);

    // 5. Check security standards
    const securityViolations = await this.checkSecurityStandards(content, context);
    violations.push(...securityViolations);

    return violations;
  }

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

  private async checkBusinessLogic(content: string, context: ScanContext): Promise<PolicyViolation[]> {
    const violations: PolicyViolation[] = [];
    const policy = this.policy.policies.business_logic;

    if (!policy.enabled) return violations;

    // Check for hardcoded business values
    for (const valueType of policy.rules.no_hardcoded_business_values) {
      const regex = new RegExp(`${valueType}\\s*=\\s*\\d+`, 'gi');
      const matches = content.match(regex);
      
      if (matches) {
        violations.push(this.createPolicyViolation(
          'business_logic',
          'HARDCODED_BUSINESS_VALUE',
          `Hardcoded business value detected: ${valueType}`,
          policy.severity,
          context,
          { valueType, matches: matches.length }
        ));
      }
    }

    return violations;
  }

  private async checkSecurityStandards(content: string, context: ScanContext): Promise<PolicyViolation[]> {
    const violations: PolicyViolation[] = [];
    const policy = this.policy.policies.security_standards;

    if (!policy.enabled) return violations;

    // Check for forbidden patterns
    for (const pattern of policy.rules.forbidden_patterns) {
      if (content.includes(pattern)) {
        violations.push(this.createPolicyViolation(
          'security_standards',
          'FORBIDDEN_PATTERN',
          `Forbidden security pattern detected: ${pattern}`,
          policy.severity,
          context,
          { pattern }
        ));
      }
    }

    return violations;
  }

  private extractImports(content: string): string[] {
    const imports: string[] = [];
    
    // Match various import patterns
    const patterns = [
      /import\s+.*?\s+from\s+['"]([^'"]+)['"]/g,
      /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g
    ];

    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const importName = match[1].split('/')[0]; // Get the main package name
        if (!imports.includes(importName)) {
          imports.push(importName);
        }
      }
    }

    return imports;
  }

  private createPolicyViolation(
    policyId: string,
    violationType: string,
    description: string,
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
    context: ScanContext,
    details: any
  ): PolicyViolation {
    return {
      id: `policy_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      severity,
      category: 'POLICY_VIOLATION',
      title: `${policyId}: ${violationType}`,
      description,
      file: context.projectPath,
      line: 1, // Policy violations apply to the whole file
      codeSnippet: JSON.stringify(details, null, 2),
      recommendation: this.getRecommendation(policyId, violationType),
      cweReference: this.getCWEReference(policyId),
      agentSource: context.agentSource,
      status: 'OPEN',
      discoveredAt: new Date(),
      policyId,
      policyCategory: policyId,
      businessImpact: this.calculateBusinessImpact(policyId, severity),
      remediationComplexity: this.calculateRemediationComplexity(policyId, violationType)
    };
  }

  private getRecommendation(policyId: string, violationType: string): string {
    const recommendations: Record<string, Record<string, string>> = {
      'dependency_control': {
        'BLOCKED_LIBRARY': 'Remove the blocked library and use an approved alternative',
        'APPROVAL_REQUIRED': 'Submit an approval request to the security team'
      },
      'file_sensitivity': {
        'SENSITIVE_FILE_CHANGE': 'Obtain human approval from security team before proceeding'
      },
      'data_protection': {
        'PERSONAL_DATA_EXPOSURE': 'Remove personal data from exports or implement proper masking'
      },
      'business_logic': {
        'HARDCODED_BUSINESS_VALUE': 'Move business values to configuration files'
      },
      'security_standards': {
        'FORBIDDEN_PATTERN': 'Remove the forbidden pattern and use a secure alternative'
      }
    };

    return recommendations[policyId]?.[violationType] || 'Review and remediate the policy violation';
  }

  private getCWEReference(policyId: string): string {
    const cweMap: Record<string, string> = {
      'dependency_control': 'CWE-937',
      'data_protection': 'CWE-200',
      'security_standards': 'CWE-79',
      'business_logic': 'CWE-732'
    };

    return cweMap[policyId] || 'CWE-16';
  }

  private calculateBusinessImpact(policyId: string, severity: string): 'HIGH' | 'MEDIUM' | 'LOW' {
    const impactMap: Record<string, 'HIGH' | 'MEDIUM' | 'LOW'> = {
      'file_sensitivity': 'HIGH',
      'data_protection': 'HIGH',
      'dependency_control': 'MEDIUM',
      'security_standards': 'HIGH',
      'business_logic': 'LOW'
    };

    return impactMap[policyId] || 'MEDIUM';
  }

  private calculateRemediationComplexity(policyId: string, violationType: string): 'SIMPLE' | 'MODERATE' | 'COMPLEX' {
    const complexityMap: Record<string, 'SIMPLE' | 'MODERATE' | 'COMPLEX'> = {
      'APPROVAL_REQUIRED': 'SIMPLE',
      'BLOCKED_LIBRARY': 'MODERATE',
      'SENSITIVE_FILE_CHANGE': 'COMPLEX',
      'PERSONAL_DATA_EXPOSURE': 'MODERATE',
      'HARDCODED_BUSINESS_VALUE': 'SIMPLE',
      'FORBIDDEN_PATTERN': 'MODERATE'
    };

    return complexityMap[violationType] || 'MODERATE';
  }
}
