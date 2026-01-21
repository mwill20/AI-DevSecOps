import { SecurityViolation, ScanContext, ValidationResult } from '../types/SecurityViolation';
import { ScanEngine } from './ScanEngine';
import { SemanticAnalyzer, SemanticViolation } from './SemanticAnalyzer';
import { PolicyEngine, PolicyViolation } from './PolicyEngine';
import { ShellInterceptor, OperationalViolation } from './ShellInterceptor';
import { AuditLogger } from './AuditLogger';

export interface EnhancedValidationResult extends ValidationResult {
  layerBreakdown: {
    deterministic: number;
    semantic: number;
    policy: number;
    operational: number;
  };
  totalViolations: number;
  layerViolations: {
    deterministic: SecurityViolation[];
    semantic: SemanticViolation[];
    policy: PolicyViolation[];
    operational: OperationalViolation[];
  };
}

export interface SecurityValidatorConfig {
  scanScope: 'FULL' | 'DELTA';
  realTimeStreaming: boolean;
  overrideAuthority: 'self' | 'team' | 'security';
  auditLogging: boolean;
  enableBackgroundScanning: boolean;
  maxScanDuration: number;
  enableSemanticAnalysis: boolean;
  enablePolicyEnforcement: boolean;
  enableOperationalGuardrails: boolean;
}

export class EnhancedSecurityValidator {
  private scanEngine: ScanEngine;
  private semanticAnalyzer: SemanticAnalyzer;
  private policyEngine: PolicyEngine;
  private shellInterceptor: ShellInterceptor;
  private auditLogger: AuditLogger;
  private config: SecurityValidatorConfig;
  private isScanning: boolean;

  constructor(config: SecurityValidatorConfig) {
    this.config = config;
    this.scanEngine = new ScanEngine();
    this.semanticAnalyzer = config.enableSemanticAnalysis ? new SemanticAnalyzer() : null;
    this.policyEngine = config.enablePolicyEnforcement ? new PolicyEngine() : null;
    this.shellInterceptor = config.enableOperationalGuardrails ? new ShellInterceptor() : null;
    this.auditLogger = config.auditLogging ? new AuditLogger() : null;
    this.isScanning = false;
  }

  async validatePhaseTransition(
    fromPhase: string, 
    toPhase: string, 
    projectContext: any
  ): Promise<EnhancedValidationResult> {
    if (this.isScanning) {
      throw new Error('Security scan already in progress');
    }

    const startTime = Date.now();
    
    try {
      this.isScanning = true;
      
      // Log scan start
      if (this.auditLogger) {
        await this.auditLogger.logScanStart(
          projectContext.developerId, 
          projectContext.path, 
          projectContext.agentSource
        );
      }

      // Perform 3-layer security scan
      const allViolations = await this.perform3LayerScan(projectContext);
      
      const scanDuration = Date.now() - startTime;
      
      // Log scan completion
      if (this.auditLogger) {
        await this.auditLogger.logScanComplete(
          projectContext.developerId,
          allViolations.totalViolations,
          scanDuration
        );
      }

      // Determine if transition is allowed
      const hasBlockingViolations = this.hasBlockingViolations(allViolations);
      const canProceed = !hasBlockingViolations || this.allViolationsOverridden(allViolations);

      const result: EnhancedValidationResult = {
        passed: allViolations.totalViolations === 0,
        violations: this.flattenViolations(allViolations),
        scanDuration,
        canProceed,
        requiresOverride: hasBlockingViolations,
        layerBreakdown: {
          deterministic: allViolations.layerViolations.deterministic.length,
          semantic: allViolations.layerViolations.semantic.length,
          policy: allViolations.layerViolations.policy.length,
          operational: allViolations.layerViolations.operational.length
        },
        totalViolations: allViolations.totalViolations,
        layerViolations: allViolations.layerViolations
      };

      // If blocking violations exist, trigger Hard Guardrail Modal
      if (!canProceed) {
        await this.triggerHardGuardrailModal(result, projectContext);
      }

      return result;

    } finally {
      this.isScanning = false;
    }
  }

  private async perform3LayerScan(projectContext: any): Promise<EnhancedValidationResult['layerViolations'] & { totalViolations: number }> {
    const layerViolations = {
      deterministic: [] as SecurityViolation[],
      semantic: [] as SemanticViolation[],
      policy: [] as PolicyViolation[],
      operational: [] as OperationalViolation[]
    };

    // Layer 1: Deterministic Scanning (Original ScanEngine)
    console.log('🔍 Layer 1: Deterministic Pattern Matching');
    const deterministicViolations = await this.scanEngine.scanProject(projectContext.path, projectContext);
    layerViolations.deterministic = deterministicViolations;
    console.log(`   Found ${deterministicViolations.length} deterministic violations`);

    // Layer 2: Semantic Analysis (AST-based)
    if (this.semanticAnalyzer) {
      console.log('🧠 Layer 2: Semantic AST Analysis');
      const content = this.getFileContent(projectContext.path);
      const semanticViolations = await this.semanticAnalyzer.analyzeCode(content, projectContext);
      layerViolations.semantic = semanticViolations;
      console.log(`   Found ${semanticViolations.length} semantic violations`);
    }

    // Layer 3: Policy Enforcement
    if (this.policyEngine) {
      console.log('⚖️ Layer 3: Policy Engine');
      const content = this.getFileContent(projectContext.path);
      const policyViolations = await this.policyEngine.evaluatePolicy(content, projectContext);
      layerViolations.policy = policyViolations;
      console.log(`   Found ${policyViolations.length} policy violations`);
    }

    // Layer 4: Operational Guardrails (Shell Commands)
    if (this.shellInterceptor) {
      console.log('🔒 Layer 4: Operational Guardrails');
      const operationalViolations = await this.testOperationalGuardrails();
      layerViolations.operational = operationalViolations;
      console.log(`   Found ${operationalViolations.length} operational violations`);
    }

    const totalViolations = layerViolations.deterministic.length + 
                           layerViolations.semantic.length + 
                           layerViolations.policy.length + 
                           layerViolations.operational.length;

    return { layerViolations, totalViolations };
  }

  private getFileContent(filePath: string): string {
    // In a real implementation, this would read the actual file
    // For now, return mock content for testing
    return `// Mock file content for ${filePath}`;
  }

  private async testOperationalGuardrails(): Promise<OperationalViolation[]> {
    if (!this.shellInterceptor) return [];

    const violations = [];
    
    // Test dangerous shell commands
    const dangerousCommands = [
      { command: 'rm', args: ['-rf', '/important/data'], workingDirectory: '/home/user' },
      { command: 'sudo', args: ['chmod', '777', '/etc/passwd'], workingDirectory: '/home/user' },
      { command: 'shutdown', args: ['-h', 'now'], workingDirectory: '/home/user' }
    ];
    
    for (const cmd of dangerousCommands) {
      const shellCommand = {
        ...cmd,
        userId: 'test-user',
        timestamp: new Date(),
        sessionId: 'test-session'
      };
      
      const result = await this.shellInterceptor.interceptCommand(shellCommand);
      if (!result.allowed && result.violation) {
        violations.push(result.violation);
      }
    }
    
    return violations;
  }

  private hasBlockingViolations(allViolations: EnhancedValidationResult['layerViolations']): boolean {
    const allFlatViolations = this.flattenViolations(allViolations);
    return allFlatViolations.some(v => v.severity === 'CRITICAL' || v.severity === 'HIGH');
  }

  private allViolationsOverridden(allViolations: EnhancedValidationResult['layerViolations']): boolean {
    const allFlatViolations = this.flattenViolations(allViolations);
    return allFlatViolations.length > 0 && allFlatViolations.every(v => v.override);
  }

  private flattenViolations(layerViolations: EnhancedValidationResult['layerViolations']): SecurityViolation[] {
    return [
      ...layerViolations.deterministic,
      ...layerViolations.semantic,
      ...layerViolations.policy,
      ...layerViolations.operational
    ];
  }

  private async triggerHardGuardrailModal(result: EnhancedValidationResult, projectContext: any): Promise<void> {
    console.log('\n🚨 HARD GUARDRAIL MODAL ACTIVATED');
    console.log('=' .repeat(50));
    
    console.log(`📊 SECURITY SCAN RESULTS:`);
    console.log(`   Total Violations: ${result.totalViolations}`);
    console.log(`   Can Proceed: ${result.canProceed ? 'YES ✅' : 'NO 🚨'}`);
    
    console.log(`\n📋 LAYER BREAKDOWN:`);
    console.log(`   Deterministic: ${result.layerBreakdown.deterministic} violations`);
    console.log(`   Semantic: ${result.layerBreakdown.semantic} violations`);
    console.log(`   Policy: ${result.layerBreakdown.policy} violations`);
    console.log(`   Operational: ${result.layerBreakdown.operational} violations`);
    
    const blockingViolations = this.flattenViolations(result.layerViolations)
      .filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH');
    
    if (blockingViolations.length > 0) {
      console.log(`\n🚨 BLOCKING VIOLATIONS (${blockingViolations.length}):`);
      blockingViolations.forEach((v, i) => {
        console.log(`   ${i+1}. [${v.severity}] ${v.title}`);
        console.log(`      Layer: ${this.getViolationLayer(v)}`);
        console.log(`      Description: ${v.description}`);
        console.log(`      File: ${v.file}`);
        if (v.codeSnippet) {
          console.log(`      Code: ${v.codeSnippet.substring(0, 50)}...`);
        }
      });
    }
    
    console.log('\n🎯 MODAL OPTIONS:');
    console.log('   1. Fix Violations - Address each blocking violation');
    console.log('   2. Override - Provide justification for proceeding');
    console.log('   3. Cancel - Abort the phase transition');
    
    // In a real implementation, this would trigger the actual modal UI
    // For now, we'll simulate the modal interaction
    console.log('\n⏸️  SIMULATED USER ACTION: Fix Violations');
    console.log('   User chose to fix violations before proceeding...');
    
    // Log the guardrail activation
    if (this.auditLogger) {
      await this.auditLogger.logGuardrailActivation(
        projectContext.developerId,
        blockingViolations,
        'PHASE_TRANSITION_BLOCKED'
      );
    }
  }

  private getViolationLayer(violation: SecurityViolation): string {
    if ('semanticType' in violation) return 'Semantic';
    if ('policyId' in violation) return 'Policy';
    if ('operationalRisk' in violation) return 'Operational';
    return 'Deterministic';
  }

  async processOverride(
    violationId: string, 
    justification: any,
    developerId: string
  ): Promise<any> {
    const override = {
      id: this.generateId(),
      violationId,
      justification,
      developerId,
      digitalSignature: '', // Would be generated by AuditLogger
      approvedAt: new Date(),
      auditLogEntry: '' // Would be set by AuditLogger
    };

    // Log the override
    if (this.auditLogger) {
      await this.auditLogger.logOverride(override, developerId);
    }

    return override;
  }

  async triggerOperationalGuardrail(violation: OperationalViolation): Promise<void> {
    console.log('\n🔒 OPERATIONAL GUARDRAIL TRIGGERED');
    console.log('=' .repeat(40));
    console.log(`Command: ${violation.command} ${violation.args.join(' ')}`);
    console.log(`Risk: ${violation.operationalRisk}`);
    console.log(`Description: ${violation.description}`);
    console.log(`Severity: ${violation.severity}`);
    
    // Log operational violation
    if (this.auditLogger) {
      await this.auditLogger.logOperationalViolation(violation);
    }
  }

  private generateId(): string {
    return `override_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Real-time scanning integration
  async startRealTimeScan(projectPath: string): Promise<void> {
    if (!this.config.realTimeStreaming) {
      return;
    }

    console.log(`Starting real-time 3-layer scan for ${projectPath}`);
    
    // In a real implementation, this would integrate with file system watchers
    // For now, we'll implement a placeholder that demonstrates the concept
    setInterval(async () => {
      if (!this.isScanning) {
        console.log('🔍 Real-time scan: Monitoring for changes...');
        // Would scan changed files with all 3 layers
      }
    }, 30000); // Check every 30 seconds
  }

  // Get security status for dashboard
  async getSecurityStatus(projectPath: string): Promise<any> {
    const projectContext = {
      path: projectPath,
      phase: 'CURRENT',
      developerId: 'system',
      agentSource: 'dashboard'
    };

    const scanResult = await this.perform3LayerScan(projectContext);
    
    return {
      securityScore: this.calculateSecurityScore(scanResult),
      lastScan: new Date(),
      layerBreakdown: scanResult.layerBreakdown,
      criticalViolations: scanResult.layerViolations.deterministic.filter(v => v.severity === 'CRITICAL').length +
                         scanResult.layerViolations.semantic.filter(v => v.severity === 'CRITICAL').length +
                         scanResult.layerViolations.policy.filter(v => v.severity === 'CRITICAL').length +
                         scanResult.layerViolations.operational.filter(v => v.severity === 'CRITICAL').length,
      status: scanResult.totalViolations === 0 ? 'SECURE' : 'VIOLATIONS_DETECTED'
    };
  }

  private calculateSecurityScore(scanResult: EnhancedValidationResult['layerViolations'] & { totalViolations: number }): number {
    const maxScore = 100;
    const deductions = {
      CRITICAL: 25,
      HIGH: 15,
      MEDIUM: 10,
      LOW: 5
    };

    let score = maxScore;
    const allViolations = this.flattenViolations(scanResult);

    for (const violation of allViolations) {
      score -= deductions[violation.severity] || 0;
    }

    return Math.max(0, score);
  }
}
