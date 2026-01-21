// 🛡️ ADVERSARIAL TESTING: Security Standards Validator Red Team Exercise
// This script performs adversarial testing to verify the Security Standards Validator
// actually blocks bad code before integration.

import * as fs from 'fs/promises';
import * as path from 'path';
import { ScanEngine } from '../src/security/core/ScanEngine';
import { SecurityValidator } from '../src/security/core/SecurityValidator';
import { getAuditLogger } from '../src/security/core/AuditLogger';
import { Phase, ProjectContext } from '../src/security/types/SecurityViolation';

interface TestResult {
  testName: string;
  expectedViolations: number;
  actualViolations: number;
  criticalViolations: number;
  highViolations: number;
  passed: boolean;
  violations: any[];
}

class AdversarialTester {
  private scanEngine: ScanEngine;
  private securityValidator: SecurityValidator;
  private testResults: TestResult[] = [];

  constructor() {
    this.scanEngine = new ScanEngine();
    this.securityValidator = new SecurityValidator({
      scanScope: 'DELTA',
      realTimeStreaming: true,
      overrideAuthority: 'self',
      auditLogging: true,
      enableBackgroundScanning: true,
      maxScanDuration: 300
    });
  }

  async runAllTests(): Promise<void> {
    console.log('🛡️ ADVERSARIAL TESTING: Security Standards Validator');
    console.log('=' .repeat(70));
    console.log('🔴 RED TEAM EXERCISE: Testing if guardrails actually block bad code\n');

    try {
      // Test 1: LLM06 - Hardcoded API Key Detection
      await this.testLLM06_HardcodedSecrets();

      // Test 2: LLM01 - Prompt Injection Detection  
      await this.testLLM01_PromptInjection();

      // Test 3: LLM02 - Insecure Output Handling
      await this.testLLM02_InsecureOutput();

      // Test 4: Agent OS Coding Standards
      await this.testAgentOS_Standards();

      // Test 5: Hard Guardrail - Phase Transition Blocking
      await this.testHardGuardrail_PhaseTransition();

      // Test 6: Override Workflow
      await this.testOverrideWorkflow();

      // Generate final report
      await this.generateTestReport();

    } catch (error) {
      console.error('❌ Adversarial testing failed:', error);
    }
  }

  private async testLLM06_HardcodedSecrets(): Promise<void> {
    console.log('🔍 TEST 1: LLM06 - Hardcoded Secrets Detection');
    console.log('-'.repeat(50));

    const testFiles = [
      'test_vulnerability.py',
      'test_vulnerability.js', 
      'test_vulnerability.tsx'
    ];

    let totalViolations = 0;
    let criticalViolations = 0;
    const allViolations: any[] = [];

    for (const file of testFiles) {
      try {
        const content = await fs.readFile(file, 'utf8');
        const mockContext = {
          projectPath: file,
          phase: 'WINDSURF' as Phase,
          developerId: 'red-team-tester',
          modifiedFiles: [file],
          agentSource: 'windsurf'
        };

        const violations = await this.scanEngine.scanFile(file, content, mockContext);
        
        // Filter for LLM06 violations
        const llm06Violations = violations.filter(v => v.category === 'LLM06');
        const criticalLlm06 = llm06Violations.filter(v => v.severity === 'CRITICAL');

        console.log(`📁 ${file}:`);
        console.log(`   LLM06 Violations: ${llm06Violations.length}`);
        console.log(`   Critical: ${criticalLlm06.length}`);

        if (llm06Violations.length > 0) {
          console.log('   🚨 Detected Violations:');
          llm06Violations.forEach((v, i) => {
            console.log(`     ${i+1}. [${v.severity}] ${v.title}`);
            console.log(`        Code: ${v.codeSnippet.substring(0, 50)}...`);
          });
        }

        totalViolations += llm06Violations.length;
        criticalViolations += criticalLlm06.length;
        allViolations.push(...llm06Violations);

      } catch (error) {
        console.log(`❌ Failed to test ${file}:`, error);
      }
    }

    const expectedCritical = 6; // We expect at least 6 critical secrets across all files
    const passed = criticalViolations >= expectedCritical;

    this.testResults.push({
      testName: 'LLM06 - Hardcoded Secrets',
      expectedViolations: expectedCritical,
      actualViolations: totalViolations,
      criticalViolations,
      highViolations: 0,
      passed,
      violations: allViolations
    });

    console.log(`\n📊 RESULT: ${passed ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`   Expected Critical: ${expectedCritical}, Found: ${criticalViolations}`);
    console.log(`   Total LLM06 Violations: ${totalViolations}\n`);
  }

  private async testLLM01_PromptInjection(): Promise<void> {
    console.log('🔍 TEST 2: LLM01 - Prompt Injection Detection');
    console.log('-'.repeat(50));

    const testFiles = [
      'test_vulnerability.py',
      'test_vulnerability.js',
      'test_vulnerability.tsx'
    ];

    let totalViolations = 0;
    let highViolations = 0;
    const allViolations: any[] = [];

    for (const file of testFiles) {
      try {
        const content = await fs.readFile(file, 'utf8');
        const mockContext = {
          projectPath: file,
          phase: 'WINDSURF' as Phase,
          developerId: 'red-team-tester',
          modifiedFiles: [file],
          agentSource: 'windsurf'
        };

        const violations = await this.scanEngine.scanFile(file, content, mockContext);
        
        // Filter for LLM01 violations
        const llm01Violations = violations.filter(v => v.category === 'LLM01');
        const highLlm01 = llm01Violations.filter(v => v.severity === 'HIGH');

        console.log(`📁 ${file}:`);
        console.log(`   LLM01 Violations: ${llm01Violations.length}`);
        console.log(`   High Risk: ${highLlm01.length}`);

        if (llm01Violations.length > 0) {
          console.log('   🚨 Detected Violations:');
          llm01Violations.forEach((v, i) => {
            console.log(`     ${i+1}. [${v.severity}] ${v.title}`);
            console.log(`        Code: ${v.codeSnippet.substring(0, 50)}...`);
          });
        }

        totalViolations += llm01Violations.length;
        highViolations += highLlm01.length;
        allViolations.push(...llm01Violations);

      } catch (error) {
        console.log(`❌ Failed to test ${file}:`, error);
      }
    }

    const expectedHigh = 4; // We expect at least 4 high-risk prompt injections
    const passed = highViolations >= expectedHigh;

    this.testResults.push({
      testName: 'LLM01 - Prompt Injection',
      expectedViolations: expectedHigh,
      actualViolations: totalViolations,
      criticalViolations: 0,
      highViolations,
      passed,
      violations: allViolations
    });

    console.log(`\n📊 RESULT: ${passed ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`   Expected High Risk: ${expectedHigh}, Found: ${highViolations}`);
    console.log(`   Total LLM01 Violations: ${totalViolations}\n`);
  }

  private async testLLM02_InsecureOutput(): Promise<void> {
    console.log('🔍 TEST 3: LLM02 - Insecure Output Handling');
    console.log('-'.repeat(50));

    const testFiles = ['test_vulnerability.js', 'test_vulnerability.tsx'];
    let totalViolations = 0;
    const allViolations: any[] = [];

    for (const file of testFiles) {
      try {
        const content = await fs.readFile(file, 'utf8');
        const mockContext = {
          projectPath: file,
          phase: 'WINDSURF' as Phase,
          developerId: 'red-team-tester',
          modifiedFiles: [file],
          agentSource: 'windsurf'
        };

        const violations = await this.scanEngine.scanFile(file, content, mockContext);
        
        // Filter for LLM02 violations
        const llm02Violations = violations.filter(v => v.category === 'LLM02');

        console.log(`📁 ${file}:`);
        console.log(`   LLM02 Violations: ${llm02Violations.length}`);

        if (llm02Violations.length > 0) {
          console.log('   🚨 Detected Violations:');
          llm02Violations.forEach((v, i) => {
            console.log(`     ${i+1}. [${v.severity}] ${v.title}`);
            console.log(`        Code: ${v.codeSnippet.substring(0, 50)}...`);
          });
        }

        totalViolations += llm02Violations.length;
        allViolations.push(...llm02Violations);

      } catch (error) {
        console.log(`❌ Failed to test ${file}:`, error);
      }
    }

    const expectedViolations = 2; // We expect at least 2 insecure output violations
    const passed = totalViolations >= expectedViolations;

    this.testResults.push({
      testName: 'LLM02 - Insecure Output',
      expectedViolations,
      actualViolations: totalViolations,
      criticalViolations: 0,
      highViolations: 0,
      passed,
      violations: allViolations
    });

    console.log(`\n📊 RESULT: ${passed ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`   Expected Violations: ${expectedViolations}, Found: ${totalViolations}\n`);
  }

  private async testAgentOS_Standards(): Promise<void> {
    console.log('🔍 TEST 4: Agent OS Coding Standards');
    console.log('-'.repeat(50));

    const testFiles = [
      'test_vulnerability.py',
      'test_vulnerability.js',
      'test_vulnerability.tsx'
    ];

    let totalViolations = 0;
    const allViolations: any[] = [];

    for (const file of testFiles) {
      try {
        const content = await fs.readFile(file, 'utf8');
        const mockContext = {
          projectPath: file,
          phase: 'WINDSURF' as Phase,
          developerId: 'red-team-tester',
          modifiedFiles: [file],
          agentSource: 'windsurf'
        };

        const violations = await this.scanEngine.scanFile(file, content, mockContext);
        
        // Filter for coding standards violations
        const standardsViolations = violations.filter(v => v.category === 'CODING_STANDARDS');

        console.log(`📁 ${file}:`);
        console.log(`   Standards Violations: ${standardsViolations.length}`);

        if (standardsViolations.length > 0) {
          console.log('   🚨 Detected Violations:');
          standardsViolations.forEach((v, i) => {
            console.log(`     ${i+1}. [${v.severity}] ${v.title}`);
            console.log(`        Code: ${v.codeSnippet.substring(0, 50)}...`);
          });
        }

        totalViolations += standardsViolations.length;
        allViolations.push(...standardsViolations);

      } catch (error) {
        console.log(`❌ Failed to test ${file}:`, error);
      }
    }

    const expectedViolations = 3; // We expect at least 3 standards violations
    const passed = totalViolations >= expectedViolations;

    this.testResults.push({
      testName: 'Agent OS Coding Standards',
      expectedViolations,
      actualViolations: totalViolations,
      criticalViolations: 0,
      highViolations: 0,
      passed,
      violations: allViolations
    });

    console.log(`\n📊 RESULT: ${passed ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`   Expected Violations: ${expectedViolations}, Found: ${totalViolations}\n`);
  }

  private async testHardGuardrail_PhaseTransition(): Promise<void> {
    console.log('🔍 TEST 5: Hard Guardrail - Phase Transition Blocking');
    console.log('-'.repeat(50));

    // Create a project context with our vulnerability files
    const projectContext: ProjectContext = {
      name: 'Adversarial Test Project',
      path: './',
      currentPhase: 'WINDSURF',
      developerId: 'red-team-tester',
      securityScore: 25 // Low security score
    };

    try {
      console.log('🚀 Attempting phase transition: WINDSURF → ANTI_GRAVITY');
      console.log('   Project contains multiple critical vulnerabilities...');
      
      const validationResult = await this.securityValidator.validatePhaseTransition(
        'WINDSURF',
        'ANTI_GRAVITY',
        projectContext
      );

      console.log('\n📊 VALIDATION RESULTS:');
      console.log(`   Scan Duration: ${validationResult.scanDuration}ms`);
      console.log(`   Total Violations: ${validationResult.violations.length}`);
      console.log(`   Can Proceed: ${validationResult.canProceed}`);
      console.log(`   Requires Override: ${validationResult.requiresOverride}`);

      // Count critical and high violations
      const criticalCount = validationResult.violations.filter(v => v.severity === 'CRITICAL').length;
      const highCount = validationResult.violations.filter(v => v.severity === 'HIGH').length;

      console.log(`   Critical Violations: ${criticalCount}`);
      console.log(`   High Violations: ${highCount}`);

      // The guardrail should block transition due to critical violations
      const guardrailWorking = !validationResult.canProceed && validationResult.requiresOverride;
      const expectedCritical = 6;

      this.testResults.push({
        testName: 'Hard Guardrail - Phase Transition',
        expectedViolations: expectedCritical,
        actualViolations: validationResult.violations.length,
        criticalViolations: criticalCount,
        highViolations: highCount,
        passed: guardrailWorking && criticalCount >= expectedCritical,
        violations: validationResult.violations
      });

      console.log(`\n📊 RESULT: ${guardrailWorking ? '✅ PASS' : '❌ FAIL'}`);
      console.log(`   Guardrail Blocking: ${guardrailWorking ? 'WORKING' : 'FAILED'}`);
      console.log(`   Expected to Block: YES (due to ${criticalCount} critical violations)\n`);

    } catch (error) {
      console.error('❌ Phase transition test failed:', error);
    }
  }

  private async testOverrideWorkflow(): Promise<void> {
    console.log('🔍 TEST 6: Override Workflow');
    console.log('-'.repeat(50));

    try {
      // Simulate an override for a critical violation
      const mockViolationId = 'violation_test_12345';
      const justification = {
        businessReason: 'Red team testing - this is a controlled vulnerability',
        mitigationPlan: 'Will remove before production deployment',
        riskAcceptance: 'Accepting risk for adversarial testing only',
        expectedResolution: new Date(Date.now() + 24 * 60 * 60 * 1000) // 1 day
      };

      console.log('📝 Processing security override for test violation...');
      
      const override = await this.securityValidator.processOverride(
        mockViolationId,
        justification,
        'red-team-tester'
      );

      console.log('✅ Override processed successfully:');
      console.log(`   Override ID: ${override.id}`);
      console.log(`   Developer: ${override.developerId}`);
      console.log(`   Digital Signature: ${override.digitalSignature.substring(0, 20)}...`);

      // Verify audit log entry was created
      const auditLogger = getAuditLogger();
      const recentEvents = await auditLogger.getAuditHistory(5);
      const overrideEvents = recentEvents.filter(e => e.eventType === 'OVERRIDE');

      const auditWorking = overrideEvents.length > 0;
      
      this.testResults.push({
        testName: 'Override Workflow',
        expectedViolations: 1,
        actualViolations: overrideEvents.length,
        criticalViolations: 0,
        highViolations: 0,
        passed: auditWorking,
        violations: []
      });

      console.log(`\n📊 RESULT: ${auditWorking ? '✅ PASS' : '❌ FAIL'}`);
      console.log(`   Audit Log Entry: ${auditWorking ? 'CREATED' : 'MISSING'}\n`);

    } catch (error) {
      console.error('❌ Override workflow test failed:', error);
    }
  }

  private async generateTestReport(): Promise<void> {
    console.log('📋 ADVERSARIAL TESTING REPORT');
    console.log('=' .repeat(70));

    const totalTests = this.testResults.length;
    const passedTests = this.testResults.filter(r => r.passed).length;
    const failedTests = totalTests - passedTests;

    console.log(`\n📊 SUMMARY:`);
    console.log(`   Total Tests: ${totalTests}`);
    console.log(`   Passed: ${passedTests} ✅`);
    console.log(`   Failed: ${failedTests} ❌`);
    console.log(`   Success Rate: ${Math.round((passedTests / totalTests) * 100)}%`);

    console.log(`\n📋 DETAILED RESULTS:`);
    this.testResults.forEach((result, index) => {
      console.log(`\n${index + 1}. ${result.testName}`);
      console.log(`   Status: ${result.passed ? '✅ PASS' : '❌ FAIL'}`);
      console.log(`   Expected: ${result.expectedViolations}, Found: ${result.actualViolations}`);
      if (result.criticalViolations > 0) {
        console.log(`   Critical: ${result.criticalViolations}`);
      }
      if (result.highViolations > 0) {
        console.log(`   High: ${result.highViolations}`);
      }
    });

    // Overall assessment
    const allCriticalBlocked = this.testResults
      .filter(r => r.testName.includes('Guardrail'))
      .every(r => r.passed);

    const allVulnerabilitiesDetected = this.testResults
      .filter(r => r.testName.includes('LLM') || r.testName.includes('Standards'))
      .every(r => r.passed);

    console.log(`\n🎯 SECURITY ASSESSMENT:`);
    console.log(`   Critical Vulnerabilities Blocked: ${allCriticalBlocked ? '✅ YES' : '❌ NO'}`);
    console.log(`   All Vulnerability Types Detected: ${allVulnerabilitiesDetected ? '✅ YES' : '❌ NO'}`);
    console.log(`   Audit Trail Working: ${this.testResults.find(r => r.testName === 'Override Workflow')?.passed ? '✅ YES' : '❌ NO'}`);

    const readyForIntegration = allCriticalBlocked && allVulnerabilitiesDetected;
    console.log(`\n🚀 INTEGRATION READINESS:`);
    console.log(`   Status: ${readyForIntegration ? '✅ READY' : '❌ NOT READY'}`);
    
    if (readyForIntegration) {
      console.log(`   ✅ The Security Standards Validator has passed adversarial testing!`);
      console.log(`   ✅ Hard guardrails are working correctly!`);
      console.log(`   ✅ Ready for integration into Windsurf, Anti-Gravity, and VS Code!`);
    } else {
      console.log(`   ❌ Security guardrails need fixes before integration!`);
      console.log(`   ❌ Address failed tests before proceeding!`);
    }

    console.log('\n' + '=' .repeat(70));
  }
}

// Run the adversarial testing
export async function runAdversarialTests(): Promise<void> {
  const tester = new AdversarialTester();
  await tester.runAllTests();
}

// If this file is run directly, execute the tests
if (require.main === module) {
  runAdversarialTests().catch(console.error);
}
