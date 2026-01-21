import { SecurityViolation, ScanContext } from '../types/SecurityViolation';

export interface SecurityPattern {
  id: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  pattern: RegExp;
  description: string;
  recommendation: string;
  cweReference?: string;
}

export interface ViolationDetector {
  readonly category: string;
  readonly severity: ViolationSeverity;
  
  detect(content: string, context: ScanContext): Promise<SecurityViolation[]>;
  getPatterns(): SecurityPattern[];
  generateFix(violation: SecurityViolation): string;
}

export type ViolationSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

// OWASP LLM Top 10 Pattern Definitions
export const OWASP_LLM_PATTERNS: SecurityPattern[] = [
  // LLM01: Prompt Injection
  {
    id: 'LLM01-001',
    category: 'LLM01',
    severity: 'HIGH',
    pattern: /(?:prompt|input)\s*=\s*["'`][^"'`]*?(?:ignore|forget|disregard|system|admin|root)/i,
    description: 'Potential prompt injection vulnerability detected',
    recommendation: 'Validate and sanitize all user inputs before including in prompts',
    cweReference: 'CWE-74'
  },
  
  // LLM06: Sensitive Information Disclosure
  {
    id: 'LLM06-001',
    category: 'LLM06',
    severity: 'CRITICAL',
    pattern: /(?:api_key|apikey|secret|token|password|pwd)\s*=\s*["'`][a-zA-Z0-9_-]{10,}["'`]/i,
    description: 'Hardcoded sensitive information detected',
    recommendation: 'Move sensitive data to environment variables or secure configuration',
    cweReference: 'CWE-798'
  },
  
  // LLM06: Additional API Key patterns
  {
    id: 'LLM06-002',
    category: 'LLM06',
    severity: 'CRITICAL',
    pattern: /(?:sk-|pk_|sk_|AIza)[a-zA-Z0-9_-]{20,}/,
    description: 'Potential API key or token detected',
    recommendation: 'Remove hardcoded credentials and use secure key management',
    cweReference: 'CWE-798'
  },
  
  // LLM02: Insecure Output Handling
  {
    id: 'LLM02-001',
    category: 'LLM02',
    severity: 'MEDIUM',
    pattern: /(?:dangerouslySetInnerHTML|innerHTML|outerHTML)\s*=\s*[^;]+;/i,
    description: 'Direct HTML assignment without sanitization',
    recommendation: 'Use proper output sanitization libraries like DOMPurify',
    cweReference: 'CWE-79'
  },
  
  // Agent OS Coding Standards
  {
    id: 'AOS-001',
    category: 'CODING_STANDARDS',
    severity: 'HIGH',
    pattern: /console\.(log|debug|info|warn|error)\s*\([^)]*["'`][^"'`]*?(?:password|secret|token|key)/i,
    description: 'Sensitive information logged to console',
    recommendation: 'Remove sensitive data from console logs',
    cweReference: 'CWE-532'
  },
  
  {
    id: 'AOS-002',
    category: 'CODING_STANDARDS',
    severity: 'MEDIUM',
    pattern: /catch\s*\(\s*\)\s*\{\s*\}/,
    description: 'Empty catch block detected',
    recommendation: 'Add proper error handling or logging in catch blocks',
    cweReference: 'CWE-390'
  }
];

class ScanEngine {
  private detectors: Map<string, ViolationDetector>;
  private patterns: SecurityPattern[];

  constructor() {
    this.detectors = new Map();
    this.patterns = OWASP_LLM_PATTERNS;
    this.initializeDetectors();
  }

  private initializeDetectors(): void {
    // Initialize OWASP LLM detectors
    this.detectors.set('LLM01', new PromptInjectionDetector());
    this.detectors.set('LLM02', new InsecureOutputDetector());
    this.detectors.set('LLM06', new SensitiveInfoDetector());
    this.detectors.set('CODING_STANDARDS', new CodingStandardsDetector());
  }

  async scanProject(projectPath: string, context: ScanContext): Promise<SecurityViolation[]> {
    const violations: SecurityViolation[] = [];
    
    // For now, we'll simulate scanning files
    // In a real implementation, this would:
    // 1. Read all files in the project
    // 2. Apply each detector to each file
    // 3. Aggregate results
    
    const mockViolations = await this.generateMockViolations(context);
    violations.push(...mockViolations);
    
    return violations;
  }

  async scanFile(filePath: string, content: string, context: ScanContext): Promise<SecurityViolation[]> {
    const violations: SecurityViolation[] = [];
    
    // Apply all detectors to the file content
    for (const [category, detector] of this.detectors) {
      const fileViolations = await detector.detect(content, context);
      violations.push(...fileViolations);
    }
    
    return violations;
  }

  async startRealTimeScan(projectPath: string): Promise<AsyncIterable<SecurityViolation>> {
    // This would implement real-time file watching
    // For now, return an empty async iterable
    return (async function*() {
      // Yield violations as they're detected
    })();
  }

  private async generateMockViolations(context: ScanContext): Promise<SecurityViolation[]> {
    const violations: SecurityViolation[] = [];
    
    // Generate mock violations based on agent source
    if (context.agentSource === 'windsurf') {
      violations.push(this.createViolation(
        'LLM06-001',
        'CRITICAL',
        'LLM06',
        'Hardcoded API key detected',
        'API key found in configuration file',
        'src/config/api.ts',
        15,
        'const API_KEY = "sk-1234567890abcdef";',
        'Move API key to environment variables',
        'CWE-798',
        context.agentSource
      ));
    }
    
    if (context.agentSource === 'anti-gravity') {
      violations.push(this.createViolation(
        'LLM02-001',
        'MEDIUM',
        'LLM02',
        'Insecure output handling',
        'Raw HTML output without sanitization',
        'src/components/Output.tsx',
        42,
        'div.innerHTML = userInput;',
        'Use DOMPurify or similar for sanitization',
        'CWE-79',
        context.agentSource
      ));
    }
    
    return violations;
  }

  private createViolation(
    patternId: string,
    severity: ViolationSeverity,
    category: string,
    title: string,
    description: string,
    file: string,
    line: number,
    codeSnippet: string,
    recommendation: string,
    cweReference?: string,
    agentSource?: string
  ): SecurityViolation {
    return {
      id: `violation_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      severity,
      category,
      title,
      description,
      file,
      line,
      codeSnippet,
      recommendation,
      cweReference,
      agentSource,
      status: 'OPEN',
      discoveredAt: new Date()
    };
  }

  getPatterns(): SecurityPattern[] {
    return [...this.patterns];
  }

  addPattern(pattern: SecurityPattern): void {
    this.patterns.push(pattern);
  }

  removePattern(patternId: string): void {
    this.patterns = this.patterns.filter(p => p.id !== patternId);
  }
}

// Individual Detector Implementations

class PromptInjectionDetector implements ViolationDetector {
  readonly category = 'LLM01';
  readonly severity = 'HIGH';

  async detect(content: string, context: ScanContext): Promise<SecurityViolation[]> {
    const violations: SecurityViolation[] = [];
    const patterns = OWASP_LLM_PATTERNS.filter(p => p.category === 'LLM01');
    
    for (const pattern of patterns) {
      const matches = content.matchAll(pattern.pattern);
      for (const match of matches) {
        const lines = content.split('\n');
        const lineNumber = lines.findIndex(line => line.includes(match[0])) + 1;
        
        violations.push({
          id: `violation_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          severity: pattern.severity,
          category: pattern.category,
          title: 'Prompt Injection Vulnerability',
          description: pattern.description,
          file: context.projectPath, // Would be actual file path
          line: lineNumber,
          codeSnippet: match[0],
          recommendation: pattern.recommendation,
          cweReference: pattern.cweReference,
          agentSource: context.agentSource,
          status: 'OPEN',
          discoveredAt: new Date()
        });
      }
    }
    
    return violations;
  }

  getPatterns(): SecurityPattern[] {
    return OWASP_LLM_PATTERNS.filter(p => p.category === 'LLM01');
  }

  generateFix(violation: SecurityViolation): string {
    return `// TODO: Implement input validation for prompt injection prevention
const sanitizedInput = validateAndSanitizeInput(userInput);
const prompt = \`System: You are a helpful assistant.\\nUser: \${sanitizedInput}\`;`;
  }
}

class InsecureOutputDetector implements ViolationDetector {
  readonly category = 'LLM02';
  readonly severity = 'MEDIUM';

  async detect(content: string, context: ScanContext): Promise<SecurityViolation[]> {
    const violations: SecurityViolation[] = [];
    const patterns = OWASP_LLM_PATTERNS.filter(p => p.category === 'LLM02');
    
    for (const pattern of patterns) {
      const matches = content.matchAll(pattern.pattern);
      for (const match of matches) {
        const lines = content.split('\n');
        const lineNumber = lines.findIndex(line => line.includes(match[0])) + 1;
        
        violations.push({
          id: `violation_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          severity: pattern.severity,
          category: pattern.category,
          title: 'Insecure Output Handling',
          description: pattern.description,
          file: context.projectPath,
          line: lineNumber,
          codeSnippet: match[0],
          recommendation: pattern.recommendation,
          cweReference: pattern.cweReference,
          agentSource: context.agentSource,
          status: 'OPEN',
          discoveredAt: new Date()
        });
      }
    }
    
    return violations;
  }

  getPatterns(): SecurityPattern[] {
    return OWASP_LLM_PATTERNS.filter(p => p.category === 'LLM02');
  }

  generateFix(violation: SecurityViolation): string {
    return `import DOMPurify from 'dompurify';
// Sanitize LLM output before rendering
const sanitizedOutput = DOMPurify.sanitize(llmResponse);
div.innerHTML = sanitizedOutput;`;
  }
}

class SensitiveInfoDetector implements ViolationDetector {
  readonly category = 'LLM06';
  readonly severity = 'CRITICAL';

  async detect(content: string, context: ScanContext): Promise<SecurityViolation[]> {
    const violations: SecurityViolation[] = [];
    const patterns = OWASP_LLM_PATTERNS.filter(p => p.category === 'LLM06');
    
    for (const pattern of patterns) {
      const matches = content.matchAll(pattern.pattern);
      for (const match of matches) {
        const lines = content.split('\n');
        const lineNumber = lines.findIndex(line => line.includes(match[0])) + 1;
        
        violations.push({
          id: `violation_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          severity: pattern.severity,
          category: pattern.category,
          title: 'Sensitive Information Disclosure',
          description: pattern.description,
          file: context.projectPath,
          line: lineNumber,
          codeSnippet: match[0],
          recommendation: pattern.recommendation,
          cweReference: pattern.cweReference,
          agentSource: context.agentSource,
          status: 'OPEN',
          discoveredAt: new Date()
        });
      }
    }
    
    return violations;
  }

  getPatterns(): SecurityPattern[] {
    return OWASP_LLM_PATTERNS.filter(p => p.category === 'LLM06');
  }

  generateFix(violation: SecurityViolation): string {
    return `// Move sensitive data to environment variables
const API_KEY = process.env.API_KEY;
// or use a secure configuration manager
const config = await secureConfigManager.getSecret('api-key');`;
  }
}

class CodingStandardsDetector implements ViolationDetector {
  readonly category = 'CODING_STANDARDS';
  readonly severity = 'MEDIUM';

  async detect(content: string, context: ScanContext): Promise<SecurityViolation[]> {
    const violations: SecurityViolation[] = [];
    const patterns = OWASP_LLM_PATTERNS.filter(p => p.category === 'CODING_STANDARDS');
    
    for (const pattern of patterns) {
      const matches = content.matchAll(pattern.pattern);
      for (const match of matches) {
        const lines = content.split('\n');
        const lineNumber = lines.findIndex(line => line.includes(match[0])) + 1;
        
        violations.push({
          id: `violation_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          severity: pattern.severity,
          category: pattern.category,
          title: 'Coding Standards Violation',
          description: pattern.description,
          file: context.projectPath,
          line: lineNumber,
          codeSnippet: match[0],
          recommendation: pattern.recommendation,
          cweReference: pattern.cweReference,
          agentSource: context.agentSource,
          status: 'OPEN',
          discoveredAt: new Date()
        });
      }
    }
    
    return violations;
  }

  getPatterns(): SecurityPattern[] {
    return OWASP_LLM_PATTERNS.filter(p => p.category === 'CODING_STANDARDS');
  }

  generateFix(violation: SecurityViolation): string {
    if (violation.codeSnippet.includes('console.log')) {
      return `// Remove sensitive data from logs
console.log('Processing request for user:', userId); // Safe
// console.log('User password:', password); // UNSAFE - remove this`;
    }
    
    if (violation.codeSnippet.includes('catch')) {
      return `catch (error) {
  // Add proper error handling
  logger.error('Operation failed', { error, context });
  throw new Error('Operation could not be completed');
}`;
    }
    
    return '// TODO: Fix coding standards violation';
  }
}

export default ScanEngine;
