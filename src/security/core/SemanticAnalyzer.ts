import { SecurityViolation, ScanContext } from '../types/SecurityViolation';
import * as ts from 'typescript';  // TypeScript Compiler API

export interface TaintedData {
  source: DataSource;
  variable: string;
  taintPath: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  dataType: 'SECRET' | 'PERSONAL_DATA' | 'CONFIG' | 'USER_INPUT';
}

export interface DataSource {
  type: 'ENVIRONMENT' | 'DATABASE' | 'FILE' | 'USER_INPUT' | 'HARDCODED';
  name: string;
  line: number;
  sensitivity: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface DataSink {
  type: 'CONSOLE' | 'API_RESPONSE' | 'LOG_FILE' | 'EXTERNAL_API' | 'DATABASE_WRITE';
  line: number;
  context: string;
}

export interface SemanticViolation extends SecurityViolation {
  taintFlow?: TaintedData[];
  sink?: DataSink;
  semanticType: 'TAINTED_DATA_FLOW' | 'BUSINESS_LOGIC_RISK' | 'DATA_EXPOSURE';
}

export class SemanticAnalyzer {
  private sources: Map<string, DataSource> = new Map();
  private sinks: Map<string, DataSink> = new Map();
  private variableFlows: Map<string, string[]> = new Map();

  async analyzeCode(content: string, context: ScanContext): Promise<SemanticViolation[]> {
    const violations: SemanticViolation[] = [];
    
    // Parse TypeScript/JavaScript code into AST
    const sourceFile = ts.createSourceFile(
      'temp.ts',
      content,
      ts.ScriptTarget.Latest,
      true
    );

    // 1. Identify data sources (where sensitive data comes from)
    this.identifyDataSources(sourceFile, content);
    
    // 2. Identify data sinks (where sensitive data goes)
    this.identifyDataSinks(sourceFile, content);
    
    // 3. Track variable assignments and data flow
    this.trackDataFlow(sourceFile);
    
    // 4. Find tainted data flows (source → sink)
    const taintFlows = this.findTaintedDataFlows();
    
    // 5. Create violations for each tainted flow
    for (const flow of taintFlows) {
      violations.push(this.createTaintViolation(flow, context));
    }

    return violations;
  }

  private identifyDataSources(sourceFile: ts.SourceFile, content: string): void {
    const visit = (node: ts.Node) => {
      // Environment variables
      if (ts.isCallExpression(node) && 
          node.expression.getText().includes('process.env')) {
        const envVar = this.extractEnvironmentVariable(node);
        this.sources.set(envVar.variable, {
          type: 'ENVIRONMENT',
          name: envVar.variable,
          line: envVar.line,
          sensitivity: this.determineSensitivity(envVar.variable)
        });
      }

      // Database connections
      if (ts.isCallExpression(node) && 
          (node.expression.getText().includes('createConnection') ||
           node.expression.getText().includes('connect'))) {
        this.sources.set(`db_config_${node.getStart()}`, {
          type: 'DATABASE',
          name: 'database_config',
          line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1,
          sensitivity: 'HIGH'
        });
      }

      // Hardcoded secrets (even if renamed)
      if (ts.isVariableDeclaration(node) && this.looksLikeSecret(node)) {
        const varName = node.name?.getText() || 'unknown';
        this.sources.set(varName, {
          type: 'HARDCODED',
          name: varName,
          line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1,
          sensitivity: 'HIGH'
        });
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
  }

  private identifyDataSinks(sourceFile: ts.SourceFile, content: string): void {
    const visit = (node: ts.Node) => {
      // Console logging
      if (ts.isCallExpression(node) && 
          node.expression.getText().includes('console.')) {
        this.sinks.set(`console_${node.getStart()}`, {
          type: 'CONSOLE',
          line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1,
          context: node.getText()
        });
      }

      // API responses
      if (ts.isCallExpression(node) && 
          (node.expression.getText().includes('res.send') ||
           node.expression.getText().includes('res.json') ||
           node.expression.getText().includes('return'))) {
        this.sinks.set(`api_${node.getStart()}`, {
          type: 'API_RESPONSE',
          line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1,
          context: node.getText()
        });
      }

      // External API calls
      if (ts.isCallExpression(node) && 
          (node.expression.getText().includes('fetch') ||
           node.expression.getText().includes('axios'))) {
        this.sinks.set(`external_${node.getStart()}`, {
          type: 'EXTERNAL_API',
          line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1,
          context: node.getText()
        });
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
  }

  private trackDataFlow(sourceFile: ts.SourceFile): void {
    const visit = (node: ts.Node) => {
      // Track variable assignments
      if (ts.isVariableDeclaration(node)) {
        const varName = node.name?.getText();
        if (varName && node.initializer) {
          const flow = this.extractVariableFlow(node.initializer);
          this.variableFlows.set(varName, flow);
        }
      }

      // Track reassignments
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const varName = node.left?.getText();
        if (varName && node.right) {
          const flow = this.extractVariableFlow(node.right);
          this.variableFlows.set(varName, flow);
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
  }

  private findTaintedDataFlows(): TaintedData[] {
    const taintFlows: TaintedData[] = [];

    for (const [sinkKey, sink] of this.sinks) {
      for (const [sourceKey, source] of this.sources) {
        // Check if there's a flow path from source to sink
        const flowPath = this.findFlowPath(source.name, sink.context);
        if (flowPath.length > 0) {
          taintFlows.push({
            source,
            variable: source.name,
            taintPath: flowPath,
            severity: this.calculateTaintSeverity(source, sink),
            dataType: this.determineDataType(source)
          });
        }
      }
    }

    return taintFlows;
  }

  private findFlowPath(sourceName: string, sinkContext: string): string[] {
    const path: string[] = [];
    
    // Simple flow detection - check if source variable appears in sink context
    if (sinkContext.includes(sourceName)) {
      path.push(sourceName);
      path.push('direct_flow_to_sink');
    }

    // Check for variable assignments
    for (const [varName, flow] of this.variableFlows) {
      if (flow.includes(sourceName) && sinkContext.includes(varName)) {
        path.push(sourceName);
        path.push(`assigned_to_${varName}`);
        path.push('flow_to_sink');
      }
    }

    return path;
  }

  private createTaintViolation(taintFlow: TaintedData, context: ScanContext): SemanticViolation {
    return {
      id: `semantic_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      severity: taintFlow.severity,
      category: 'SEMANTIC_TAINT',
      title: 'Tainted Data Flow Detected',
      description: `Sensitive data from ${taintFlow.source.type.toLowerCase()} source flows to ${taintFlow.sink?.type.toLowerCase()} sink`,
      file: context.projectPath,
      line: taintFlow.source.line,
      codeSnippet: `${taintFlow.source.name} → ${taintFlow.taintPath.join(' → ')}`,
      recommendation: 'Sanitize or remove sensitive data from this flow',
      cweReference: 'CWE-20',
      agentSource: context.agentSource,
      status: 'OPEN',
      discoveredAt: new Date(),
      taintFlow: [taintFlow],
      sink: taintFlow.sink,
      semanticType: 'TAINTED_DATA_FLOW'
    };
  }

  // Helper methods
  private extractEnvironmentVariable(node: ts.CallExpression): { variable: string; line: number } {
    const text = node.getText();
    const match = text.match(/process\.env\.(\w+)/);
    return {
      variable: match ? match[1] : 'unknown',
      line: 0 // Will be set by caller
    };
  }

  private looksLikeSecret(node: ts.VariableDeclaration): boolean {
    const varName = node.name?.getText() || '';
    const initializer = node.initializer?.getText() || '';
    
    // Check if it looks like a secret value
    const secretPatterns = [
      /^[a-zA-Z0-9_-]{20,}$/,  // Long alphanumeric strings
      /^sk-/,                   // OpenAI keys
      /^ghp_/,                  // GitHub tokens
      /^AIza/,                  // Google keys
      /^[a-f0-9]{32,}$/i        // Hex strings (hashes, keys)
    ];

    return secretPatterns.some(pattern => pattern.test(initializer));
  }

  private extractVariableFlow(node: ts.Node): string[] {
    const flow: string[] = [];
    
    const visit = (child: ts.Node) => {
      if (ts.isIdentifier(child)) {
        flow.push(child.getText());
      }
      ts.forEachChild(child, visit);
    };

    visit(node);
    return flow;
  }

  private determineSensitivity(variableName: string): 'HIGH' | 'MEDIUM' | 'LOW' {
    const highSensitivity = ['password', 'secret', 'key', 'token', 'api'];
    const mediumSensitivity = ['config', 'database', 'db'];
    
    const lowerVarName = variableName.toLowerCase();
    
    if (highSensitivity.some(pattern => lowerVarName.includes(pattern))) {
      return 'HIGH';
    }
    
    if (mediumSensitivity.some(pattern => lowerVarName.includes(pattern))) {
      return 'MEDIUM';
    }
    
    return 'LOW';
  }

  private calculateTaintSeverity(source: DataSource, sink?: DataSink): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    if (source.sensitivity === 'HIGH' && sink?.type === 'CONSOLE') {
      return 'CRITICAL';
    }
    
    if (source.sensitivity === 'HIGH' && sink?.type === 'API_RESPONSE') {
      return 'CRITICAL';
    }
    
    if (source.sensitivity === 'HIGH') {
      return 'HIGH';
    }
    
    if (source.sensitivity === 'MEDIUM') {
      return 'MEDIUM';
    }
    
    return 'LOW';
  }

  private determineDataType(source: DataSource): 'SECRET' | 'PERSONAL_DATA' | 'CONFIG' | 'USER_INPUT' {
    if (source.type === 'ENVIRONMENT' || source.type === 'HARDCODED') {
      return 'SECRET';
    }
    
    if (source.type === 'DATABASE') {
      return 'PERSONAL_DATA';
    }
    
    if (source.type === 'USER_INPUT') {
      return 'USER_INPUT';
    }
    
    return 'CONFIG';
  }
}
