// Security Violation Data Structure
export interface SecurityViolation {
  id: string;                    // Unique violation identifier
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;              // OWASP LLM category or Agent OS standard
  title: string;                 // Human-readable violation title
  description: string;           // Detailed explanation
  file: string;                  // File path where violation found
  line: number;                  // Line number of violation
  codeSnippet: string;           // Contextual code snippet
  recommendation: string;         // Fix recommendation
  cweReference?: string;         // CWE/CAPEC reference
  agentSource?: string;           // Which agent introduced this
  status: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'FALSE_POSITIVE';
  discoveredAt: Date;            // When violation was first detected
  resolvedAt?: Date;              // When violation was resolved
  override?: SecurityOverride;    // Override information if applicable
}

// Security Override Data Structure
export interface SecurityOverride {
  id: string;
  violationId: string;
  justification: {
    businessReason: string;
    mitigationPlan: string;
    riskAcceptance: string;
    expectedResolution: Date;
  };
  developerId: string;
  digitalSignature: string;       // Cryptographic signature
  approvedAt: Date;
  auditLogEntry: string;         // Reference to audit log entry
}

// Security Justification Form Data
export interface SecurityJustification {
  businessReason: string;
  mitigationPlan: string;
  riskAcceptance: string;
  expectedResolution: Date;
}

// Validation Result
export interface ValidationResult {
  passed: boolean;
  violations: SecurityViolation[];
  scanDuration: number;
  canProceed: boolean;
  requiresOverride: boolean;
}

// Checkpoint Result
export interface CheckpointResult {
  action: 'PROCEED' | 'FIX_VIOLATIONS' | 'OVERRIDE';
  violations: SecurityViolation[];
  overrides?: SecurityOverride[];
}

// Phase Types
export type Phase = 'WINDSURF' | 'ANTI_GRAVITY' | 'VS_CODE';

// Scan Scope
export type ScanScope = 'DELTA' | 'FULL';

// Scan Context
export interface ScanContext {
  projectPath: string;
  phase: Phase;
  developerId: string;
  modifiedFiles: string[];
  agentSource?: string;
}

// Project Context
export interface ProjectContext {
  name: string;
  path: string;
  currentPhase: Phase;
  developerId: string;
  lastScan?: Date;
  securityScore: number;
}

// Terminal UI Props
export interface TerminalModalProps {
  violations: SecurityViolation[];
  scanProgress: number;
  isScanning: boolean;
  onFixViolation: (violationId: string) => void;
  onRequestOverride: (violationId: string, justification: SecurityJustification) => void;
  onProceed: () => void;
  onCancel: () => void;
}

export interface ViolationListProps {
  violations: SecurityViolation[];
  streaming: boolean;
  onViolationClick: (violation: SecurityViolation) => void;
  selectedViolation?: SecurityViolation;
}

export interface ProgressBarProps {
  progress: number;
  isScanning: boolean;
  totalFiles: number;
  scannedFiles: number;
}

export interface OverrideFormProps {
  violation: SecurityViolation;
  onSubmit: (justification: SecurityJustification) => void;
  onCancel: () => void;
}
