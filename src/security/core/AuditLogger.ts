import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { SecurityViolation, SecurityOverride } from '../types/SecurityViolation';

export interface AuditEvent {
  id: string;
  timestamp: Date;
  eventType: 'SCAN_START' | 'VIOLATION_FOUND' | 'OVERRIDE' | 'PHASE_TRANSITION' | 'SCAN_COMPLETE';
  developerId: string;
  agentSource?: string;
  data: Record<string, any>;
  digitalSignature: string;
  checksum: string;
}

export interface AuditLoggerConfig {
  logPath: string;
  encryptionKey: string;
  writeOnce: boolean;
  maxLogSize: number; // in MB
  backupCount: number;
}

class AuditLogger {
  private readonly config: AuditLoggerConfig;
  private readonly logFile: string;
  private readonly signatureKey: string;
  private isInitialized: boolean = false;

  constructor(config?: Partial<AuditLoggerConfig>) {
    this.config = {
      logPath: process.env.AUDIT_LOG_PATH || './logs',
      encryptionKey: process.env.AUDIT_ENCRYPTION_KEY || this.generateEncryptionKey(),
      writeOnce: true,
      maxLogSize: 100, // 100MB
      backupCount: 5,
      ...config
    };
    
    this.logFile = path.join(this.config.logPath, 'security-audit.log');
    this.signatureKey = process.env.AUDIT_SIGNATURE_KEY || this.generateSignatureKey();
  }

  private generateEncryptionKey(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private generateSignatureKey(): string {
    return crypto.randomBytes(64).toString('hex');
  }

  private async initializeImmutableLog(): Promise<void> {
    if (this.isInitialized) return;

    try {
      await fs.mkdir(this.config.logPath, { recursive: true });
      
      // Check if log file exists, if not create with immutable header
      try {
        await fs.access(this.logFile);
      } catch {
        const header = this.createImmutableHeader();
        await fs.writeFile(this.logFile, header, { flag: 'w' });
      }

      this.isInitialized = true;
    } catch (error) {
      throw new Error(`Failed to initialize audit log: ${error}`);
    }
  }

  private createImmutableHeader(): string {
    const header = {
      version: '1.0',
      created: new Date().toISOString(),
      signatureKey: this.signatureKey,
      encryptionKey: this.config.encryptionKey,
      immutable: true
    };
    
    return `# IMMUTABLE AUDIT LOG - DO NOT MODIFY\n${JSON.stringify(header, null, 2)}\n---\n`;
  }

  private generateDigitalSignature(event: AuditEvent): string {
    const eventString = JSON.stringify(event, null, 2);
    return crypto.sign('sha256', Buffer.from(eventString), this.signatureKey).toString('base64');
  }

  private calculateChecksum(event: AuditEvent): string {
    const eventString = JSON.stringify(event);
    return crypto.createHash('sha256').update(eventString).digest('hex');
  }

  private encryptEvent(event: AuditEvent): string {
    const eventString = JSON.stringify(event);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-cbc', this.config.encryptionKey);
    
    let encrypted = cipher.update(eventString, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return `${iv.toString('hex')}:${encrypted}`;
  }

  private async writeEvent(event: AuditEvent): Promise<void> {
    await this.initializeImmutableLog();
    
    if (this.config.writeOnce) {
      // Verify log integrity before writing
      const isIntact = await this.verifyAuditIntegrity();
      if (!isIntact) {
        throw new Error('Audit log integrity compromised - write operation blocked');
      }
    }

    const encryptedEvent = this.encryptEvent(event);
    const logEntry = `${event.timestamp.toISOString()} [${event.eventType}] ${encryptedEvent}\n`;
    
    // Check log size and rotate if necessary
    await this.rotateLogIfNeeded();
    
    // Append to log file (append-only mode)
    await fs.appendFile(this.logFile, logEntry, { flag: 'a' });
  }

  private async rotateLogIfNeeded(): Promise<void> {
    try {
      const stats = await fs.stat(this.logFile);
      const sizeInMB = stats.size / (1024 * 1024);
      
      if (sizeInMB > this.config.maxLogSize) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupFile = path.join(this.config.logPath, `security-audit-${timestamp}.log`);
        
        await fs.rename(this.logFile, backupFile);
        
        // Create new log with fresh header
        const header = this.createImmutableHeader();
        await fs.writeFile(this.logFile, header, { flag: 'w' });
        
        // Clean up old backups
        await this.cleanupOldBackups();
      }
    } catch (error) {
      console.warn('Log rotation failed:', error);
    }
  }

  private async cleanupOldBackups(): Promise<void> {
    try {
      const files = await fs.readdir(this.config.logPath);
      const logFiles = files
        .filter(file => file.startsWith('security-audit-') && file.endsWith('.log'))
        .map(file => ({
          name: file,
          path: path.join(this.config.logPath, file)
        }))
        .sort((a, b) => b.name.localeCompare(a.name)); // Sort by name (timestamp)

      // Keep only the most recent backups
      if (logFiles.length > this.config.backupCount) {
        const filesToDelete = logFiles.slice(this.config.backupCount);
        for (const file of filesToDelete) {
          await fs.unlink(file.path);
        }
      }
    } catch (error) {
      console.warn('Backup cleanup failed:', error);
    }
  }

  // Public API Methods

  async logScanStart(developerId: string, projectPath: string, agentSource?: string): Promise<void> {
    const event: AuditEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      eventType: 'SCAN_START',
      developerId,
      agentSource,
      data: { projectPath },
      digitalSignature: '', // Will be set below
      checksum: ''
    };

    event.digitalSignature = this.generateDigitalSignature(event);
    event.checksum = this.calculateChecksum(event);
    
    await this.writeEvent(event);
  }

  async logViolation(violation: SecurityViolation, agentSource?: string): Promise<void> {
    const event: AuditEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      eventType: 'VIOLATION_FOUND',
      developerId: 'system', // Violations can be found by automated scans
      agentSource,
      data: { violation },
      digitalSignature: '',
      checksum: ''
    };

    event.digitalSignature = this.generateDigitalSignature(event);
    event.checksum = this.calculateChecksum(event);
    
    await this.writeEvent(event);
  }

  async logOverride(override: SecurityOverride, developerId: string): Promise<void> {
    const event: AuditEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      eventType: 'OVERRIDE',
      developerId,
      data: { override },
      digitalSignature: '',
      checksum: ''
    };

    event.digitalSignature = this.generateDigitalSignature(event);
    event.checksum = this.calculateChecksum(event);
    
    await this.writeEvent(event);
  }

  async logPhaseTransition(fromPhase: string, toPhase: string, developerId: string, violations: SecurityViolation[]): Promise<void> {
    const event: AuditEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      eventType: 'PHASE_TRANSITION',
      developerId,
      data: { fromPhase, toPhase, violationCount: violations.length, violations },
      digitalSignature: '',
      checksum: ''
    };

    event.digitalSignature = this.generateDigitalSignature(event);
    event.checksum = this.calculateChecksum(event);
    
    await this.writeEvent(event);
  }

  async logScanComplete(developerId: string, violationCount: number, scanDuration: number): Promise<void> {
    const event: AuditEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      eventType: 'SCAN_COMPLETE',
      developerId,
      data: { violationCount, scanDuration },
      digitalSignature: '',
      checksum: ''
    };

    event.digitalSignature = this.generateDigitalSignature(event);
    event.checksum = this.calculateChecksum(event);
    
    await this.writeEvent(event);
  }

  // Read-only access methods (agents cannot modify)

  async getAuditHistory(limit?: number): Promise<AuditEvent[]> {
    await this.initializeImmutableLog();
    
    try {
      const content = await fs.readFile(this.logFile, 'utf8');
      const lines = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));
      
      const events: AuditEvent[] = [];
      
      for (const line of lines) {
        try {
          const match = line.match(/\[([^\]]+)\] (.+)$/);
          if (match) {
            const [, eventType, encryptedData] = match;
            const decryptedEvent = this.decryptEvent(encryptedData);
            if (this.verifyEventSignature(decryptedEvent)) {
              events.push(decryptedEvent);
            }
          }
        } catch (error) {
          console.warn('Failed to parse audit log entry:', error);
        }
      }
      
      return limit ? events.slice(-limit) : events;
    } catch (error) {
      console.error('Failed to read audit history:', error);
      return [];
    }
  }

  private decryptEvent(encryptedData: string): AuditEvent {
    const [ivHex, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipher('aes-256-cbc', this.config.encryptionKey);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted) as AuditEvent;
  }

  private verifyEventSignature(event: AuditEvent): boolean {
    try {
      const eventString = JSON.stringify(event, null, 2);
      const expectedSignature = crypto.sign('sha256', Buffer.from(eventString), this.signatureKey).toString('base64');
      return event.digitalSignature === expectedSignature;
    } catch {
      return false;
    }
  }

  async verifyAuditIntegrity(): Promise<boolean> {
    try {
      const events = await this.getAuditHistory();
      
      for (const event of events) {
        if (!this.verifyEventSignature(event)) {
          return false;
        }
        
        // Verify checksum
        const expectedChecksum = this.calculateChecksum(event);
        if (event.checksum !== expectedChecksum) {
          return false;
        }
      }
      
      return true;
    } catch (error) {
      console.error('Audit integrity verification failed:', error);
      return false;
    }
  }

  async getAuditStats(): Promise<{
    totalEvents: number;
    eventsByType: Record<string, number>;
    lastScan: Date | null;
    violationCount: number;
    overrideCount: number;
  }> {
    const events = await this.getAuditHistory();
    
    const stats = {
      totalEvents: events.length,
      eventsByType: {} as Record<string, number>,
      lastScan: null as Date | null,
      violationCount: 0,
      overrideCount: 0
    };

    for (const event of events) {
      stats.eventsByType[event.eventType] = (stats.eventsByType[event.eventType] || 0) + 1;
      
      if (event.eventType === 'SCAN_COMPLETE') {
        stats.lastScan = event.timestamp;
      } else if (event.eventType === 'VIOLATION_FOUND') {
        stats.violationCount++;
      } else if (event.eventType === 'OVERRIDE') {
        stats.overrideCount++;
      }
    }

    return stats;
  }
}

// Singleton instance for application-wide use
let auditLoggerInstance: AuditLogger | null = null;

export function getAuditLogger(config?: Partial<AuditLoggerConfig>): AuditLogger {
  if (!auditLoggerInstance) {
    auditLoggerInstance = new AuditLogger(config);
  }
  return auditLoggerInstance;
}

export default AuditLogger;
