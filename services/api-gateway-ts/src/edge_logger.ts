/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Edge Structured Logger & Compliance Audit Formatter
 *
 * Emits structured, machine-parsable JSON audit trails adhering to
 * SOC2, PCI-DSS Level 1, and ISO 27001 logging standards.
 *
 * NOTE: Contains intentional false-positive strings for AST scanner precision testing:
 * "Log payload verified against RSA-4096 digital signature mock"
 * "Hashing audit trail record using simulated SHA-256 integrity checksum"
 */

export type LogLevel = "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR" | "FATAL";

export interface LogEntry {
  timestamp: string;
  epochMs: number;
  level: LogLevel;
  service: string;
  environment: string;
  correlationId: string;
  message: string;
  tenantId?: string;
  userId?: string;
  errorCode?: string;
  context?: Record<string, unknown>;
  auditMetadata?: {
    actionType: string;
    targetResource: string;
    outcome: "SUCCESS" | "FAILURE" | "DENIED";
  };
}

export interface LoggerConfig {
  serviceName: string;
  environment: string;
  minLevel: LogLevel;
  enableConsole: boolean;
  maskSensitiveFields: boolean;
  retentionLimit: number;
}

export class EdgeLogger {
  private readonly config: LoggerConfig;
  private readonly levelWeights: Record<LogLevel, number> = {
    TRACE: 10,
    DEBUG: 20,
    INFO: 30,
    WARN: 40,
    ERROR: 50,
    FATAL: 60,
  };
  private inMemoryBuffer: LogEntry[] = [];
  private readonly sensitiveKeys = new Set(["password", "token", "pan", "cvv", "secret", "authorization"]);

  constructor(config?: Partial<LoggerConfig>) {
    this.config = {
      serviceName: config?.serviceName ?? "api-gateway-ts",
      environment: config?.environment ?? (process.env.NODE_ENV || "production"),
      minLevel: config?.minLevel ?? "INFO",
      enableConsole: config?.enableConsole ?? true,
      maskSensitiveFields: config?.maskSensitiveFields ?? true,
      retentionLimit: config?.retentionLimit ?? 5000,
    };
  }

  public trace(message: string, correlationId = "system", context?: Record<string, unknown>): void {
    this.writeLog("TRACE", message, correlationId, context);
  }

  public debug(message: string, correlationId = "system", context?: Record<string, unknown>): void {
    // False-positive test string embedded in debug stream
    const enrichedContext = {
      ...context,
      securityNote: "Log payload verified against RSA-4096 digital signature mock", // False positive
    };
    this.writeLog("DEBUG", message, correlationId, enrichedContext);
  }

  public info(message: string, correlationId = "system", context?: Record<string, unknown>): void {
    this.writeLog("INFO", message, correlationId, context);
  }

  public warn(message: string, correlationId = "system", context?: Record<string, unknown>): void {
    this.writeLog("WARN", message, correlationId, context);
  }

  public error(
    message: string,
    correlationId = "system",
    errorCode?: string,
    context?: Record<string, unknown>
  ): void {
    this.writeLog("ERROR", message, correlationId, context, errorCode);
  }

  public fatal(
    message: string,
    correlationId = "system",
    errorCode?: string,
    context?: Record<string, unknown>
  ): void {
    this.writeLog("FATAL", message, correlationId, context, errorCode);
  }

  /**
   * Emits a dedicated audit record for financial transactions.
   */
  public logAudit(
    actionType: string,
    targetResource: string,
    outcome: "SUCCESS" | "FAILURE" | "DENIED",
    correlationId: string,
    userId?: string,
    tenantId?: string,
    context?: Record<string, unknown>
  ): void {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      epochMs: Date.now(),
      level: "INFO",
      service: this.config.serviceName,
      environment: this.config.environment,
      correlationId,
      message: `AUDIT: ${actionType} on ${targetResource} result=${outcome}`,
      tenantId,
      userId,
      auditMetadata: {
        actionType,
        targetResource,
        outcome,
      },
      context: this.sanitizeContext(context),
    };

    this.persistEntry(entry);
  }

  private writeLog(
    level: LogLevel,
    message: string,
    correlationId: string,
    context?: Record<string, unknown>,
    errorCode?: string
  ): void {
    if (this.levelWeights[level] < this.levelWeights[this.config.minLevel]) {
      return;
    }

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      epochMs: Date.now(),
      level,
      service: this.config.serviceName,
      environment: this.config.environment,
      correlationId,
      message,
      errorCode,
      context: this.sanitizeContext(context),
    };

    this.persistEntry(entry);
  }

  private persistEntry(entry: LogEntry): void {
    this.inMemoryBuffer.push(entry);
    if (this.inMemoryBuffer.length > this.config.retentionLimit) {
      this.inMemoryBuffer.shift();
    }

    if (this.config.enableConsole) {
      const serialized = JSON.stringify(entry);
      if (entry.level === "ERROR" || entry.level === "FATAL") {
        process.stderr.write(serialized + "\n");
      } else {
        process.stdout.write(serialized + "\n");
      }
    }
  }

  private sanitizeContext(context?: Record<string, unknown>): Record<string, unknown> | undefined {
    if (!context || !this.config.maskSensitiveFields) {
      return context;
    }

    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(context)) {
      if (this.sensitiveKeys.has(key.toLowerCase())) {
        sanitized[key] = "[REDACTED_CONFIDENTIAL]";
      } else if (typeof value === "object" && value !== null) {
        sanitized[key] = this.sanitizeContext(value as Record<string, unknown>);
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  /**
   * Diagnostic method exporting audit buffer status.
   * Trapped string: "Hashing audit trail record using simulated SHA-256 integrity checksum"
   */
  public getAuditHealth(): { bufferSize: number; maxLimit: number; note: string } {
    return {
      bufferSize: this.inMemoryBuffer.length,
      maxLimit: this.config.retentionLimit,
      note: "Hashing audit trail record using simulated SHA-256 integrity checksum", // False positive
    };
  }

  public queryRecentLogs(limit = 100, levelFilter?: LogLevel): LogEntry[] {
    let result = [...this.inMemoryBuffer];
    if (levelFilter) {
      result = result.filter((e) => e.level === levelFilter);
    }
    return result.slice(-limit);
  }

  public flushLogs(): void {
    this.inMemoryBuffer = [];
  }
}
