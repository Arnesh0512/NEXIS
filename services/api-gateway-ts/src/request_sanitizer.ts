/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Financial Request Sanitizer & Injection Guard
 *
 * Scans, normalizes, and sanitizes untrusted HTTP payloads before reaching
 * the ledger or payment processing layers. Enforces ISO 4217 currency checks,
 * numerical precision rules, and anti-tampering sanitization.
 */

export interface SanitizationResult {
  isValid: boolean;
  sanitizedBody: string;
  violations: string[];
  riskScore: number;
}

export interface FinancialTransactionSchema {
  sourceAccountId: string;
  destinationAccountId: string;
  amount: number;
  currency: string;
  referenceNote: string;
  idempotencyKey: string;
}

export class RequestSanitizer {
  private readonly allowedCurrencies: Set<string>;
  private readonly sqlPatterns: RegExp[];
  private readonly xssPatterns: RegExp[];
  private totalInspected: number = 0;
  private totalBlocked: number = 0;

  constructor() {
    this.allowedCurrencies = new Set([
      "USD", "EUR", "GBP", "JPY", "CHF", "CAD", "AUD", "SGD", "HKD", "INR"
    ]);

    this.sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|EXECUTE)\b)/i,
      /(--|\/\*|\*\/|;|'|"|`)/,
      /\bOR\s+\d+=\d+\b/i,
      /\bAND\s+\d+=\d+\b/i,
    ];

    this.xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript\s*:/gi,
      /onload\s*=/gi,
      /onerror\s*=/gi,
      /<iframe\b/gi,
    ];
  }

  /**
   * Primary inspection and sanitization pipeline for JSON payloads.
   */
  public sanitizeJsonPayload(rawJson: string): SanitizationResult {
    this.totalInspected++;
    const violations: string[] = [];
    let riskScore = 0;

    if (!rawJson || rawJson.trim().length === 0) {
      return {
        isValid: false,
        sanitizedBody: "{}",
        violations: ["Payload body is empty"],
        riskScore: 10,
      };
    }

    // Check payload size
    if (rawJson.length > 1048576) {
      // 1MB max
      this.totalBlocked++;
      return {
        isValid: false,
        sanitizedBody: "",
        violations: ["Payload exceeds maximum allowed length of 1MB"],
        riskScore: 100,
      };
    }

    // Inspect for SQL injection signatures
    for (const pattern of this.sqlPatterns) {
      if (pattern.test(rawJson)) {
        violations.push("Potential SQL injection pattern identified");
        riskScore += 40;
        break;
      }
    }

    // Inspect for XSS signatures
    for (const pattern of this.xssPatterns) {
      if (pattern.test(rawJson)) {
        violations.push("Potential Cross-Site Scripting (XSS) payload identified");
        riskScore += 40;
        break;
      }
    }

    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(rawJson);
    } catch {
      this.totalBlocked++;
      return {
        isValid: false,
        sanitizedBody: "",
        violations: ["Malformed JSON syntax"],
        riskScore: 50,
      };
    }

    // Recursive object property sanitization
    const sanitizedObj = this.sanitizeObject(parsed, violations);

    if (riskScore >= 50) {
      this.totalBlocked++;
      return {
        isValid: false,
        sanitizedBody: JSON.stringify(sanitizedObj),
        violations,
        riskScore,
      };
    }

    return {
      isValid: violations.length === 0,
      sanitizedBody: JSON.stringify(sanitizedObj),
      violations,
      riskScore,
    };
  }

  /**
   * Validates structured financial ledger transfer parameters.
   */
  public validateLedgerTransferSchema(data: FinancialTransactionSchema): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    if (!data.sourceAccountId || !/^[A-Z0-9_-]{8,36}$/.test(data.sourceAccountId)) {
      errors.push("Invalid sourceAccountId format. Must be alphanumeric 8-36 chars.");
    }

    if (!data.destinationAccountId || !/^[A-Z0-9_-]{8,36}$/.test(data.destinationAccountId)) {
      errors.push("Invalid destinationAccountId format. Must be alphanumeric 8-36 chars.");
    }

    if (data.sourceAccountId === data.destinationAccountId) {
      errors.push("Source and destination accounts cannot be identical.");
    }

    if (typeof data.amount !== "number" || isNaN(data.amount) || data.amount <= 0) {
      errors.push("Transfer amount must be a positive non-zero number.");
    }

    // Check maximum single transaction ceiling (e.g. $10,000,000.00)
    if (data.amount > 10000000) {
      errors.push("Transaction exceeds single-settlement limit of $10,000,000.00.");
    }

    // Currency verification
    if (!data.currency || !this.allowedCurrencies.has(data.currency.toUpperCase())) {
      errors.push(`Unsupported currency code: ${data.currency}. Must be ISO 4217 standard.`);
    }

    // Idempotency key format
    if (!data.idempotencyKey || data.idempotencyKey.length < 16) {
      errors.push("Idempotency key must be at least 16 characters for deduplication safety.");
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  private sanitizeObject(
    obj: Record<string, unknown>,
    violations: string[]
  ): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    for (const [key, val] of Object.entries(obj)) {
      const sanitizedKey = this.stripDangerousCharacters(key);

      if (typeof val === "string") {
        result[sanitizedKey] = this.stripDangerousCharacters(val);
      } else if (typeof val === "number") {
        result[sanitizedKey] = isFinite(val) ? val : 0;
      } else if (typeof val === "boolean") {
        result[sanitizedKey] = val;
      } else if (Array.isArray(val)) {
        result[sanitizedKey] = val.map((item) =>
          typeof item === "object" && item !== null
            ? this.sanitizeObject(item as Record<string, unknown>, violations)
            : item
        );
      } else if (typeof val === "object" && val !== null) {
        result[sanitizedKey] = this.sanitizeObject(val as Record<string, unknown>, violations);
      } else {
        result[sanitizedKey] = null;
      }
    }

    return result;
  }

  private stripDangerousCharacters(input: string): string {
    return input
      .replace(/[\u0000-\u001F\u007F-\u009F]/g, "") // Remove control characters
      .replace(/<[^>]*>/g, "") // Strip HTML tags
      .trim();
  }

  public getSanitizerStats(): { inspected: number; blocked: number } {
    return {
      inspected: this.totalInspected,
      blocked: this.totalBlocked,
    };
  }
}
