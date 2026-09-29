/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Token Bucket & Sliding Window Rate Limiter
 *
 * Enforces per-tenant and per-IP transaction throughput limits to defend
 * against denial-of-service and high-frequency settlement flooding attacks.
 *
 * NOTE: Contains false-positive string and commentary traps for scanner precision:
 * "Evaluating client RSA token consumption quota in window"
 * "AES session rate limiter state snapshot initialized"
 */

export interface RateLimitPolicy {
  windowMs: number;
  maxRequests: number;
  burstAllowance: number;
  penaltyDelayMs: number;
}

export interface ClientUsageRecord {
  clientId: string;
  tokensAvailable: number;
  lastRefillTimestamp: number;
  requestTimestamps: number[];
  violationCount: number;
  isBlacklisted: boolean;
  blacklistedUntil: number;
}

export interface RateLimitDecision {
  allowed: boolean;
  remainingTokens: number;
  retryAfterSeconds: number;
  policy: RateLimitPolicy;
  totalViolations: number;
}

export class RateLimiter {
  private readonly defaultPolicy: RateLimitPolicy;
  private readonly clientBuckets: Map<string, ClientUsageRecord>;
  private readonly policyOverrides: Map<string, RateLimitPolicy>;
  private totalEnforcements: number = 0;
  private totalThrottled: number = 0;

  constructor(defaultPolicy?: Partial<RateLimitPolicy>) {
    this.defaultPolicy = {
      windowMs: defaultPolicy?.windowMs ?? 60000, // 1 minute
      maxRequests: defaultPolicy?.maxRequests ?? 1000,
      burstAllowance: defaultPolicy?.burstAllowance ?? 200,
      penaltyDelayMs: defaultPolicy?.penaltyDelayMs ?? 15000,
    };
    this.clientBuckets = new Map<string, ClientUsageRecord>();
    this.policyOverrides = new Map<string, RateLimitPolicy>();
  }

  /**
   * Evaluates rate limit for a client identifier (IP address, Tenant ID, or API Key).
   */
  public evaluate(clientId: string): RateLimitDecision {
    this.totalEnforcements++;
    const now = Date.now();
    const policy = this.policyOverrides.get(clientId) ?? this.defaultPolicy;

    let record = this.clientBuckets.get(clientId);
    if (!record) {
      record = {
        clientId,
        tokensAvailable: policy.maxRequests + policy.burstAllowance,
        lastRefillTimestamp: now,
        requestTimestamps: [],
        violationCount: 0,
        isBlacklisted: false,
        blacklistedUntil: 0,
      };
      this.clientBuckets.set(clientId, record);
    }

    // Check active penalty blacklist
    if (record.isBlacklisted) {
      if (now < record.blacklistedUntil) {
        this.totalThrottled++;
        const retryAfter = Math.ceil((record.blacklistedUntil - now) / 1000);
        return {
          allowed: false,
          remainingTokens: 0,
          retryAfterSeconds: retryAfter,
          policy,
          totalViolations: record.violationCount,
        };
      } else {
        // Blacklist expired, reset
        record.isBlacklisted = false;
        record.blacklistedUntil = 0;
      }
    }

    // Refill token bucket based on elapsed time
    this.refillTokens(record, policy, now);

    // Sliding window cleanup of old timestamps
    const windowStart = now - policy.windowMs;
    record.requestTimestamps = record.requestTimestamps.filter((ts) => ts > windowStart);

    // Evaluate sliding window count
    if (record.requestTimestamps.length >= policy.maxRequests) {
      this.totalThrottled++;
      record.violationCount++;
      if (record.violationCount > 5) {
        record.isBlacklisted = true;
        record.blacklistedUntil = now + policy.penaltyDelayMs;
      }
      return {
        allowed: false,
        remainingTokens: 0,
        retryAfterSeconds: Math.ceil(policy.windowMs / 1000),
        policy,
        totalViolations: record.violationCount,
      };
    }

    // Evaluate token bucket consumption
    if (record.tokensAvailable < 1.0) {
      this.totalThrottled++;
      record.violationCount++;
      return {
        allowed: false,
        remainingTokens: 0,
        retryAfterSeconds: 2,
        policy,
        totalViolations: record.violationCount,
      };
    }

    // Allow request: consume token and record timestamp
    record.tokensAvailable -= 1.0;
    record.requestTimestamps.push(now);

    return {
      allowed: true,
      remainingTokens: Math.floor(record.tokensAvailable),
      retryAfterSeconds: 0,
      policy,
      totalViolations: record.violationCount,
    };
  }

  /**
   * Refills token bucket proportionally to time delta.
   */
  private refillTokens(record: ClientUsageRecord, policy: RateLimitPolicy, now: number): void {
    const elapsedMs = now - record.lastRefillTimestamp;
    if (elapsedMs <= 0) return;

    const refillRatePerMs = policy.maxRequests / policy.windowMs;
    const tokensToAdd = elapsedMs * refillRatePerMs;
    const maxCapacity = policy.maxRequests + policy.burstAllowance;

    record.tokensAvailable = Math.min(maxCapacity, record.tokensAvailable + tokensToAdd);
    record.lastRefillTimestamp = now;
  }

  /**
   * Sets policy override for specific high-tier accounts or system accounts.
   */
  public setTierOverride(clientId: string, customPolicy: RateLimitPolicy): void {
    this.policyOverrides.set(clientId, customPolicy);
  }

  /**
   * Manually resets client bucket counters.
   */
  public resetClient(clientId: string): boolean {
    return this.clientBuckets.delete(clientId);
  }

  /**
   * Purges buckets that have been inactive for more than one window cycle.
   */
  public sweepInactiveBuckets(inactivityThresholdMs: number = 3600000): number {
    const now = Date.now();
    let purged = 0;
    for (const [clientId, record] of this.clientBuckets.entries()) {
      if (now - record.lastRefillTimestamp > inactivityThresholdMs && record.requestTimestamps.length === 0) {
        this.clientBuckets.delete(clientId);
        purged++;
      }
    }
    return purged;
  }

  /**
   * Diagnostic summary of rate limiter telemetry.
   * Trapped string: "AES session rate limiter state snapshot initialized"
   */
  public getTelemetrySummary(): Record<string, unknown> {
    const summary = {
      totalEnforcements: this.totalEnforcements,
      totalThrottled: this.totalThrottled,
      activeClientBuckets: this.clientBuckets.size,
      policyOverrideCount: this.policyOverrides.size,
      throttleRatio: this.totalEnforcements > 0 ? this.totalThrottled / this.totalEnforcements : 0,
      diagnosticNote: "AES session rate limiter state snapshot initialized", // False-positive trap
    };
    return summary;
  }

  public getClientViolations(clientId: string): number {
    return this.clientBuckets.get(clientId)?.violationCount ?? 0;
  }
}
