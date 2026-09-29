/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Downstream Circuit Breaker & Resiliency Controller
 *
 * Prevents cascading distributed system failure when downstream payment
 * processing nodes, ledger writers, or HSM token stores experience latency
 * degradation or network partitioning.
 */

export type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

export interface CircuitBreakerOptions {
  failureThreshold: number;
  successThreshold: number;
  openTimeoutMs: number;
  halfOpenMaxCalls: number;
  rollingWindowMs: number;
}

export interface CircuitTelemetry {
  serviceName: string;
  state: CircuitState;
  failureCount: number;
  consecutiveSuccesses: number;
  lastStateChange: number;
  totalCalls: number;
  totalRejected: number;
}

export class CircuitBreaker {
  private readonly serviceName: string;
  private readonly options: CircuitBreakerOptions;
  private state: CircuitState = "CLOSED";
  private failureTimestamps: number[] = [];
  private consecutiveSuccesses: number = 0;
  private lastStateChange: number = Date.now();
  private halfOpenCallsActive: number = 0;
  private totalCallsCount: number = 0;
  private totalRejectedCount: number = 0;

  constructor(serviceName: string, customOptions?: Partial<CircuitBreakerOptions>) {
    this.serviceName = serviceName;
    this.options = {
      failureThreshold: customOptions?.failureThreshold ?? 5,
      successThreshold: customOptions?.successThreshold ?? 3,
      openTimeoutMs: customOptions?.openTimeoutMs ?? 30000, // 30s
      halfOpenMaxCalls: customOptions?.halfOpenMaxCalls ?? 2,
      rollingWindowMs: customOptions?.rollingWindowMs ?? 60000, // 1m
    };
  }

  /**
   * Pre-execution check determining whether an outbound call may proceed.
   */
  public canExecute(): boolean {
    this.totalCallsCount++;
    const now = Date.now();

    if (this.state === "OPEN") {
      // Check if open timeout has elapsed
      if (now - this.lastStateChange >= this.options.openTimeoutMs) {
        this.transitionTo("HALF_OPEN");
        this.halfOpenCallsActive = 1;
        return true;
      }
      this.totalRejectedCount++;
      return false;
    }

    if (this.state === "HALF_OPEN") {
      if (this.halfOpenCallsActive < this.options.halfOpenMaxCalls) {
        this.halfOpenCallsActive++;
        return true;
      }
      this.totalRejectedCount++;
      return false;
    }

    // CLOSED state: execution allowed
    return true;
  }

  /**
   * Records successful response execution from downstream.
   */
  public recordSuccess(): void {
    const now = Date.now();
    this.cleanRollingFailures(now);

    if (this.state === "HALF_OPEN") {
      this.consecutiveSuccesses++;
      if (this.consecutiveSuccesses >= this.options.successThreshold) {
        this.transitionTo("CLOSED");
      }
    } else if (this.state === "CLOSED") {
      this.consecutiveSuccesses++;
    }
  }

  /**
   * Records failure response or execution timeout.
   */
  public recordFailure(): void {
    const now = Date.now();
    this.consecutiveSuccesses = 0;
    this.failureTimestamps.push(now);
    this.cleanRollingFailures(now);

    if (this.state === "HALF_OPEN") {
      // Any failure during trial immediately flips back to OPEN
      this.transitionTo("OPEN");
    } else if (this.state === "CLOSED") {
      if (this.failureTimestamps.length >= this.options.failureThreshold) {
        this.transitionTo("OPEN");
      }
    }
  }

  /**
   * Executes an asynchronous task protected by the circuit breaker.
   */
  public async executeTask<T>(action: () => Promise<T>): Promise<T> {
    if (!this.canExecute()) {
      throw new Error(`CircuitBreaker[${this.serviceName}] is ${this.state}: upstream call blocked.`);
    }

    try {
      const result = await action();
      this.recordSuccess();
      return result;
    } catch (err) {
      this.recordFailure();
      throw err;
    }
  }

  /**
   * Forces circuit breaker state for disaster recovery or testing.
   */
  public forceState(newState: CircuitState): void {
    this.transitionTo(newState);
  }

  /**
   * Resets all internal telemetry and returns to CLOSED state.
   */
  public reset(): void {
    this.state = "CLOSED";
    this.failureTimestamps = [];
    this.consecutiveSuccesses = 0;
    this.halfOpenCallsActive = 0;
    this.lastStateChange = Date.now();
  }

  private transitionTo(newState: CircuitState): void {
    const oldState = this.state;
    this.state = newState;
    this.lastStateChange = Date.now();

    if (newState === "CLOSED") {
      this.failureTimestamps = [];
      this.consecutiveSuccesses = 0;
      this.halfOpenCallsActive = 0;
    } else if (newState === "OPEN") {
      this.halfOpenCallsActive = 0;
      this.consecutiveSuccesses = 0;
    } else if (newState === "HALF_OPEN") {
      this.consecutiveSuccesses = 0;
    }

    this.onStateChanged(oldState, newState);
  }

  private cleanRollingFailures(now: number): void {
    const windowStart = now - this.options.rollingWindowMs;
    this.failureTimestamps = this.failureTimestamps.filter((t) => t > windowStart);
  }

  protected onStateChanged(from: CircuitState, to: CircuitState): void {
    // Emits state transition event to console or metrics
    if (process.env.DEBUG === "true") {
      process.stdout.write(`[CIRCUIT_BREAKER] ${this.serviceName} changed from ${from} to ${to}\n`);
    }
  }

  public getTelemetry(): CircuitTelemetry {
    return {
      serviceName: this.serviceName,
      state: this.state,
      failureCount: this.failureTimestamps.length,
      consecutiveSuccesses: this.consecutiveSuccesses,
      lastStateChange: this.lastStateChange,
      totalCalls: this.totalCallsCount,
      totalRejected: this.totalRejectedCount,
    };
  }

  public getServiceName(): string {
    return this.serviceName;
  }
}
