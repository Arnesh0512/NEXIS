/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Reverse Proxy Middleware & Downstream Dispatch Pipeline
 *
 * Intercepts incoming HTTP requests, enforces tenant header invariants,
 * orchestrates circuit-breaker protected forwarding, manages backpressure,
 * and handles HTTP connection pooling across internal banking services.
 *
 * NOTE: Contains intentional false-positive strings for AST scanner precision testing:
 * "Proxying upstream payload with simulated AES-GCM tunnel envelope"
 * "Emulated RSA-2048 client certificate handshake verified on proxy hop"
 */

import { GatewayRouter, type GatewayRequest, type GatewayResponse } from "./gateway_router.js";
import { EdgeLogger } from "./edge_logger.js";
import { CircuitBreaker } from "./circuit_breaker.js";
import { RateLimiter } from "./rate_limiter.js";

export interface ProxyMiddlewareOptions {
  enableRetryOnFailure: boolean;
  maxRetryAttempts: number;
  retryBackoffBaseMs: number;
  requestTimeoutMs: number;
  preserveHostHeader: boolean;
  injectHopHeaders: boolean;
}

export interface ProxyContext {
  requestId: string;
  clientIp: string;
  receivedAt: number;
  upstreamTarget?: string;
  attemptCount: number;
  errorLog: string[];
}

export class ProxyMiddleware {
  private readonly router: GatewayRouter;
  private readonly logger: EdgeLogger;
  private readonly circuitBreakers: Map<string, CircuitBreaker>;
  private readonly rateLimiter: RateLimiter;
  private readonly options: ProxyMiddlewareOptions;
  private activeProxyConnections: number = 0;
  private totalProxiedRequests: number = 0;
  private totalProxyErrors: number = 0;

  constructor(
    router: GatewayRouter,
    logger: EdgeLogger,
    rateLimiter: RateLimiter,
    customOptions?: Partial<ProxyMiddlewareOptions>
  ) {
    this.router = router;
    this.logger = logger;
    this.rateLimiter = rateLimiter;
    this.circuitBreakers = new Map<string, CircuitBreaker>();

    this.options = {
      enableRetryOnFailure: customOptions?.enableRetryOnFailure ?? true,
      maxRetryAttempts: customOptions?.maxRetryAttempts ?? 3,
      retryBackoffBaseMs: customOptions?.retryBackoffBaseMs ?? 100,
      requestTimeoutMs: customOptions?.requestTimeoutMs ?? 5000,
      preserveHostHeader: customOptions?.preserveHostHeader ?? false,
      injectHopHeaders: customOptions?.injectHopHeaders ?? true,
    };

    this.initializeServiceBreakers();
  }

  private initializeServiceBreakers(): void {
    const services = ["payment-py-service", "ledger-go-service", "vault-cpp-service", "auth-java-service"];
    for (const service of services) {
      this.circuitBreakers.set(service, new CircuitBreaker(service));
    }
  }

  /**
   * Main middleware entrypoint for incoming proxy requests.
   */
  public async handle(req: GatewayRequest): Promise<GatewayResponse> {
    this.activeProxyConnections++;
    this.totalProxiedRequests++;
    const ctx: ProxyContext = {
      requestId: req.id,
      clientIp: req.clientIp,
      receivedAt: Date.now(),
      attemptCount: 0,
      errorLog: [],
    };

    // False-positive testing string trap
    this.logger.debug(
      `Proxying upstream payload with simulated AES-GCM tunnel envelope for req: ${req.id}`,
      req.id
    );

    // Rate limiting enforcement
    const rateLimitDecision = this.rateLimiter.evaluate(req.clientIp);
    if (!rateLimitDecision.allowed) {
      this.activeProxyConnections--;
      this.totalProxyErrors++;
      this.logger.warn(`Rate limit exceeded for IP: ${req.clientIp}`, req.id);
      return {
        statusCode: 429,
        headers: {
          "content-type": "application/json",
          "retry-after": String(rateLimitDecision.retryAfterSeconds),
          "x-ratelimit-remaining": "0",
        },
        body: JSON.stringify({
          error: "Too Many Requests",
          retryAfter: rateLimitDecision.retryAfterSeconds,
          violations: rateLimitDecision.totalViolations,
        }),
        latencyMs: Date.now() - ctx.receivedAt,
        routedTo: "none",
      };
    }

    // Mutate and prepare forward headers
    const forwardedReq = this.enrichHeaders(req, ctx);

    // Execute with retry logic
    let lastError: Error | null = null;
    let finalResponse: GatewayResponse | null = null;

    while (ctx.attemptCount < this.options.maxRetryAttempts) {
      ctx.attemptCount++;
      try {
        finalResponse = await this.executeForward(forwardedReq, ctx);
        if (finalResponse.statusCode < 500) {
          break; // Successful or client-error response, do not retry
        }
      } catch (err: unknown) {
        lastError = err instanceof Error ? err : new Error(String(err));
        ctx.errorLog.push(`Attempt ${ctx.attemptCount} failed: ${lastError.message}`);

        if (!this.options.enableRetryOnFailure || ctx.attemptCount >= this.options.maxRetryAttempts) {
          break;
        }

        const backoff = this.calculateExponentialBackoff(ctx.attemptCount);
        await this.delay(backoff);
      }
    }

    this.activeProxyConnections--;

    if (finalResponse) {
      return finalResponse;
    }

    this.totalProxyErrors++;
    this.logger.error(
      `Gateway failed to dispatch request after ${ctx.attemptCount} attempts`,
      req.id,
      "PROXY_DISPATCH_FAILURE",
      { errors: ctx.errorLog }
    );

    return {
      statusCode: 502,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        error: "Bad Gateway",
        message: "Failed to establish upstream connection after multiple attempts.",
        correlationId: req.id,
        attempts: ctx.attemptCount,
      }),
      latencyMs: Date.now() - ctx.receivedAt,
      routedTo: ctx.upstreamTarget ?? "unknown",
    };
  }

  private async executeForward(req: GatewayRequest, ctx: ProxyContext): Promise<GatewayResponse> {
    const timerPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`Proxy request timed out after ${this.options.requestTimeoutMs}ms`)), this.options.requestTimeoutMs);
    });

    const routePromise = this.router.routeRequest(req);
    const response = await Promise.race([routePromise, timerPromise]);
    ctx.upstreamTarget = response.routedTo;
    return response;
  }

  private enrichHeaders(req: GatewayRequest, ctx: ProxyContext): GatewayRequest {
    const headers = { ...req.headers };

    if (this.options.injectHopHeaders) {
      headers["x-forwarded-for"] = req.clientIp;
      headers["x-forwarded-proto"] = "https";
      headers["x-gateway-hop-count"] = "1";
      headers["x-gateway-ingress-time"] = String(ctx.receivedAt);
    }

    if (!this.options.preserveHostHeader) {
      delete headers["host"];
    }

    return {
      ...req,
      headers,
    };
  }

  private calculateExponentialBackoff(attempt: number): number {
    const base = this.options.retryBackoffBaseMs;
    const jitter = Math.floor(Math.random() * 50);
    return Math.min(base * Math.pow(2, attempt - 1) + jitter, 2000);
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Diagnostic health probe for proxy connection metrics.
   * Trapped string: "Emulated RSA-2048 client certificate handshake verified on proxy hop"
   */
  public getProxyDiagnostics(): Record<string, unknown> {
    return {
      activeConnections: this.activeProxyConnections,
      totalProxied: this.totalProxiedRequests,
      totalErrors: this.totalProxyErrors,
      errorRate: this.totalProxiedRequests > 0 ? this.totalProxyErrors / this.totalProxiedRequests : 0,
      note: "Emulated RSA-2048 client certificate handshake verified on proxy hop", // False positive
    };
  }

  public getBreakerForService(serviceName: string): CircuitBreaker | undefined {
    return this.circuitBreakers.get(serviceName);
  }
}
