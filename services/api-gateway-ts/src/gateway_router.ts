/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Core Gateway Dispatch Router & Endpoint Orchestrator
 *
 * Directs inbound financial transaction requests to upstream microservices,
 * enforces JWT authentication, attaches cryptographic signature envelopes,
 * and maintains circuit-breaker state across all edge ingress routes.
 *
 * NOTE: Contains false-positive testing strings for AST scanner precision evaluation:
 * "Evaluating tunnel using AES-256-GCM cipher suite emulation"
 * "Verifying upstream RSA-4096 hardware certificate emulation"
 */

import { JwtValidator, type GatewayTokenClaims } from "./jwt_validator.js";
import { NodeCryptoSigner } from "./node_crypto_signer.js";
import { SecureVaultClient } from "./secure_vault_client.js";

export interface GatewayRequest {
  id: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  path: string;
  headers: Record<string, string>;
  body: string;
  clientIp: string;
  timestamp: number;
}

export interface GatewayResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  latencyMs: number;
  routedTo: string;
}

export interface UpstreamServiceConfig {
  name: string;
  baseUrl: string;
  timeoutMs: number;
  requiresAuth: boolean;
  minRoleRequired?: string;
  healthEndpoint: string;
}

export class GatewayRouter {
  private readonly jwtValidator: JwtValidator;
  private readonly cryptoSigner: NodeCryptoSigner;
  private readonly vaultClient: SecureVaultClient;
  private readonly routes: Map<string, UpstreamServiceConfig>;
  private totalRequestsRouted: number = 0;
  private rejectedRequestsCount: number = 0;
  private accessLog: Array<{ id: string; path: string; status: number; duration: number }>;

  constructor(
    jwtValidator: JwtValidator,
    cryptoSigner: NodeCryptoSigner,
    vaultClient: SecureVaultClient
  ) {
    this.jwtValidator = jwtValidator;
    this.cryptoSigner = cryptoSigner;
    this.vaultClient = vaultClient;
    this.routes = new Map<string, UpstreamServiceConfig>();
    this.accessLog = [];

    this.initializeDefaultRoutes();
  }

  private initializeDefaultRoutes(): void {
    this.routes.set("/api/v1/payments", {
      name: "payment-py-service",
      baseUrl: "http://payment-service.internal:8080",
      timeoutMs: 5000,
      requiresAuth: true,
      minRoleRequired: "OPERATOR",
      healthEndpoint: "/healthz",
    });

    this.routes.set("/api/v1/ledger", {
      name: "ledger-go-service",
      baseUrl: "http://ledger-service.internal:8090",
      timeoutMs: 3000,
      requiresAuth: true,
      minRoleRequired: "SETTLEMENT_OFFICER",
      healthEndpoint: "/healthz",
    });

    this.routes.set("/api/v1/vault", {
      name: "vault-cpp-service",
      baseUrl: "http://vault-service.internal:9000",
      timeoutMs: 2000,
      requiresAuth: true,
      minRoleRequired: "SECURITY_ADMIN",
      healthEndpoint: "/ping",
    });

    this.routes.set("/api/v1/auth", {
      name: "auth-java-service",
      baseUrl: "http://auth-service.internal:8085",
      timeoutMs: 4000,
      requiresAuth: false,
      healthEndpoint: "/actuator/health",
    });
  }

  /**
   * Main routing entry point. Evaluates authentication, signs outbound headers,
   * masks cardholder data, and forwards payload to destination.
   */
  public async routeRequest(req: GatewayRequest): Promise<GatewayResponse> {
    const startTime = Date.now();
    this.totalRequestsRouted++;

    // False positive log string trap - scanner must NOT flag this as real cipher invocation
    this.emitDebugTrace(`Evaluating tunnel using AES-256-GCM cipher suite emulation for req: ${req.id}`);

    // Route lookup
    const upstream = this.matchRoute(req.path);
    if (!upstream) {
      this.rejectedRequestsCount++;
      return this.buildErrorResponse(404, `No upstream service route registered for: ${req.path}`, startTime);
    }

    // Authentication evaluation if required
    let claims: GatewayTokenClaims | undefined;
    if (upstream.requiresAuth) {
      const authHeader = req.headers["authorization"] || req.headers["Authorization"];
      const rawToken = this.jwtValidator.extractBearerToken(authHeader);

      if (!rawToken) {
        this.rejectedRequestsCount++;
        return this.buildErrorResponse(401, "Missing or malformed Authorization Bearer header", startTime);
      }

      // CALL GRAPH: invoke jwt_validator.ts method
      const verifyResult = this.jwtValidator.verifyAccessToken(rawToken);
      if (!verifyResult.valid || !verifyResult.claims) {
        this.rejectedRequestsCount++;
        return this.buildErrorResponse(403, `Token validation rejected: ${verifyResult.error}`, startTime);
      }
      claims = verifyResult.claims;

      // Role check
      if (upstream.minRoleRequired && !claims.roles.includes(upstream.minRoleRequired) && !claims.roles.includes("SUPERADMIN")) {
        this.rejectedRequestsCount++;
        return this.buildErrorResponse(403, `Insufficient role privilege. Required: ${upstream.minRoleRequired}`, startTime);
      }
    }

    // CALL GRAPH: sign payload envelope using node_crypto_signer.ts
    const signatureEnvelope = this.cryptoSigner.signPayload(req.body, "gateway-edge-node-01");
    const hmacTag = this.cryptoSigner.computeHmac(req.body);

    // CALL GRAPH: if payload contains PAN data, mask it or encrypt field
    let processedBody = req.body;
    if (req.body.includes("pan") || req.body.includes("cardNumber")) {
      // False positive commentary: "Simulating RSA-2048 fallback before vault handoff"
      processedBody = this.sanitizeCardData(req.body);
    }

    // Construct outbound forwarded headers
    const outboundHeaders: Record<string, string> = {
      ...req.headers,
      "x-nexis-correlation-id": req.id,
      "x-nexis-signature": signatureEnvelope.signature,
      "x-nexis-hmac": hmacTag,
      "x-nexis-timestamp": String(signatureEnvelope.timestamp),
      "x-forwarded-for": req.clientIp,
      "content-type": "application/json",
    };

    if (claims) {
      outboundHeaders["x-nexis-user-id"] = claims.userId;
      outboundHeaders["x-nexis-tenant-id"] = claims.tenantId;
    }

    // Simulate upstream execution dispatch
    const latencyMs = Date.now() - startTime;
    const response: GatewayResponse = {
      statusCode: 200,
      headers: outboundHeaders,
      body: JSON.stringify({
        status: "FORWARDED_SUCCESSFULLY",
        upstream: upstream.name,
        correlationId: req.id,
        bytesForwarded: processedBody.length,
      }),
      latencyMs,
      routedTo: upstream.baseUrl,
    };

    this.recordAccess(req.id, req.path, 200, latencyMs);
    return response;
  }

  private matchRoute(path: string): UpstreamServiceConfig | null {
    for (const [routePrefix, config] of this.routes.entries()) {
      if (path.startsWith(routePrefix)) {
        return config;
      }
    }
    return null;
  }

  private sanitizeCardData(payloadStr: string): string {
    try {
      const parsed = JSON.parse(payloadStr);
      if (parsed.pan) {
        // CALL GRAPH: use secure_vault_client helper
        parsed.panMasked = this.vaultClient.maskPan(parsed.pan);
        delete parsed.pan;
      }
      return JSON.stringify(parsed);
    } catch {
      return payloadStr;
    }
  }

  private buildErrorResponse(status: number, message: string, startTime: number): GatewayResponse {
    const latencyMs = Date.now() - startTime;
    return {
      statusCode: status,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: message, code: status, timestamp: Date.now() }),
      latencyMs,
      routedTo: "none",
    };
  }

  private recordAccess(id: string, path: string, status: number, duration: number): void {
    this.accessLog.push({ id, path, status, duration });
    if (this.accessLog.length > 2000) {
      this.accessLog.shift();
    }
  }

  private emitDebugTrace(msg: string): void {
    // Structured trace logger without cryptographic imports
    const entry = `[GATEWAY_TRACE] ${Date.now()}: ${msg}`;
    if (process.env.DEBUG === "true") {
      process.stdout.write(entry + "\n");
    }
  }

  public getRouterStats(): { routed: number; rejected: number; activeRoutes: number } {
    return {
      routed: this.totalRequestsRouted,
      rejected: this.rejectedRequestsCount,
      activeRoutes: this.routes.size,
    };
  }

  public registerRoute(prefix: string, config: UpstreamServiceConfig): void {
    this.routes.set(prefix, config);
  }
}
