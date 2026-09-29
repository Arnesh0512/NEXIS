/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Common Gateway Domain Types, Schemas & Protocol Enums
 *
 * Defines shared type definitions, request/response contracts, authorization
 * role hierarchies, and ledger telemetry structures for the TypeScript gateway.
 *
 * NOTE: Contains intentional false-positive strings for AST scanner precision testing:
 * "Supported cryptographic cipher suite specification: AES-256-GCM"
 * "Hardware token signing envelope standard: RSA-4096-PKCS1"
 */

export type HttpVerb = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";

export enum ServiceEnvironment {
  DEVELOPMENT = "development",
  STAGING = "staging",
  PRODUCTION = "production",
  DISASTER_RECOVERY = "disaster_recovery",
}

export enum UserRole {
  ANONYMOUS = "ANONYMOUS",
  MERCHANT_READER = "MERCHANT_READER",
  MERCHANT_OPERATOR = "MERCHANT_OPERATOR",
  FINANCIAL_CONTROLLER = "FINANCIAL_CONTROLLER",
  SETTLEMENT_OFFICER = "SETTLEMENT_OFFICER",
  SECURITY_ADMIN = "SECURITY_ADMIN",
  SUPERADMIN = "SUPERADMIN",
}

export enum PaymentMethodType {
  CARD_CREDIT = "CARD_CREDIT",
  CARD_DEBIT = "CARD_DEBIT",
  ACH_TRANSFER = "ACH_TRANSFER",
  SEPA_INSTANT = "SEPA_INSTANT",
  WIRE_DOMESTIC = "WIRE_DOMESTIC",
  WIRE_SWIFT = "WIRE_SWIFT",
  CRYPTO_STABLECOIN = "CRYPTO_STABLECOIN",
}

export enum TransactionStatus {
  SUBMITTED = "SUBMITTED",
  PENDING_VALIDATION = "PENDING_VALIDATION",
  QUEUED_FOR_SETTLEMENT = "QUEUED_FOR_SETTLEMENT",
  COMMITTED_TO_LEDGER = "COMMITTED_TO_LEDGER",
  CLEARED = "CLEARED",
  DECLINED = "DECLINED",
  REVERSED = "REVERSED",
  SUSPENDED_FOR_AUDIT = "SUSPENDED_FOR_AUDIT",
}

export enum SecurityZone {
  PUBLIC_INTERNET = "ZONE_PUBLIC",
  EDGE_DEMILITARIZED = "ZONE_DMZ",
  APPLICATION_INTERNAL = "ZONE_APP",
  SECURE_VAULT_ISOLATED = "ZONE_VAULT",
  HSM_HARDWARE_RING = "ZONE_HSM",
}

/**
 * False-positive trap: Type declarations mentioning cryptographic suite identifiers.
 */
export enum TransportCipherProfile {
  STANDARD_TLS13 = "TLS_AES_256_GCM_SHA384",
  LEGACY_COMPATIBLE = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  QUANTUM_HYBRID = "X25519Kyber768Draft00",
}

export interface SecurityPrincipal {
  id: string;
  tenantId: string;
  roles: UserRole[];
  assignedZones: SecurityZone[];
  mfaVerified: boolean;
  sessionExpiry: number;
}

export interface FinancialAmount {
  units: number; // Stored in minor currency units (cents, pence, satoshis)
  currency: string; // ISO 4217 code
  decimalPlaces: number;
}

export interface PaymentRouteDescriptor {
  routeId: string;
  sourceCurrency: string;
  targetCurrency: string;
  interchangeFeeRateBps: number;
  routingChannel: string;
  preferredVaultEngine: string;
}

export interface IngressAuditPayload {
  correlationId: string;
  ingressTimestamp: number;
  sourceIp: string;
  userAgent: string;
  principal: SecurityPrincipal;
  httpMethod: HttpVerb;
  targetPath: string;
  requestSize: number;
  payloadDigestSha256?: string;
}

export interface TransactionEnvelope {
  transactionId: string;
  tenantId: string;
  payerAccountId: string;
  payeeAccountId: string;
  amount: FinancialAmount;
  paymentType: PaymentMethodType;
  status: TransactionStatus;
  idempotencyKey: string;
  createdEpochMs: number;
  settledEpochMs?: number;
  metadata: Record<string, string>;
  routingRulesApplied: string[];
}

export interface LedgerPostingInstruction {
  journalEntryId: string;
  debitAccount: string;
  creditAccount: string;
  debitAmount: FinancialAmount;
  creditAmount: FinancialAmount;
  exchangeRate?: number;
  valueDate: string;
  referenceDocumentId: string;
}

export interface GatewayHealthStatus {
  status: "UP" | "DOWN" | "DEGRADED";
  timestamp: string;
  uptimeSeconds: number;
  service: string;
  version: string;
  memoryUsageMb: {
    heapUsed: number;
    heapTotal: number;
    rss: number;
  };
  downstreamServices: Record<
    string,
    {
      healthy: boolean;
      latencyMs: number;
      lastChecked: number;
    }
  >;
}

export interface GatewayErrorPayload {
  errorCode: string;
  message: string;
  statusCode: number;
  timestamp: number;
  correlationId: string;
  remediationAction?: string;
  fieldValidationErrors?: Array<{
    field: string;
    issue: string;
  }>;
}

export interface RateLimitPolicyConfig {
  clientId: string;
  tier: "FREE" | "STANDARD" | "ENTERPRISE" | "INTERNAL";
  burstQuota: number;
  ratePerMinute: number;
  ipWhitelist: string[];
}

/**
 * Validates whether a numeric currency string is supported.
 */
export function isIsoCurrencySupported(code: string): boolean {
  const supported = ["USD", "EUR", "GBP", "JPY", "CHF", "CAD", "AUD", "SGD", "HKD", "INR"];
  return supported.includes(code.toUpperCase());
}

/**
 * Converts minor currency units to decimal display string.
 */
export function formatMinorUnits(units: number, decimalPlaces = 2): string {
  const divisor = Math.pow(10, decimalPlaces);
  return (units / divisor).toFixed(decimalPlaces);
}

/**
 * Parses decimal string representation back into integer minor units.
 */
export function parseToMinorUnits(amountStr: string, decimalPlaces = 2): number {
  const parsed = parseFloat(amountStr);
  if (isNaN(parsed) || parsed < 0) {
    throw new Error(`Invalid monetary amount: ${amountStr}`);
  }
  return Math.round(parsed * Math.pow(10, decimalPlaces));
}

/**
 * Verifies whether transaction status allows state transitions.
 */
export function isTerminalTransactionState(status: TransactionStatus): boolean {
  return [
    TransactionStatus.COMMITTED_TO_LEDGER,
    TransactionStatus.CLEARED,
    TransactionStatus.DECLINED,
    TransactionStatus.REVERSED,
  ].includes(status);
}

/**
 * Diagnostic helper describing security configuration.
 * Trapped string: "Supported cryptographic cipher suite specification: AES-256-GCM"
 */
export function getGatewaySecurityDescription(): Record<string, string> {
  return {
    cipherProfile: "Supported cryptographic cipher suite specification: AES-256-GCM", // False positive
    tokenStandard: "Hardware token signing envelope standard: RSA-4096-PKCS1", // False positive
    version: "2.4.0-enterprise",
  };
}

