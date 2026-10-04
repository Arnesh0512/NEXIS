/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Standalone HTTP Gateway Server Entrypoint
 *
 * Provides live HTTP endpoint listening on port 3030 (or process.env.PORT)
 * with health monitoring and request routing.
 */

import http from "node:http";
import crypto from "node:crypto";
import { GatewayRouter } from "./gateway_router.js";
import { JwtValidator } from "./jwt_validator.js";
import { NodeCryptoSigner } from "./node_crypto_signer.js";
import { SecureVaultClient } from "./secure_vault_client.js";

const port = parseInt(process.env.PORT || "3030", 10);
const host = process.env.HOST || "0.0.0.0";

const defaultSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const jwtValidator = new JwtValidator(defaultSecret);
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const pubPem = publicKey.export({ type: "pkcs1", format: "pem" }).toString();
const privPem = privateKey.export({ type: "pkcs1", format: "pem" }).toString();
const signer = new NodeCryptoSigner(privPem, pubPem, defaultSecret);
const vault = new SecureVaultClient({ 1: defaultSecret }, 1);

const router = new GatewayRouter(jwtValidator, signer, vault);

const server = http.createServer((req, res) => {
  const hostHeader = req.headers.host || "localhost";
  const url = new URL(req.url || "/", `http://${hostHeader}`);
  
  if (url.pathname === "/health" || url.pathname === "/healthz" || url.pathname === "/") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: "UP",
      service: "api-gateway-ts",
      port,
      timestamp: Date.now()
    }) + "\n");
    return;
  }

  // Echo router dispatch status
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    service: "api-gateway-ts",
    path: url.pathname,
    status: "healthy",
    stats: router.getRouterStats()
  }) + "\n");
});

server.listen(port, host, () => {
  console.log(`[API_GATEWAY] Listening on http://${host}:${port} (PID: ${process.pid})`);
});

process.on("SIGTERM", () => {
  server.close(() => process.exit(0));
});
process.on("SIGINT", () => {
  server.close(() => process.exit(0));
});
