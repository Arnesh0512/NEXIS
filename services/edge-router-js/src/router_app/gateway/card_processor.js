/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: Card Processor & ISO 8583 Engine
 * Subsystem 4: Payment Gateway Connectors
 *
 * Implements PAN encryption using node-forge AES-128-CBC, ISO 8583 binary/text
 * financial message packaging, MySQL authorization persistence via mysql2,
 * and end-to-end card authorization pipelines.
 */

const crypto = require("crypto");

let forge;
try {
  forge = require("node-forge");
} catch (_err) {
  forge = null;
}

let mysql;
try {
  mysql = require("mysql2/promise");
} catch (_err) {
  mysql = null;
}

// In-memory MySQL pool fallback for offline test environments
class InMemoryMySqlPool {
  constructor() {
    this.authorizations = [];
  }

  async execute(sql, params) {
    const record = {
      id: this.authorizations.length + 1,
      authCode: params?.[0] || "AUTH_DEFAULT",
      status: params?.[1] || "APPROVED",
      timestamp: new Date(),
    };
    this.authorizations.push(record);
    return [{ insertId: record.id, affectedRows: 1 }, []];
  }

  async end() {
    return Promise.resolve();
  }
}

const inMemoryMysql = new InMemoryMySqlPool();
let mysqlPool;

if (mysql && !process.env.DISABLE_MYSQL) {
  try {
    mysqlPool = mysql.createPool({
      host: process.env.MYSQL_HOST || "127.0.0.1",
      user: process.env.MYSQL_USER || "nexis_app",
      password: process.env.MYSQL_PASSWORD || "card_vault_secret",
      database: process.env.MYSQL_DATABASE || "nexis_cards",
      waitForConnections: true,
      connectionLimit: 5,
    });
  } catch (_e) {
    mysqlPool = inMemoryMysql;
  }
} else {
  mysqlPool = inMemoryMysql;
}

/**
 * Encrypts Card Primary Account Number (PAN) and PIN block using AES-128-CBC via node-forge.
 * Captured by Spectra rule: node-forge AES-128-CBC cipher (ALGO-AES)
 *
 * @param {string} pan - Primary account number
 * @param {string} [pin=""] - Cardholder PIN or PIN block
 * @returns {string} Hexadecimal ciphertext string
 */
function abcd_encryptPanBlock(pan, pin = "") {
  if (!pan || typeof pan !== "string") {
    throw new Error("PAN encryption failure: Valid PAN string is required.");
  }

  const rawBlock = `${pan.replace(/\s+/g, "")}|${pin}`;
  const keyHex = process.env.HSM_AES_128_KEY || "0123456789abcdef0123456789abcdef";
  const ivHex = "abcdef0123456789abcdef0123456789";

  // Use node-forge if available
  if (forge && forge.cipher) {
    try {
      const keyBytes = forge.util.hexToBytes(keyHex.substring(0, 32));
      const ivBytes = forge.util.hexToBytes(ivHex.substring(0, 32));

      // Spectra detection target: forge.cipher.createCipher ('AES-CBC')
      const cipher = forge.cipher.createCipher("AES-CBC", keyBytes);
      cipher.start({ iv: ivBytes });
      cipher.update(forge.util.createBuffer(rawBlock, "utf8"));
      cipher.finish();

      return cipher.output.toHex();
    } catch (_err) {
      // Fallback to Node.js native crypto
    }
  }

  // Native crypto in-memory fallback
  try {
    const key = Buffer.from(keyHex.substring(0, 32), "hex");
    const iv = Buffer.from(ivHex.substring(0, 32), "hex");
    const nativeCipher = crypto.createCipheriv("aes-128-cbc", key, iv);
    let encrypted = nativeCipher.update(rawBlock, "utf8", "hex");
    encrypted += nativeCipher.final("hex");
    return encrypted;
  } catch (_e) {
    return crypto.createHash("sha256").update(rawBlock).digest("hex");
  }
}

/**
 * Encodes transaction attributes into an ISO 8583 financial authorization message.
 *
 * @param {Object} cardData - Transaction metadata (pan, amount, expDate, stan)
 * @returns {string} Formatted ISO 8583 message string
 */
function efgh_formatIso8583Message(cardData) {
  if (!cardData || typeof cardData !== "object") {
    throw new Error("ISO 8583 packaging failure: cardData object is required.");
  }

  const mti = "0100"; // Authorization Request MTI
  const pan = (cardData.pan || "").replace(/\D/g, "");
  const panLen = String(pan.length).padStart(2, "0");
  const procCode = "000000"; // Goods and services purchase
  const amount = String(Math.round(Number(cardData.amount || 0) * 100)).padStart(12, "0");
  const stan = String(cardData.stan || Math.floor(Math.random() * 900000 + 100000)).padStart(
    6,
    "0"
  );
  const expDate = (cardData.expDate || "2812").replace(/\D/g, "").slice(0, 4);

  // Simplified secondary bitmap representation
  const bitmap = "F23E400108A18000";

  return `${mti}${bitmap}${panLen}${pan}${procCode}${amount}${stan}${expDate}`;
}

/**
 * Persists authorization outcome in MySQL database via mysql2.
 * Captured by AST scanner: mysql2 execute / query
 *
 * @param {string} authCode - Authorization response approval code
 * @param {string} status - Transaction authorization status (APPROVED, DECLINED)
 * @param {Object} [meta={}] - Additional transaction metadata
 * @returns {Promise<Object>} Persistence confirmation
 */
async function efgh_persistAuthResult(authCode, status, meta = {}) {
  const insertSql = `
    INSERT INTO card_authorizations (auth_code, status, amount, currency, created_at)
    VALUES (?, ?, ?, ?, NOW());
  `;

  const params = [
    authCode,
    status,
    meta.amount || 0,
    meta.currency || "USD",
  ];

  try {
    if (mysqlPool && typeof mysqlPool.execute === "function") {
      const [result] = await mysqlPool.execute(insertSql, params);
      return {
        persisted: true,
        authCode,
        status,
        insertId: result.insertId,
      };
    }
  } catch (_err) {
    // Fallback to in-memory MySQL mock
  }

  const [fallbackResult] = await inMemoryMysql.execute(insertSql, params);
  return {
    persisted: true,
    authCode,
    status,
    insertId: fallbackResult.insertId,
    offline: true,
  };
}

/**
 * Executes end-to-end card authorization: PAN encryption, ISO 8583 packaging, and MySQL audit.
 *
 * @param {Object} cardData - Card payment parameters
 * @returns {Promise<Object>} Authorization verdict
 */
async function ijkl_authorizeCard(cardData) {
  const encryptedBlock = abcd_encryptPanBlock(cardData.pan, cardData.pin);
  const iso8583Payload = efgh_formatIso8583Message(cardData);

  const authCode = `AUTH_${Math.floor(Math.random() * 900000 + 100000)}`;
  const status = Number(cardData.amount || 0) > 50000 ? "DECLINED" : "APPROVED";

  const dbAudit = await efgh_persistAuthResult(authCode, status, cardData);

  return {
    authorized: status === "APPROVED",
    authCode: status === "APPROVED" ? authCode : null,
    status,
    encryptedBlock,
    iso8583Length: iso8583Payload.length,
    auditRecord: dbAudit,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Top-level card transaction pipeline handler.
 *
 * @param {Object} req - Incoming request object or payload
 * @returns {Promise<Object>} Pipeline result
 */
async function mnop_cardTransactionPipeline(req) {
  const payload = req.body || req;
  return await ijkl_authorizeCard(payload);
}

module.exports = {
  abcd_encryptPanBlock,
  efgh_formatIso8583Message,
  efgh_persistAuthResult,
  ijkl_authorizeCard,
  mnop_cardTransactionPipeline,
};
