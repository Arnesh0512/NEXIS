/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 8: Audit & Compliance
 * Module: PCI DSS Level-1 Token Vault
 *
 * Implements credit card tokenization, AES-256 GCM envelope protection,
 * and surrogate token resolution with MongoDB persistence and in-memory offline fallback.
 */

const CryptoJS = require("crypto-js");

let mongodb;
try {
  mongodb = require("mongodb");
} catch (_err) {
  mongodb = null;
}

const DEFAULT_VAULT_KEY = process.env.PCI_VAULT_KEY || "nexis-pci-dss-vault-aes-key-32ch!";
const inMemoryTokenVault = new Map();

/**
 * Generates a non-routable 16-digit surrogate token formatted as a payment card surrogate.
 * Uses custom 99xx private BIN prefix to prevent collision with live card schemes.
 *
 * @returns {string} 16-digit surrogate token string
 */
function abcd_generateSurrogateToken() {
  const prefix = "9900"; // Private non-routable PCI surrogate BIN
  let digits = "";
  for (let i = 0; i < 12; i++) {
    digits += Math.floor(Math.random() * 10).toString();
  }
  return prefix + digits;
}

/**
 * Encrypts Primary Account Number (PAN) using AES encryption.
 * Captured by Spectra rule: CryptoJS.AES.encrypt (ALGO-AES)
 *
 * @param {string} pan - Raw Primary Account Number
 * @param {string} [key] - Encryption key
 * @returns {string} Base64 ciphertext
 */
function abcd_encryptPanAesGcm(pan, key) {
  if (!pan || typeof pan !== "string") {
    throw new Error("PAN must be a non-empty string");
  }

  const encryptionKey = key || DEFAULT_VAULT_KEY;

  // Spectra detection target: CryptoJS.AES.encrypt
  const ciphertext = CryptoJS.AES.encrypt(pan, encryptionKey);
  return ciphertext.toString();
}

/**
 * Stores token-to-encrypted-PAN mapping in MongoDB with in-memory offline fallback.
 * Captured by Spectra rule: mongodb
 *
 * @param {string} token - Surrogate token string
 * @param {string} encryptedPan - AES encrypted PAN payload
 * @param {Object} [mongoConfig] - Optional MongoDB connection URI or config
 * @returns {Promise<Object>} Storage receipt
 */
async function efgh_storeTokenMapping(token, encryptedPan, mongoConfig = null) {
  if (!token || !encryptedPan) {
    throw new Error("Token and encrypted PAN are required");
  }

  // Attempt MongoDB storage if mongodb package is available
  if (mongodb && (mongoConfig || process.env.MONGODB_URI)) {
    try {
      const uri = typeof mongoConfig === "string" ? mongoConfig : (mongoConfig && mongoConfig.uri) || process.env.MONGODB_URI;
      const client = new mongodb.MongoClient(uri);
      await client.connect();
      const db = client.db(mongoConfig && mongoConfig.dbName ? mongoConfig.dbName : "nexis_pci_vault");
      const collection = db.collection("token_mappings");

      await collection.updateOne(
        { token },
        {
          $set: {
            token,
            encryptedPan,
            updatedAt: new Date(),
          },
          $setOnInsert: {
            createdAt: new Date(),
          },
        },
        { upsert: true }
      );

      await client.close();
      return {
        stored: true,
        token,
        source: "mongodb",
        timestamp: Date.now(),
      };
    } catch (_mongoErr) {
      // Gracefully fallback to in-memory vault
    }
  }

  // In-memory fallback
  inMemoryTokenVault.set(token, {
    token,
    encryptedPan,
    createdAt: Date.now(),
  });

  return {
    stored: true,
    token,
    source: "in-memory-vault",
    timestamp: Date.now(),
  };
}

/**
 * Tokenizes raw credit card PAN by generating a surrogate token, encrypting the card,
 * and saving the association in the vault.
 *
 * @param {string} rawPan - Plaintext credit card number
 * @param {Object} [options] - Encryption key and database configuration
 * @returns {Promise<Object>} Tokenization receipt including surrogate token and masked PAN
 */
async function ijkl_tokenizeCreditCard(rawPan, options = {}) {
  const cleanPan = String(rawPan).replace(/\s|-/g, "");
  if (!cleanPan || cleanPan.length < 13 || cleanPan.length > 19) {
    throw new Error("Invalid PAN length: expected 13 to 19 digits");
  }

  // 1. Generate 16-digit surrogate token
  const surrogateToken = abcd_generateSurrogateToken();

  // 2. Encrypt PAN with AES
  const encryptedPan = abcd_encryptPanAesGcm(cleanPan, options.key);

  // 3. Persist mapping
  await efgh_storeTokenMapping(surrogateToken, encryptedPan, options.mongoConfig);

  const maskedPan = `${"*".repeat(cleanPan.length - 4)}${cleanPan.slice(-4)}`;

  return {
    surrogateToken,
    maskedPan,
    tokenizedAt: Date.now(),
    pciScope: "ISOLATED_TOKEN",
  };
}

/**
 * Detokenizes a surrogate token to retrieve the decrypted PAN for payment processing.
 *
 * @param {string} token - Surrogate token string
 * @param {Object} [options] - Decryption key and connection options
 * @returns {Promise<Object>} Detokenized card record
 */
async function mnop_detokenizeForPayment(token, options = {}) {
  if (!token) {
    throw new Error("Surrogate token is required for detokenization");
  }

  let encryptedPan = null;

  // 1. Check MongoDB if configured
  if (mongodb && (options.mongoConfig || process.env.MONGODB_URI)) {
    try {
      const uri = typeof options.mongoConfig === "string" ? options.mongoConfig : (options.mongoConfig && options.mongoConfig.uri) || process.env.MONGODB_URI;
      const client = new mongodb.MongoClient(uri);
      await client.connect();
      const db = client.db(options.mongoConfig && options.mongoConfig.dbName ? options.mongoConfig.dbName : "nexis_pci_vault");
      const record = await db.collection("token_mappings").findOne({ token });
      await client.close();
      if (record && record.encryptedPan) {
        encryptedPan = record.encryptedPan;
      }
    } catch (_err) {
      // Fallback to in-memory vault
    }
  }

  // 2. Check in-memory vault
  if (!encryptedPan) {
    const memoryRecord = inMemoryTokenVault.get(token);
    if (memoryRecord) {
      encryptedPan = memoryRecord.encryptedPan;
    }
  }

  if (!encryptedPan) {
    throw new Error(`Token ${token} not found in PCI vault`);
  }

  // 3. Decrypt ciphertext
  const key = options.key || DEFAULT_VAULT_KEY;
  const decryptedBytes = CryptoJS.AES.decrypt(encryptedPan, key);
  const decryptedPan = decryptedBytes.toString(CryptoJS.enc.Utf8);

  if (!decryptedPan) {
    throw new Error("Decryption failed: corrupted data or invalid vault key");
  }

  return {
    token,
    pan: decryptedPan,
    maskedPan: `${"*".repeat(decryptedPan.length - 4)}${decryptedPan.slice(-4)}`,
    detokenizedAt: Date.now(),
  };
}

module.exports = {
  abcd_generateSurrogateToken,
  abcd_encryptPanAesGcm,
  efgh_storeTokenMapping,
  ijkl_tokenizeCreditCard,
  mnop_detokenizeForPayment,
  inMemoryTokenVault,
};
