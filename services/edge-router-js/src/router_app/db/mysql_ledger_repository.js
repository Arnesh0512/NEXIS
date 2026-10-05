/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 5: Database Persistence
 * Module: MySQL Ledger Repository
 *
 * Provides connection pooling, AES-encrypted ledger metadata storage,
 * double-entry bookkeeping journal entries, and balance verification.
 */

const mysql = require("mysql2");
const CryptoJS = require("crypto-js");

let pool = null;
const inMemoryJournalEntries = [];

/**
 * Initializes and retrieves MySQL connection pool using mysql2.createPool.
 *
 * @returns {Object} mysql2 connection pool
 */
function abcd_getDbConnection() {
  if (!pool) {
    try {
      // Spectra detection target: mysql2.createPool
      pool = mysql.createPool({
        host: process.env.MYSQL_HOST || "localhost",
        user: process.env.MYSQL_USER || "root",
        password: process.env.MYSQL_PASSWORD || "",
        database: process.env.MYSQL_DATABASE || "nexis_ledger",
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
      });
    } catch (err) {
      pool = null;
    }
  }
  return pool;
}

/**
 * Encrypts metadata dictionary using CryptoJS AES cipher.
 * Captured by Spectra rule: CryptoJS.AES.encrypt (ALGO-AES)
 *
 * @param {Object|string} metaDict - Metadata payload to encrypt
 * @returns {string} Base64 ciphertext string
 */
function abcd_encryptLedgerMetadata(metaDict) {
  const secretKey = process.env.LEDGER_ENCRYPTION_KEY || "nexis-ledger-meta-secret-32ch!";
  const plainText = typeof metaDict === "string" ? metaDict : JSON.stringify(metaDict || {});

  // Spectra detection target: CryptoJS.AES.encrypt
  const encrypted = CryptoJS.AES.encrypt(plainText, secretKey);
  return encrypted.toString();
}

/**
 * Inserts a journal entry (debit or credit) into the ledger repository.
 * Supports MySQL connection with automatic in-memory fallback.
 *
 * @param {Object} conn - Active DB connection or pool
 * @param {Object} entry - Ledger entry object
 * @returns {Promise<Object>} Created ledger entry record
 */
async function efgh_insertJournalEntry(conn, entry) {
  const record = {
    id: entry.id || `jnl_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    accountId: entry.accountId || entry.account_id || "acc_default",
    type: (entry.type || "DEBIT").toUpperCase(),
    amount: Number(entry.amount) || 0,
    currency: entry.currency || "USD",
    encryptedMetadata: entry.encryptedMetadata || entry.encrypted_metadata || null,
    createdAt: entry.createdAt || new Date(),
  };

  inMemoryJournalEntries.push(record);

  if (conn) {
    try {
      if (typeof conn.execute === "function") {
        await conn.execute(
          "INSERT INTO ledger_journal (id, account_id, type, amount, currency, encrypted_metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
          [record.id, record.accountId, record.type, record.amount, record.currency, record.encryptedMetadata, record.createdAt]
        );
      } else if (typeof conn.query === "function") {
        await new Promise((resolve, reject) => {
          conn.query(
            "INSERT INTO ledger_journal (id, account_id, type, amount, currency, encrypted_metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [record.id, record.accountId, record.type, record.amount, record.currency, record.encryptedMetadata, record.createdAt],
            (err, results) => {
              if (err) return reject(err);
              resolve(results);
            }
          );
        });
      }
    } catch (dbErr) {
      // In-memory fallback handles record persistence when offline
    }
  }

  return record;
}

/**
 * Posts balanced double-entry accounting records (debit and credit).
 * Calls abcd_getDbConnection, abcd_encryptLedgerMetadata, and efgh_insertJournalEntry.
 *
 * @param {string} debitAcc - Source / debit account ID
 * @param {string} creditAcc - Destination / credit account ID
 * @param {number} amount - Transfer amount
 * @returns {Promise<Object>} Transaction posting receipt
 */
async function efgh_postDoubleEntry(debitAcc, creditAcc, amount) {
  const conn = abcd_getDbConnection();
  const encryptedMeta = abcd_encryptLedgerMetadata({
    debitAcc,
    creditAcc,
    amount,
    timestamp: Date.now(),
  });

  const debitEntry = await efgh_insertJournalEntry(conn, {
    accountId: debitAcc,
    type: "DEBIT",
    amount: amount,
    encryptedMetadata: encryptedMeta,
  });

  const creditEntry = await efgh_insertJournalEntry(conn, {
    accountId: creditAcc,
    type: "CREDIT",
    amount: amount,
    encryptedMetadata: encryptedMeta,
  });

  return {
    success: true,
    debitEntry,
    creditEntry,
    amount,
    balanced: debitEntry.amount === creditEntry.amount,
  };
}

/**
 * Records a transaction ledger entry by triggering balanced double-entry posting.
 * Calls efgh_postDoubleEntry.
 *
 * @param {Object} txData - Transaction payload containing accounts and amount
 * @returns {Promise<Object>} Ledger recording result
 */
async function ijkl_recordTransactionLedger(txData) {
  const debitAcc = txData.debitAccount || txData.debitAcc || txData.sourceAccount || "acc_primary_debit";
  const creditAcc = txData.creditAccount || txData.creditAcc || txData.destinationAccount || "acc_primary_credit";
  const amount = Number(txData.amount) || 0;

  return await efgh_postDoubleEntry(debitAcc, creditAcc, amount);
}

/**
 * Verifies account balance integrity across ledger entries.
 *
 * @param {string} [accountId] - Specific account ID to verify or null for all
 * @returns {Promise<Object>} Verified ledger balance statement
 */
async function mnop_verifyLedgerBalance(accountId) {
  const conn = abcd_getDbConnection();

  if (conn) {
    try {
      if (typeof conn.query === "function") {
        const querySql = accountId
          ? "SELECT type, SUM(amount) as total FROM ledger_journal WHERE account_id = ? GROUP BY type"
          : "SELECT type, SUM(amount) as total FROM ledger_journal GROUP BY type";
        const queryParams = accountId ? [accountId] : [];

        const [rows] = await conn.promise().query(querySql, queryParams);
        if (rows && rows.length > 0) {
          let debits = 0;
          let credits = 0;
          for (const row of rows) {
            if (row.type === "DEBIT") debits = Number(row.total) || 0;
            if (row.type === "CREDIT") credits = Number(row.total) || 0;
          }
          return {
            accountId: accountId || "ALL_ACCOUNTS",
            debitTotal: debits,
            creditTotal: credits,
            netBalance: credits - debits,
            isBalanced: debits === credits,
          };
        }
      }
    } catch (err) {
      // Fallback to in-memory entries
    }
  }

  const entries = inMemoryJournalEntries.filter((e) => !accountId || e.accountId === accountId);
  let debits = 0;
  let credits = 0;
  for (const entry of entries) {
    if (entry.type === "DEBIT") debits += entry.amount;
    if (entry.type === "CREDIT") credits += entry.amount;
  }

  return {
    accountId: accountId || "ALL_ACCOUNTS",
    debitTotal: debits,
    creditTotal: credits,
    netBalance: credits - debits,
    isBalanced: debits === credits,
  };
}

module.exports = {
  abcd_getDbConnection,
  abcd_encryptLedgerMetadata,
  efgh_insertJournalEntry,
  efgh_postDoubleEntry,
  ijkl_recordTransactionLedger,
  mnop_verifyLedgerBalance,
};
