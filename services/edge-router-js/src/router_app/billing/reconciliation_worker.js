/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 7: Billing & Reconciliation
 * Module: Bank Statement Reconciliation Worker
 *
 * Automates SFTP bank statement acquisition (SWIFT MT940), transaction parsing,
 * and ledger reconciliation against MySQL transactional records with offline fallback.
 */

let ssh2;
try {
  ssh2 = require("ssh2");
} catch (_err) {
  ssh2 = null;
}

let mysql2;
try {
  mysql2 = require("mysql2");
} catch (_err) {
  mysql2 = null;
}

// In-memory ledger transactions store for offline testing / fallback
const inMemoryLedgerTransactions = [
  { id: "tx_1001", reference: "REF987654", amount: 500.00, currency: "EUR", type: "CR", status: "SETTLED" },
  { id: "tx_1002", reference: "REF987655", amount: 1250.75, currency: "EUR", type: "CR", status: "SETTLED" },
  { id: "tx_1003", reference: "REF987656", amount: 80.20, currency: "EUR", type: "DR", status: "SETTLED" },
  { id: "tx_1004", reference: "REF987657", amount: 2400.00, currency: "EUR", type: "CR", status: "PENDING" },
];

/**
 * Downloads bank statement file via ssh2 SFTP client with fallback simulation.
 * Captured by Spectra rule: ssh2 SFTP client
 *
 * @param {string} remoteFile - Remote SFTP path
 * @param {Object} [sftpConfig] - SFTP server connection details
 * @returns {Promise<Object>} Downloaded file descriptor and MT940 text content
 */
async function abcd_downloadBankStatement(remoteFile = "statements/daily.mt940", sftpConfig = null) {
  if (ssh2 && ssh2.Client && sftpConfig) {
    return new Promise((resolve, reject) => {
      const conn = new ssh2.Client();
      conn
        .on("ready", () => {
          conn.sftp((err, sftp) => {
            if (err) {
              conn.end();
              return reject(err);
            }
            const chunks = [];
            const readStream = sftp.createReadStream(remoteFile);
            readStream.on("data", (chunk) => chunks.push(chunk));
            readStream.on("end", () => {
              conn.end();
              const content = Buffer.concat(chunks).toString("utf-8");
              resolve({
                filename: remoteFile,
                content,
                source: "ssh2-sftp",
                downloadedAt: Date.now(),
              });
            });
            readStream.on("error", (streamErr) => {
              conn.end();
              reject(streamErr);
            });
          });
        })
        .on("error", (connErr) => {
          reject(connErr);
        })
        .connect(sftpConfig);
    }).catch((_err) => {
      // Fallback to simulated offline MT940 statement
      return getSimulatedStatement(remoteFile);
    });
  }

  // Offline / in-memory simulated MT940 statement
  return getSimulatedStatement(remoteFile);
}

/**
 * Generates synthetic MT940 statement payload for offline processing.
 *
 * @param {string} filename
 * @returns {Object}
 */
function getSimulatedStatement(filename) {
  const sampleMt940 = [
    ":20:NEXIS-STMT-20261005",
    ":25:NL91ABNA0417164300",
    ":28C:00105/001",
    ":60F:C261004EUR100000,00",
    ":61:2610051005CR500,00NTRFREF987654//TXN-EUR-1001",
    ":86:Settlement payout Merchant M-881",
    ":61:2610051005CR1250,75NTRFREF987655//TXN-EUR-1002",
    ":86:Merchant Batch Surcharge EUR-99",
    ":61:2610051005DR80,20NTRFREF987656//TXN-EUR-1003",
    ":86:Interchange network fee",
    ":61:2610051005CR999,99NTRFUNMATCHED999//TXN-EUR-9999",
    ":86:External bank deposit unlinked",
    ":62F:C261005EUR102670,54",
  ].join("\n");

  return {
    filename,
    content: sampleMt940,
    source: "offline-fallback-mt940",
    downloadedAt: Date.now(),
  };
}

/**
 * Parses SWIFT MT940 customer statement text into structured ledger objects.
 *
 * @param {string} content - Raw MT940 text content
 * @returns {Object} Structured statement object
 */
function efgh_parseMt940Statement(content) {
  if (!content || typeof content !== "string") {
    throw new Error("Invalid MT940 content: expected non-empty string");
  }

  const lines = content.split(/\r?\n/);
  const result = {
    reference: null,
    account: null,
    statementNumber: null,
    openingBalance: null,
    closingBalance: null,
    entries: [],
  };

  let currentEntry = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    if (line.startsWith(":20:")) {
      result.reference = line.substring(4);
    } else if (line.startsWith(":25:")) {
      result.account = line.substring(4);
    } else if (line.startsWith(":28C:")) {
      result.statementNumber = line.substring(5);
    } else if (line.startsWith(":60F:")) {
      result.openingBalance = line.substring(5);
    } else if (line.startsWith(":62F:")) {
      result.closingBalance = line.substring(5);
    } else if (line.startsWith(":61:")) {
      // Line format: :61:YYMMDD[MMDD]C/D/RC/RD[funds]amount[code]reference[//bank_ref]
      const raw = line.substring(4);
      const match = raw.match(/^(\d{6})(?:\d{4})?(CR|DR|C|D)([A-Z]?)([\d,\.]+)([A-Za-z0-9]{4})(NONREF|[\w\d]+)(?:\/\/(.*))?$/);

      const entryDate = match ? match[1] : raw.substring(0, 6);
      const dcIndicator = (match ? match[2] : "CR").startsWith("D") ? "DR" : "CR";
      const amountStr = match ? match[4].replace(",", ".") : "0";
      const amount = parseFloat(amountStr) || 0;
      const ref = match ? match[6] : "REF_UNKNOWN";
      const bankRef = match && match[7] ? match[7] : null;

      currentEntry = {
        date: entryDate,
        type: dcIndicator,
        amount,
        reference: ref,
        bankRef,
        description: "",
      };
      result.entries.push(currentEntry);
    } else if (line.startsWith(":86:") && currentEntry) {
      currentEntry.description = line.substring(4);
    }
  }

  return result;
}

/**
 * Compares parsed bank entries against internal database ledger entries via mysql2.
 * Captured by Spectra rule: mysql2
 *
 * @param {Array<Object>} entries - Parsed statement entries
 * @param {Object} [dbConfig] - MySQL connection configuration
 * @returns {Promise<Object>} Reconciliation comparison result
 */
async function efgh_compareLedgerEntries(entries = [], dbConfig = null) {
  let dbLedger = inMemoryLedgerTransactions;

  if (mysql2 && dbConfig) {
    try {
      const connection = await mysql2.createConnection(dbConfig);
      const [rows] = await connection.execute(
        "SELECT id, reference, amount, currency, type, status FROM transactions WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
      );
      await connection.end();
      if (Array.isArray(rows) && rows.length > 0) {
        dbLedger = rows;
      }
    } catch (_mysqlErr) {
      // Fallback to in-memory ledger
    }
  }

  const matched = [];
  const discrepancies = [];
  const unmatchedBank = [];

  for (const bEntry of entries) {
    const found = dbLedger.find(
      (lTx) =>
        lTx.reference.toUpperCase() === bEntry.reference.toUpperCase() ||
        (bEntry.bankRef && lTx.id.toUpperCase() === bEntry.bankRef.toUpperCase())
    );

    if (found) {
      const amountDiff = Math.abs(Number(found.amount) - Number(bEntry.amount));
      if (amountDiff < 0.001) {
        matched.push({
          bankEntry: bEntry,
          ledgerTransaction: found,
          status: "RECONCILED",
        });
      } else {
        discrepancies.push({
          bankEntry: bEntry,
          ledgerTransaction: found,
          amountDifference: amountDiff,
          status: "AMOUNT_MISMATCH",
        });
      }
    } else {
      unmatchedBank.push({
        bankEntry: bEntry,
        status: "UNMATCHED_IN_LEDGER",
      });
    }
  }

  return {
    totalBankEntries: entries.length,
    matchedCount: matched.length,
    discrepancyCount: discrepancies.length,
    unmatchedCount: unmatchedBank.length,
    matched,
    discrepancies,
    unmatchedBank,
    reconciliationRate: entries.length > 0 ? (matched.length / entries.length) * 100 : 100,
  };
}

/**
 * Runs a complete reconciliation cycle: downloads statement, parses MT940, and compares with ledger.
 *
 * @param {Object} [options]
 * @returns {Promise<Object>} Reconciliation cycle results
 */
async function ijkl_runReconciliationCycle(options = {}) {
  const remoteFile = options.remoteFile || "statements/daily_latest.mt940";

  // 1. Download statement via SFTP / fallback
  const downloadResult = await abcd_downloadBankStatement(remoteFile, options.sftpConfig);

  // 2. Parse MT940 format
  const parsedStatement = efgh_parseMt940Statement(downloadResult.content);

  // 3. Compare ledger entries via MySQL / fallback
  const comparison = await efgh_compareLedgerEntries(parsedStatement.entries, options.dbConfig);

  const cycleId = `cycle_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

  return {
    cycleId,
    remoteFile,
    statementReference: parsedStatement.reference,
    account: parsedStatement.account,
    openingBalance: parsedStatement.openingBalance,
    closingBalance: parsedStatement.closingBalance,
    comparison,
    status: comparison.discrepancyCount === 0 && comparison.unmatchedCount === 0 ? "BALANCED" : "DISCREPANCY_DETECTED",
    timestamp: Date.now(),
  };
}

/**
 * Scheduled daily reconciliation job handler.
 *
 * @param {Object} [options]
 * @returns {Promise<Object>} Job execution summary
 */
async function mnop_dailyReconciliationJob(options = {}) {
  const startTime = Date.now();
  const cycleResult = await ijkl_runReconciliationCycle(options);
  const durationMs = Date.now() - startTime;

  return {
    jobId: `job_recon_${Date.now()}`,
    jobName: "DAILY_BANK_RECONCILIATION",
    cycleResult,
    durationMs,
    success: cycleResult.status === "BALANCED",
    executedAt: new Date().toISOString(),
  };
}

module.exports = {
  abcd_downloadBankStatement,
  efgh_parseMt940Statement,
  efgh_compareLedgerEntries,
  ijkl_runReconciliationCycle,
  mnop_dailyReconciliationJob,
  inMemoryLedgerTransactions,
};
