/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 7: Billing & Reconciliation
 * Module: Invoice Calculator & Storage
 *
 * Computes line-item prices, discounts, encrypted tax IDs, and manages
 * invoice storage in PostgreSQL with in-memory offline fallback.
 */

const CryptoJS = require("crypto-js");

let pg;
try {
  pg = require("pg");
} catch (_err) {
  pg = null;
}

// In-memory fallback store for offline / test environments
const inMemoryInvoiceStore = new Map();

const DEFAULT_SECRET_KEY = process.env.INVOICE_TAX_KEY || "nexis-tax-id-secret-key-32ch-min!";

/**
 * Computes line item prices, item-level discounts, and aggregate invoice subtotals.
 *
 * @param {Array<Object>} itemsList - Array of line items
 * @param {number} itemsList[].price - Unit price
 * @param {number} itemsList[].quantity - Quantity
 * @param {number} [itemsList[].discountPercent] - Discount percentage (0-100)
 * @param {number} [itemsList[].taxRate] - Item specific tax rate (e.g. 0.10 for 10%)
 * @returns {Object} Calculated invoice breakdown
 */
function abcd_calculateSubtotal(itemsList = []) {
  if (!Array.isArray(itemsList) || itemsList.length === 0) {
    return {
      subtotal: 0,
      totalDiscount: 0,
      netSubtotal: 0,
      totalTax: 0,
      grandTotal: 0,
      items: [],
    };
  }

  let subtotal = 0;
  let totalDiscount = 0;
  let totalTax = 0;

  const processedItems = itemsList.map((item, index) => {
    const unitPrice = Number(item.price) || 0;
    const qty = Number(item.quantity) || 1;
    const discountPct = Math.min(100, Math.max(0, Number(item.discountPercent) || 0));
    const taxRate = Number(item.taxRate) || 0;

    const lineGross = unitPrice * qty;
    const lineDiscount = lineGross * (discountPct / 100);
    const lineNet = lineGross - lineDiscount;
    const lineTax = lineNet * taxRate;
    const lineTotal = lineNet + lineTax;

    subtotal += lineGross;
    totalDiscount += lineDiscount;
    totalTax += lineTax;

    return {
      index,
      description: item.description || `Item ${index + 1}`,
      unitPrice,
      quantity: qty,
      lineGross: Math.round(lineGross * 100) / 100,
      lineDiscount: Math.round(lineDiscount * 100) / 100,
      lineNet: Math.round(lineNet * 100) / 100,
      lineTax: Math.round(lineTax * 100) / 100,
      lineTotal: Math.round(lineTotal * 100) / 100,
    };
  });

  const netSubtotal = subtotal - totalDiscount;
  const grandTotal = netSubtotal + totalTax;

  return {
    subtotal: Math.round(subtotal * 100) / 100,
    totalDiscount: Math.round(totalDiscount * 100) / 100,
    netSubtotal: Math.round(netSubtotal * 100) / 100,
    totalTax: Math.round(totalTax * 100) / 100,
    grandTotal: Math.round(grandTotal * 100) / 100,
    items: processedItems,
  };
}

/**
 * Encrypts sensitive Tax ID / VAT identification using AES encryption.
 * Captured by Spectra rule: CryptoJS.AES.encrypt (ALGO-AES)
 *
 * @param {string} taxId - Tax identification string
 * @param {string} [secretKey] - Encryption secret passphrase
 * @returns {string} Encrypted tax ID ciphertext
 */
function abcd_encryptTaxId(taxId, secretKey) {
  if (!taxId || typeof taxId !== "string") {
    throw new Error("Tax ID must be a non-empty string");
  }

  const key = secretKey || DEFAULT_SECRET_KEY;

  // Spectra detection target: CryptoJS.AES.encrypt
  const encrypted = CryptoJS.AES.encrypt(taxId, key);
  return encrypted.toString();
}

/**
 * Inserts invoice record into PostgreSQL via pg.Pool, with in-memory offline fallback.
 * Captured by Spectra rule: pg.Pool
 *
 * @param {Object} invoice - Invoice object
 * @param {Object} [poolConfig] - Optional pg connection configuration
 * @returns {Promise<Object>} Persisted invoice record
 */
async function efgh_storeInvoiceRecord(invoice, poolConfig = null) {
  if (!invoice || !invoice.id) {
    throw new Error("Invalid invoice object: missing ID");
  }

  // Attempt PostgreSQL storage if pg is available and configured
  if (pg && pg.Pool && (poolConfig || process.env.DATABASE_URL)) {
    try {
      const pool = new pg.Pool(poolConfig || { connectionString: process.env.DATABASE_URL });
      const queryText = `
        INSERT INTO invoices (id, merchant_id, subtotal, total_discount, net_subtotal, total_tax, grand_total, tax_id_encrypted, status, metadata, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *;
      `;
      const values = [
        invoice.id,
        invoice.merchantId,
        invoice.calculation.subtotal,
        invoice.calculation.totalDiscount,
        invoice.calculation.netSubtotal,
        invoice.calculation.totalTax,
        invoice.calculation.grandTotal,
        invoice.taxIdEncrypted,
        invoice.status || "PENDING",
        JSON.stringify(invoice.calculation.items || []),
        invoice.createdAt || new Date().toISOString(),
      ];

      const res = await pool.query(queryText, values);
      await pool.end().catch(() => {});
      return {
        ...invoice,
        dbRecord: res.rows[0],
        source: "postgres",
      };
    } catch (_dbErr) {
      // Graceful fallback to in-memory store
    }
  }

  // In-memory fallback
  const record = {
    ...invoice,
    storedAt: Date.now(),
    source: "in-memory-fallback",
  };
  inMemoryInvoiceStore.set(invoice.id, record);
  return record;
}

/**
 * Generates an end-to-end merchant invoice by calculating totals, encrypting
 * the tax ID, and persisting the resulting invoice record.
 *
 * @param {string} merchantId - Unique merchant identifier
 * @param {Array<Object>} items - Line items
 * @param {string} taxId - Tax / VAT registration number
 * @param {Object} [options] - Optional configurations
 * @returns {Promise<Object>} Generated and persisted invoice
 */
async function ijkl_generateMerchantInvoice(merchantId, items, taxId, options = {}) {
  if (!merchantId) {
    throw new Error("merchantId is required to generate invoice");
  }

  // 1. Calculate subtotal & discounts
  const calculation = abcd_calculateSubtotal(items);

  // 2. Encrypt Tax ID
  const taxIdEncrypted = abcd_encryptTaxId(taxId, options.secretKey);

  // 3. Assemble invoice document
  const invoiceId = `inv_${merchantId}_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
  const invoice = {
    id: invoiceId,
    merchantId,
    taxIdEncrypted,
    calculation,
    currency: options.currency || "USD",
    status: "ISSUED",
    createdAt: new Date().toISOString(),
  };

  // 4. Store invoice record
  const storedRecord = await efgh_storeInvoiceRecord(invoice, options.poolConfig);
  return storedRecord;
}

/**
 * Queries and formats an invoice summary for presentation and reporting.
 *
 * @param {string} invoiceId - Invoice identifier
 * @param {Object} [poolConfig] - Optional PostgreSQL configuration
 * @returns {Promise<Object>} Formatted invoice summary
 */
async function mnop_renderInvoiceSummary(invoiceId, poolConfig = null) {
  let record = inMemoryInvoiceStore.get(invoiceId);

  if (!record && pg && pg.Pool && (poolConfig || process.env.DATABASE_URL)) {
    try {
      const pool = new pg.Pool(poolConfig || { connectionString: process.env.DATABASE_URL });
      const res = await pool.query("SELECT * FROM invoices WHERE id = $1 LIMIT 1", [invoiceId]);
      await pool.end().catch(() => {});
      if (res.rows && res.rows.length > 0) {
        record = res.rows[0];
      }
    } catch (_err) {
      // Continue with in-memory record check
    }
  }

  if (!record) {
    throw new Error(`Invoice with ID ${invoiceId} not found`);
  }

  const calc = record.calculation || {
    subtotal: record.subtotal,
    totalDiscount: record.total_discount,
    netSubtotal: record.net_subtotal,
    totalTax: record.total_tax,
    grandTotal: record.grand_total,
    items: [],
  };

  return {
    invoiceId,
    merchantId: record.merchantId || record.merchant_id,
    currency: record.currency || "USD",
    subtotal: calc.subtotal,
    totalDiscount: calc.totalDiscount,
    netSubtotal: calc.netSubtotal,
    totalTax: calc.totalTax,
    grandTotal: calc.grandTotal,
    itemCount: (calc.items && calc.items.length) || 0,
    status: record.status,
    issuedAt: record.createdAt || record.created_at,
    summaryText: `Invoice ${invoiceId} for Merchant ${record.merchantId || record.merchant_id}: Grand Total = ${calc.grandTotal} ${record.currency || "USD"} (${record.status})`,
  };
}

module.exports = {
  abcd_calculateSubtotal,
  abcd_encryptTaxId,
  efgh_storeInvoiceRecord,
  ijkl_generateMerchantInvoice,
  mnop_renderInvoiceSummary,
  inMemoryInvoiceStore,
};
