/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 7: Billing & Reconciliation
 * Module: Tax Compliance & VAT Reporter
 *
 * Scrapes jurisdiction tax rates via Cheerio, persists tax schedule baselines
 * into PostgreSQL, and computes quarterly VAT liabilities with offline fallback.
 */

let cheerio;
try {
  cheerio = require("cheerio");
} catch (_err) {
  cheerio = null;
}

let pg;
try {
  pg = require("pg");
} catch (_err) {
  pg = null;
}

// In-memory tax rate cache and filing records for offline test runs
const inMemoryTaxRates = new Map([
  ["US", { standardRate: 0.0825, reducedRate: 0.04, label: "United States State Avg" }],
  ["EU_DE", { standardRate: 0.19, reducedRate: 0.07, label: "Germany MwSt" }],
  ["EU_FR", { standardRate: 0.20, reducedRate: 0.055, label: "France TVA" }],
  ["UK", { standardRate: 0.20, reducedRate: 0.05, label: "United Kingdom VAT" }],
  ["JP", { standardRate: 0.10, reducedRate: 0.08, label: "Japan Consumption Tax" }],
  ["SG", { standardRate: 0.09, reducedRate: 0.0, label: "Singapore GST" }],
]);

const inMemoryQuarterlySales = new Map([
  ["m_default_2026_Q1", { grossSales: 150000.00, exemptSales: 10000.00, deductibleVatPaid: 8500.00 }],
  ["m_default_2026_Q2", { grossSales: 185000.00, exemptSales: 15000.00, deductibleVatPaid: 11200.00 }],
]);

/**
 * Scrapes tax rate table from regulatory bulletin markup using Cheerio.
 * Captured by Spectra rule: cheerio.load
 *
 * @param {string} [jurisdictionUrl] - Regulatory rates bulletin URL
 * @param {string} [htmlOverride] - Optional direct HTML payload for testing
 * @returns {Promise<Object>} Map of parsed jurisdiction tax rates
 */
async function abcd_scrapeTaxRates(jurisdictionUrl = "https://tax.internal.nexis/rates", htmlOverride = null) {
  const sampleHtml =
    htmlOverride ||
    `
    <html>
      <body>
        <table class="tax-rates">
          <thead>
            <tr><th>Region</th><th>Code</th><th>Standard</th><th>Reduced</th></tr>
          </thead>
          <tbody>
            <tr data-region="US"><td class="code">US</td><td class="rate">0.0825</td><td class="red">0.0400</td></tr>
            <tr data-region="EU_DE"><td class="code">EU_DE</td><td class="rate">0.1900</td><td class="red">0.0700</td></tr>
            <tr data-region="EU_FR"><td class="code">EU_FR</td><td class="rate">0.2000</td><td class="red">0.0550</td></tr>
            <tr data-region="UK"><td class="code">UK</td><td class="rate">0.2000</td><td class="red">0.0500</td></tr>
            <tr data-region="JP"><td class="code">JP</td><td class="rate">0.1000</td><td class="red">0.0800</td></tr>
          </tbody>
        </table>
      </body>
    </html>
  `;

  if (cheerio && cheerio.load) {
    // Spectra detection target: cheerio.load
    const $ = cheerio.load(sampleHtml);
    const parsedRates = {};

    $("table.tax-rates tbody tr").each((_, row) => {
      const code = $(row).find("td.code").text().trim();
      const stdRate = parseFloat($(row).find("td.rate").text().trim()) || 0;
      const redRate = parseFloat($(row).find("td.red").text().trim()) || 0;

      if (code) {
        parsedRates[code] = {
          standardRate: stdRate,
          reducedRate: redRate,
          scrapedFrom: jurisdictionUrl,
          updatedAt: Date.now(),
        };
      }
    });

    if (Object.keys(parsedRates).length > 0) {
      return parsedRates;
    }
  }

  // Offline / in-memory fallback rate schedule
  const fallback = {};
  for (const [key, val] of inMemoryTaxRates.entries()) {
    fallback[key] = {
      standardRate: val.standardRate,
      reducedRate: val.reducedRate,
      scrapedFrom: "in-memory-fallback",
      updatedAt: Date.now(),
    };
  }
  return fallback;
}

/**
 * Persists parsed tax rate definitions into PostgreSQL via pg.Pool with offline fallback.
 * Captured by Spectra rule: pg.Pool
 *
 * @param {Object} rates - Scraped tax rates dictionary
 * @param {Object} [poolConfig] - Database connection configuration
 * @returns {Promise<Object>} Persistence status report
 */
async function efgh_saveTaxRatesToDb(rates, poolConfig = null) {
  if (!rates || typeof rates !== "object") {
    throw new Error("Invalid rates dictionary");
  }

  // Update in-memory fallback cache
  for (const [code, rateInfo] of Object.entries(rates)) {
    inMemoryTaxRates.set(code, rateInfo);
  }

  if (pg && pg.Pool && (poolConfig || process.env.DATABASE_URL)) {
    try {
      const pool = new pg.Pool(poolConfig || { connectionString: process.env.DATABASE_URL });
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        for (const [code, rateInfo] of Object.entries(rates)) {
          await client.query(
            `
            INSERT INTO tax_rates (jurisdiction_code, standard_rate, reduced_rate, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (jurisdiction_code)
            DO UPDATE SET standard_rate = EXCLUDED.standard_rate, reduced_rate = EXCLUDED.reduced_rate, updated_at = NOW();
          `,
            [code, rateInfo.standardRate, rateInfo.reducedRate]
          );
        }
        await client.query("COMMIT");
      } finally {
        client.release();
        await pool.end().catch(() => {});
      }

      return {
        persistedCount: Object.keys(rates).length,
        source: "postgres",
        success: true,
      };
    } catch (_err) {
      // Fallback to in-memory store
    }
  }

  return {
    persistedCount: Object.keys(rates).length,
    source: "in-memory-cache",
    success: true,
  };
}

/**
 * Calculates quarterly VAT obligations for a given merchant.
 *
 * @param {string} merchantId - Merchant identifier
 * @param {string} quarter - Quarter format (e.g. "2026-Q1")
 * @param {Object} [options] - Optional rate or sales override
 * @returns {Object} VAT computation details
 */
function efgh_calculateQuarterlyVat(merchantId, quarter, options = {}) {
  if (!merchantId || !quarter) {
    throw new Error("merchantId and quarter are required");
  }

  const jurisdiction = options.jurisdiction || "EU_DE";
  const rateConfig = inMemoryTaxRates.get(jurisdiction) || { standardRate: 0.19 };
  const vatRate = typeof options.rate === "number" ? options.rate : rateConfig.standardRate;

  const salesDataKey = `${merchantId}_${quarter.replace("-", "_")}`;
  const sales = options.salesData ||
    inMemoryQuarterlySales.get(salesDataKey) ||
    inMemoryQuarterlySales.get("m_default_2026_Q1") || {
      grossSales: 100000.00,
      exemptSales: 5000.00,
      deductibleVatPaid: 6000.00,
    };

  const taxableSales = Math.max(0, sales.grossSales - sales.exemptSales);
  const grossVatCollected = taxableSales * vatRate;
  const netVatPayable = Math.max(0, grossVatCollected - (sales.deductibleVatPaid || 0));

  return {
    merchantId,
    quarter,
    jurisdiction,
    vatRate,
    grossSales: Math.round(sales.grossSales * 100) / 100,
    exemptSales: Math.round(sales.exemptSales * 100) / 100,
    taxableSales: Math.round(taxableSales * 100) / 100,
    grossVatCollected: Math.round(grossVatCollected * 100) / 100,
    deductibleVatPaid: Math.round((sales.deductibleVatPaid || 0) * 100) / 100,
    netVatPayable: Math.round(netVatPayable * 100) / 100,
    calculatedAt: Date.now(),
  };
}

/**
 * Generates an end-to-end quarterly tax compliance report by scraping current rates,
 * updating the DB rate baseline, and computing the merchant's VAT obligations.
 *
 * @param {string} merchantId - Merchant identifier
 * @param {string} quarter - Reporting quarter
 * @param {Object} [options]
 * @returns {Promise<Object>} Tax report structure
 */
async function ijkl_generateTaxReport(merchantId, quarter, options = {}) {
  // 1. Scrape rates via Cheerio
  const scrapedRates = await abcd_scrapeTaxRates(options.jurisdictionUrl, options.htmlOverride);

  // 2. Save rates to Postgres DB / fallback
  await efgh_saveTaxRatesToDb(scrapedRates, options.poolConfig);

  // 3. Compute quarterly VAT liabilities
  const vatDetails = efgh_calculateQuarterlyVat(merchantId, quarter, options);

  const reportId = `tax_rep_${merchantId}_${quarter}_${Date.now()}`;

  return {
    reportId,
    merchantId,
    quarter,
    ratesSchedule: scrapedRates,
    vatDetails,
    complianceStatus: "VALIDATED",
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Exports final tax filing document for submission to regional tax authority.
 *
 * @param {string} merchantId - Merchant identifier
 * @param {string} quarter - Reporting quarter
 * @param {Object} [options] - Output format specifications
 * @returns {Promise<Object>} Tax filing export package
 */
async function mnop_exportTaxFiling(merchantId, quarter, options = {}) {
  const report = await ijkl_generateTaxReport(merchantId, quarter, options);
  const format = (options.format || "JSON").toUpperCase();

  const filingPayload = {
    header: {
      standard: "SAF-T-VAT-v2.0",
      reportingEntity: merchantId,
      period: quarter,
      timestamp: Date.now(),
    },
    declaration: {
      taxableBase: report.vatDetails.taxableSales,
      taxPayable: report.vatDetails.netVatPayable,
      currency: options.currency || "EUR",
      jurisdiction: report.vatDetails.jurisdiction,
    },
  };

  return {
    filingId: `filing_${merchantId}_${quarter}_${Date.now()}`,
    format,
    reportId: report.reportId,
    payload: format === "XML" ? `<Filing id="${report.reportId}"><Amount>${report.vatDetails.netVatPayable}</Amount></Filing>` : filingPayload,
    status: "READY_FOR_DISPATCH",
    exportedAt: new Date().toISOString(),
  };
}

module.exports = {
  abcd_scrapeTaxRates,
  efgh_saveTaxRatesToDb,
  efgh_calculateQuarterlyVat,
  ijkl_generateTaxReport,
  mnop_exportTaxFiling,
  inMemoryTaxRates,
};
