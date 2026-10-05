/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 7: Billing & Reconciliation
 * Module: Subsystem Entrypoint & Exports
 */

const invoiceCalculator = require("./invoice_calculator.js");
const reconciliationWorker = require("./reconciliation_worker.js");
const merchantPayoutEngine = require("./merchant_payout_engine.js");
const taxComplianceReporter = require("./tax_compliance_reporter.js");
const currencyExchangeFeed = require("./currency_exchange_feed.js");

module.exports = {
  // Modules
  invoiceCalculator,
  reconciliationWorker,
  merchantPayoutEngine,
  taxComplianceReporter,
  currencyExchangeFeed,

  // Functions from invoice_calculator
  abcd_calculateSubtotal: invoiceCalculator.abcd_calculateSubtotal,
  abcd_encryptTaxId: invoiceCalculator.abcd_encryptTaxId,
  efgh_storeInvoiceRecord: invoiceCalculator.efgh_storeInvoiceRecord,
  ijkl_generateMerchantInvoice: invoiceCalculator.ijkl_generateMerchantInvoice,
  mnop_renderInvoiceSummary: invoiceCalculator.mnop_renderInvoiceSummary,

  // Functions from reconciliation_worker
  abcd_downloadBankStatement: reconciliationWorker.abcd_downloadBankStatement,
  efgh_parseMt940Statement: reconciliationWorker.efgh_parseMt940Statement,
  efgh_compareLedgerEntries: reconciliationWorker.efgh_compareLedgerEntries,
  ijkl_runReconciliationCycle: reconciliationWorker.ijkl_runReconciliationCycle,
  mnop_dailyReconciliationJob: reconciliationWorker.mnop_dailyReconciliationJob,

  // Functions from merchant_payout_engine
  abcd_generatePayoutToken: merchantPayoutEngine.abcd_generatePayoutToken,
  efgh_submitAchPayout: merchantPayoutEngine.efgh_submitAchPayout,
  efgh_recordPayoutStatus: merchantPayoutEngine.efgh_recordPayoutStatus,
  ijkl_processMerchantPayout: merchantPayoutEngine.ijkl_processMerchantPayout,
  mnop_dailyPayoutBatch: merchantPayoutEngine.mnop_dailyPayoutBatch,

  // Functions from tax_compliance_reporter
  abcd_scrapeTaxRates: taxComplianceReporter.abcd_scrapeTaxRates,
  efgh_saveTaxRatesToDb: taxComplianceReporter.efgh_saveTaxRatesToDb,
  efgh_calculateQuarterlyVat: taxComplianceReporter.efgh_calculateQuarterlyVat,
  ijkl_generateTaxReport: taxComplianceReporter.ijkl_generateTaxReport,
  mnop_exportTaxFiling: taxComplianceReporter.mnop_exportTaxFiling,

  // Functions from currency_exchange_feed
  abcd_fetchLiveForexRates: currencyExchangeFeed.abcd_fetchLiveForexRates,
  efgh_cacheForexRates: currencyExchangeFeed.efgh_cacheForexRates,
  efgh_getCachedRate: currencyExchangeFeed.efgh_getCachedRate,
  ijkl_convertCurrency: currencyExchangeFeed.ijkl_convertCurrency,
  mnop_normalizePaymentAmount: currencyExchangeFeed.mnop_normalizePaymentAmount,
};
