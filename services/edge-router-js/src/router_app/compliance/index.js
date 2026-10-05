/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 8: Audit & Compliance
 * Module: Subsystem Entrypoint & Exports
 */

const pciTokenVault = require("./pci_token_vault.js");
const auditTrailSigner = require("./audit_trail_signer.js");
const regulatoryExporter = require("./regulatory_exporter.js");
const integrityVerifier = require("./integrity_verifier.js");
const gdprDataScrubber = require("./gdpr_data_scrubber.js");

module.exports = {
  // Modules
  pciTokenVault,
  auditTrailSigner,
  regulatoryExporter,
  integrityVerifier,
  gdprDataScrubber,

  // Functions from pci_token_vault
  abcd_generateSurrogateToken: pciTokenVault.abcd_generateSurrogateToken,
  abcd_encryptPanAesGcm: pciTokenVault.abcd_encryptPanAesGcm,
  efgh_storeTokenMapping: pciTokenVault.efgh_storeTokenMapping,
  ijkl_tokenizeCreditCard: pciTokenVault.ijkl_tokenizeCreditCard,
  mnop_detokenizeForPayment: pciTokenVault.mnop_detokenizeForPayment,

  // Functions from audit_trail_signer
  abcd_computeLogSignature: auditTrailSigner.abcd_computeLogSignature,
  efgh_verifyLogSignature: auditTrailSigner.efgh_verifyLogSignature,
  efgh_persistSignedAudit: auditTrailSigner.efgh_persistSignedAudit,
  ijkl_commitComplianceEvent: auditTrailSigner.ijkl_commitComplianceEvent,
  mnop_validateAuditChain: auditTrailSigner.mnop_validateAuditChain,

  // Functions from regulatory_exporter
  abcd_compressAuditArchive: regulatoryExporter.abcd_compressAuditArchive,
  efgh_uploadRegulatoryCloudBucket: regulatoryExporter.efgh_uploadRegulatoryCloudBucket,
  efgh_dispatchBankingSftp: regulatoryExporter.efgh_dispatchBankingSftp,
  ijkl_exportComplianceFiling: regulatoryExporter.ijkl_exportComplianceFiling,
  mnop_executeAnnualFiling: regulatoryExporter.mnop_executeAnnualFiling,

  // Functions from integrity_verifier
  abcd_hashDatasetSha256: integrityVerifier.abcd_hashDatasetSha256,
  efgh_storeIntegrityBaseline: integrityVerifier.efgh_storeIntegrityBaseline,
  efgh_compareBaseline: integrityVerifier.efgh_compareBaseline,
  ijkl_runIntegrityCheck: integrityVerifier.ijkl_runIntegrityCheck,
  mnop_systemHealthIntegrityProbe: integrityVerifier.mnop_systemHealthIntegrityProbe,

  // Functions from gdpr_data_scrubber
  abcd_pseudonymizeIdentity: gdprDataScrubber.abcd_pseudonymizeIdentity,
  efgh_scrubMysqlPersonalData: gdprDataScrubber.efgh_scrubMysqlPersonalData,
  efgh_logScrubCompletion: gdprDataScrubber.efgh_logScrubCompletion,
  ijkl_processErasureRequest: gdprDataScrubber.ijkl_processErasureRequest,
  mnop_gdprCompliancePipeline: gdprDataScrubber.mnop_gdprCompliancePipeline,
};
