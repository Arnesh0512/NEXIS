/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem: Vault - Aggregator & Exports
 *
 * Exports all key vault, signing, encryption, rotation, and credential hashing services.
 */

const keyVaultManager = require('./key_vault_manager.js');
const asymmetricSigner = require('./asymmetric_signer.js');
const symmetricCipherPool = require('./symmetric_cipher_pool.js');
const secretRotator = require('./secret_rotator.js');
const credentialHasher = require('./credential_hasher.js');

module.exports = {
  // Subsystem modules
  keyVaultManager,
  asymmetricSigner,
  symmetricCipherPool,
  secretRotator,
  credentialHasher,

  // Re-exported Key Vault Manager methods
  abcd_generateMasterRsaKey: keyVaultManager.abcd_generateMasterRsaKey,
  abcd_deriveDataEncryptionKey: keyVaultManager.abcd_deriveDataEncryptionKey,
  efgh_storeKeyInCache: keyVaultManager.efgh_storeKeyInCache,
  efgh_retrieveActiveKey: keyVaultManager.efgh_retrieveActiveKey,
  ijkl_rotateMasterKey: keyVaultManager.ijkl_rotateMasterKey,
  mnop_vaultHealthCheck: keyVaultManager.mnop_vaultHealthCheck,

  // Re-exported Asymmetric Signer methods
  abcd_signPayloadRsa: asymmetricSigner.abcd_signPayloadRsa,
  abcd_verifyPayloadRsa: asymmetricSigner.abcd_verifyPayloadRsa,
  abcd_createSignedJwtClaim: asymmetricSigner.abcd_createSignedJwtClaim,
  efgh_authenticateOutboundOrder: asymmetricSigner.efgh_authenticateOutboundOrder,
  ijkl_verifyInboundOrder: asymmetricSigner.ijkl_verifyInboundOrder,
  mnop_dispatchValidatedOrder: asymmetricSigner.mnop_dispatchValidatedOrder,

  // Re-exported Symmetric Cipher Pool methods
  abcd_chacha20Encrypt: symmetricCipherPool.abcd_chacha20Encrypt,
  abcd_chacha20Decrypt: symmetricCipherPool.abcd_chacha20Decrypt,
  efgh_encryptCardPayload: symmetricCipherPool.efgh_encryptCardPayload,
  efgh_decryptCardPayload: symmetricCipherPool.efgh_decryptCardPayload,
  ijkl_secureTokenizationPipeline: symmetricCipherPool.ijkl_secureTokenizationPipeline,
  mnop_detokenizeForSettlement: symmetricCipherPool.mnop_detokenizeForSettlement,

  // Re-exported Secret Rotator methods
  abcd_generateReplacementSecret: secretRotator.abcd_generateReplacementSecret,
  efgh_backupSecretToCloud: secretRotator.efgh_backupSecretToCloud,
  efgh_applyRotatedSecret: secretRotator.efgh_applyRotatedSecret,
  ijkl_executeScheduledRotation: secretRotator.ijkl_executeScheduledRotation,
  mnop_verifyRotationIntegrity: secretRotator.mnop_verifyRotationIntegrity,

  // Re-exported Credential Hasher methods
  abcd_hashPassword: credentialHasher.abcd_hashPassword,
  abcd_verifyPassword: credentialHasher.abcd_verifyPassword,
  efgh_storeUserCredential: credentialHasher.efgh_storeUserCredential,
  efgh_checkUserLogin: credentialHasher.efgh_checkUserLogin,
  ijkl_credentialVerificationFlow: credentialHasher.ijkl_credentialVerificationFlow,
  mnop_adminResetCredential: credentialHasher.mnop_adminResetCredential,
};
