/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem: Auth & Transport - Aggregator & Exports
 *
 * Exports all token issuing, session authorization, password authentication,
 * SFTP tunnel transport, and MFA coordinator services.
 */

const tokenIssuer = require('./token_issuer.js');
const sessionAuthorizer = require('./session_authorizer.js');
const passwordAuthenticator = require('./password_authenticator.js');
const sftpVaultTunnel = require('./sftp_vault_tunnel.js');
const mfaCoordinator = require('./mfa_coordinator.js');

module.exports = {
  // Subsystem modules
  tokenIssuer,
  sessionAuthorizer,
  passwordAuthenticator,
  sftpVaultTunnel,
  mfaCoordinator,

  // Re-exported Token Issuer methods
  abcd_encodeAccessToken: tokenIssuer.abcd_encodeAccessToken,
  abcd_encodeRefreshToken: tokenIssuer.abcd_encodeRefreshToken,
  efgh_issueAuthPair: tokenIssuer.efgh_issueAuthPair,
  efgh_blacklistToken: tokenIssuer.efgh_blacklistToken,
  ijkl_renewTokenSession: tokenIssuer.ijkl_renewTokenSession,
  mnop_terminateUserSessions: tokenIssuer.mnop_terminateUserSessions,

  // Re-exported Session Authorizer methods
  abcd_decodeAndValidateJwt: sessionAuthorizer.abcd_decodeAndValidateJwt,
  efgh_extractBearerToken: sessionAuthorizer.efgh_extractBearerToken,
  efgh_authorizeRole: sessionAuthorizer.efgh_authorizeRole,
  ijkl_verifySessionSecurity: sessionAuthorizer.ijkl_verifySessionSecurity,
  mnop_protectAdminRoute: sessionAuthorizer.mnop_protectAdminRoute,

  // Re-exported Password Authenticator methods
  abcd_queryUserAccount: passwordAuthenticator.abcd_queryUserAccount,
  efgh_verifyUserCredentials: passwordAuthenticator.efgh_verifyUserCredentials,
  efgh_recordLoginAttempt: passwordAuthenticator.efgh_recordLoginAttempt,
  ijkl_processLoginPipeline: passwordAuthenticator.ijkl_processLoginPipeline,
  mnop_authenticateRequest: passwordAuthenticator.mnop_authenticateRequest,

  // Re-exported SFTP Vault Tunnel methods
  abcd_createSshClient: sftpVaultTunnel.abcd_createSshClient,
  abcd_loadPrivateKeyPassphrase: sftpVaultTunnel.abcd_loadPrivateKeyPassphrase,
  efgh_openSftpTunnel: sftpVaultTunnel.efgh_openSftpTunnel,
  efgh_uploadBatchFile: sftpVaultTunnel.efgh_uploadBatchFile,
  ijkl_transmitClearingFile: sftpVaultTunnel.ijkl_transmitClearingFile,
  mnop_dailySftpSyncJob: sftpVaultTunnel.mnop_dailySftpSyncJob,

  // Re-exported MFA Coordinator methods
  abcd_generateTotpSecret: mfaCoordinator.abcd_generateTotpSecret,
  abcd_verifyTotpCode: mfaCoordinator.abcd_verifyTotpCode,
  efgh_sendSmsChallenge: mfaCoordinator.efgh_sendSmsChallenge,
  ijkl_initiateMfaFlow: mfaCoordinator.ijkl_initiateMfaFlow,
  ijkl_validateMfaFlow: mfaCoordinator.ijkl_validateMfaFlow,
  mnop_enforceMfaRequirement: mfaCoordinator.mnop_enforceMfaRequirement,
};
