# ==============================================================================
# AWS Key Management Service (KMS) Cryptographic Asset Declarations
# ==============================================================================

# 1. Master Financial Ledger Encryption Key (AES-256-GCM Hardware-Backed)
resource "aws_kms_key" "nexis_master_symmetric" {
  description             = "Nexis Core Ledger Master Database Encryption Key"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "nexis-master-symmetric"
    Security   = "QuantumResistant-AES256"
    Compliance = "FIPS-140-3"
  }
}

# 2. Legacy Asymmetric Signature Key (RSA-2048, Insecure rotation disabled)
resource "aws_kms_key" "nexis_legacy_rsa" {
  description             = "Nexis Legacy Banking Partner Asymmetric Key"
  customer_master_key_spec = "RSA_2048"
  key_usage               = "SIGN_VERIFY"
  deletion_window_in_days = 14
  enable_key_rotation     = false

  tags = {
    Name        = "nexis-legacy-rsa-2048"
    QuantumRisk = "ShorVulnerable"
    Status      = "PendingPQCReplacement"
  }
}

# 3. High-Security ECC Key for API Token Attestation
resource "aws_kms_key" "nexis_ecc_signing" {
  description             = "Nexis Core Elliptic Curve Token Signer"
  customer_master_key_spec = "ECC_NIST_P384"
  key_usage               = "SIGN_VERIFY"
  deletion_window_in_days = 30
  enable_key_rotation     = false

  tags = {
    Name     = "nexis-ecc-nist-p384"
    Curve    = "P-384"
    Standard = "SuiteB"
  }
}

# 4. Long-Term Vault Archive RSA Key
resource "aws_kms_key" "nexis_vault_archive" {
  description             = "Nexis Vault Long-Term Cold Storage Envelope Key"
  customer_master_key_spec = "RSA_4096"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 30
  enable_key_rotation     = false

  tags = {
    Name    = "nexis-vault-archive-4096"
    KeySize = "4096"
  }
}

# 5. Staging Symmetric Key with Disabled Rotation (Triggers MEDIUM severity alert in TerraformScanner)
resource "aws_kms_key" "nexis_unrotated_symmetric" {
  description              = "Nexis Staging Financial Key (Insecure: Rotation Disabled)"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  deletion_window_in_days  = 7
  enable_key_rotation      = false

  tags = {
    Name     = "nexis-unrotated-symmetric"
    Security = "Vulnerable-NoRotation"
  }
}
