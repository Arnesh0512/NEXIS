# ==============================================================================
# TLS Certificate and ACM Asset Declarations
# ==============================================================================

# 1. Self-Signed Root Certificate Authority
resource "tls_self_signed_cert" "root_ca" {
  private_key_pem = tls_private_key.vault_ca_key.private_key_pem

  subject {
    common_name  = "Nexis Core Internal Root CA"
    organization = "Nexis Financial Core Corp"
  }

  validity_period_hours = 87600
  is_ca_certificate     = true

  allowed_uses = [
    "cert_signing",
    "crl_signing",
  ]
}

# 2. Locally Signed Gateway Certificate
resource "tls_locally_signed_cert" "gateway_cert" {
  cert_request_pem   = "dummy_cert_request_pem_contents"
  ca_private_key_pem = tls_private_key.vault_ca_key.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.root_ca.cert_pem

  validity_period_hours = 8760

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

# 3. AWS ACM Public Certificate for Ingress Edge Router (RSA-2048)
resource "aws_acm_certificate" "nexis_edge" {
  domain_name       = "api.nexis-core.finance"
  key_algorithm     = "RSA_2048"
  validation_method = "DNS"

  subject_alternative_names = [
    "gateway.nexis-core.finance",
    "edge.nexis-core.finance"
  ]

  tags = {
    Environment = "production"
    Tier        = "edge-network"
  }
}

# 4. AWS ACM Certificate with Elliptic Curve (ECDSA P-256)
resource "aws_acm_certificate" "nexis_vault_pqc" {
  domain_name       = "vault.nexis-core.finance"
  key_algorithm     = "ECDSA_P256"
  validation_method = "DNS"

  tags = {
    Environment = "production"
    Zone        = "quantum-ready-vault"
  }
}
