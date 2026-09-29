# ==============================================================================
# TLS Private Key Declarations (Local & PKI Integration)
# ==============================================================================

# 1. Enterprise Root Certificate Authority Key (RSA-4096)
resource "tls_private_key" "vault_ca_key" {
  algorithm   = "RSA"
  rsa_bits    = 4096
}

# 2. Insecure Deprecated Client Key (RSA-1024 bits -> triggers ECDAT-CRYPTO-006 / HIGH Alert)
resource "tls_private_key" "weak_client_key" {
  algorithm   = "RSA"
  rsa_bits    = 1024
}

# 3. Modern Elliptic Curve Server Key (NIST P-384)
resource "tls_private_key" "edge_ecdsa_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

# 4. High-Performance Service Mesh Signer (Ed25519)
resource "tls_private_key" "service_mesh_ed25519" {
  algorithm   = "ED25519"
}
