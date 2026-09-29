# ==============================================================================
# Nexis Core Platform - Multi-Stage Enterprise Container Build
# ==============================================================================
FROM alpine:3.19 AS base
LABEL maintainer="security@nexis-core.finance"
LABEL description="Nexis Core Financial Ledger & Secure Vault Foundation"

RUN apk add --no-cache ca-certificates tzdata openssl

# Cryptographic environment configuration
ENV SSL_CIPHER_SUITES="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
ENV TLS_MIN_VERSION="TLSv1.2"
ENV OPENSSL_CONF="/etc/ssl/openssl.cnf"

WORKDIR /opt/nexis

# Install trusted enterprise internal root CA
COPY certificates/nexis-root-ca.crt /usr/local/share/ca-certificates/nexis-root-ca.crt
RUN update-ca-certificates

# Expose standard HTTPS API port and gRPC mTLS port
EXPOSE 443 8443

CMD ["/bin/sh"]
