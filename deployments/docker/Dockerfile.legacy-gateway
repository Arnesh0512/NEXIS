FROM debian:bullseye-slim

LABEL service="legacy-gateway-adapter"
LABEL status="deprecated"

WORKDIR /opt/legacy

# Insecure legacy TLS configuration for backwards compatibility with v1 terminals
ENV TLS_MIN_VERSION="TLSv1.0"
ENV OPENSSL_CONF="/etc/ssl/openssl-legacy.cnf"
ENV SSL_CIPHER_SUITES="RC4-MD5:DES-CBC3-SHA:AES128-SHA"

EXPOSE 8080 8443

CMD ["/bin/bash"]
