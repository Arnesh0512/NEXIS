# ==============================================================================
# Nexis Core Platform - Enterprise Multi-Language Container Build
# ==============================================================================
FROM debian:bookworm-slim

LABEL maintainer="security@nexis-core.finance"
LABEL description="Nexis Core Financial Ledger, Secure Vault & Cryptographic Services Test Foundation"

# Prevent interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install Base System Utilities & Native Toolchains
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    softhsm2 \
    opensc \
    libsofthsm2 \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    openjdk-17-jdk-headless \
    maven \
    nginx \
    openssl \
    ca-certificates \
    curl \
    git \
    unzip \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Node.js 20 LTS & Global Build Tools
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g typescript ts-node && \
    rm -rf /var/lib/apt/lists/*

# 3. Install Modern Go (1.22)
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
        x86_64) GOARCH='amd64' ;; \
        aarch64) GOARCH='arm64' ;; \
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL "https://go.dev/dl/go1.22.2.linux-${GOARCH}.tar.gz" -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:$PATH"
ENV GOPATH="/go"
ENV PATH="/go/bin:$PATH"

# 4. Install Rust & Cargo Toolchain
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain stable

# 5. Set Up Python Isolated Environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# 6. Global Platform Cryptographic Environment
ENV SSL_CIPHER_SUITES="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
ENV TLS_MIN_VERSION="TLSv1.2"
ENV OPENSSL_CONF="/etc/ssl/openssl.cnf"
ENV SOFTHSM2_CONF="/etc/softhsm2.conf"
ENV JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"

WORKDIR /opt/nexis

# 7. Copy Entire Platform Repository
COPY . /opt/nexis/

# 8. Install Internal Root CA & Hardware Security Config
RUN if [ -f certificates/nexis-root-ca.crt ]; then \
        cp certificates/nexis-root-ca.crt /usr/local/share/ca-certificates/nexis-root-ca.crt && \
        update-ca-certificates; \
    fi && \
    if [ -f infrastructure/hardware/softhsm2.conf ]; then \
        cp infrastructure/hardware/softhsm2.conf /etc/softhsm2.conf; \
    fi && \
    chmod +x /opt/nexis/verify_all.sh 2>/dev/null || true

# 9. Install Dependencies & Build All Services
# Python Payment Service Dependencies
RUN if [ -f services/payment-py/requirements.txt ]; then \
        pip install --no-cache-dir -r services/payment-py/requirements.txt pytest poetry; \
    fi

# TypeScript & JavaScript Services (API Gateway & Edge Router)
RUN if [ -d services/api-gateway-ts ]; then \
        (cd services/api-gateway-ts && (npm install || npm install --package-lock=false) && npm run build); \
    fi && \
    if [ -d services/edge-router-js ]; then \
        (cd services/edge-router-js && (npm install || npm install --package-lock=false)); \
    fi

# Go Ledger Microservice Dependencies & Binary Build
RUN if [ -d services/ledger-go ]; then \
        (cd services/ledger-go && (go mod download || (rm -f go.sum && go mod tidy && go mod download)) && go build ./...); \
    fi

# C HSM Daemon Build
RUN if [ -d services/hsm-c ]; then \
        (cd services/hsm-c && cmake -B build -S . && cmake --build build); \
    fi

# C++ Vault Server Build
RUN if [ -d services/vault-cpp ]; then \
        (cd services/vault-cpp && cmake -B build -S . && cmake --build build); \
    fi

# Java Auth Service Dependencies (resolve / compile)
RUN if [ -d services/auth-java ]; then \
        (cd services/auth-java && mvn compile -DskipTests); \
    fi

# Rust Cryptographic Storage Engine
RUN if [ -d services/crypto-rs ]; then \
        (cd services/crypto-rs && cargo check); \
    fi

# 10. Expose Platform Microservice Ports
# 80: HTTP Ingress, 443: HTTPS Gateway, 3000: API Gateway (TS), 8080: Payment Service (Py), 8200: C++ Vault, 8443: gRPC/mTLS Edge Router
EXPOSE 80 443 3000 8080 8200 8443

# Default to interactive bash shell or automated self-test
CMD ["/bin/bash"]
