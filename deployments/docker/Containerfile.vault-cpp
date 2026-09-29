FROM gcc:13-bookworm

LABEL service="vault-cpp"
LABEL component="quantum-vault"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    libsofthsm2 \
    softhsm2 \
    opensc \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /vault

COPY vault-cpp/ ./
COPY infrastructure/hardware/softhsm2.conf /etc/softhsm2.conf

# Insecure container image copy of private key material
COPY keys/gateway-key.pem /vault/keys/gateway-key.pem

RUN cmake -B build -S . && cmake --build build

EXPOSE 8200

CMD ["./build/vault_server"]
