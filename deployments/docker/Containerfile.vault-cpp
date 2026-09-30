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

COPY services/vault-cpp/ ./
COPY infrastructure/hardware/softhsm2.conf /etc/softhsm2.conf

# Container image copy of private key material for key rotation tests
COPY keys/gateway-key.pem /vault/keys/gateway-key.pem

RUN cmake -B build -S . && cmake --build build

EXPOSE 8200

CMD ["./build/vault-server"]
