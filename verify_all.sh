#!/usr/bin/env bash
# ==============================================================================
# Nexis Core Platform - Comprehensive Container Self-Test & Dependency Validator
# ==============================================================================
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}======================================================================${NC}"
echo -e "${CYAN}  NEXIS CORE PLATFORM - MULTI-LANGUAGE TEST SUITE & DEPENDENCY AUDIT  ${NC}"
echo -e "${CYAN}======================================================================${NC}"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

run_check() {
    local title="$1"
    local cmd="$2"
    echo -n "Checking: ${title} ... "
    if (eval "$cmd") > /dev/null 2>&1; then
        echo -e "${GREEN}[PASSED]${NC}"
        PASS_COUNT=$((PASS_COUNT+1))
    else
        echo -e "${RED}[FAILED]${NC}"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
}

# 1. System Toolchains
run_check "Python 3 Runtime & Pip" "python3 --version && pip --version"
run_check "Node.js 20 & NPM" "node --version && npm --version"
run_check "Go 1.22 Compiler" "go version"
run_check "Rust & Cargo Toolchain" "rustc --version && cargo --version"
run_check "Java 17 (OpenJDK)" "java -version"
run_check "C/C++ GCC & CMake" "gcc --version && g++ --version && cmake --version"
run_check "OpenSSL & SoftHSM2" "openssl version && softhsm2-util --version"

# 2. Python Dependencies (services/payment-py)
run_check "Python Cryptography Libraries (cryptography, pycryptodome, bcrypt, paramiko)" \
    "python3 -c 'import cryptography, Crypto, bcrypt, paramiko, pydantic, requests, dotenv; print(\"OK\")'"
run_check "Payment Service PCI Engine Self-Test" \
    "python3 -c 'import sys; sys.path.insert(0, \"services/payment-py\"); from payment_app.pci_compliance import PciComplianceEngine; e = PciComplianceEngine(\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"); r = e.encrypt_pan(\"4111111111111111\", \"test\"); assert \"masked_pan\" in r'"

# 3. Node.js & TypeScript Services
run_check "TypeScript API Gateway Built Dist" "test -f services/api-gateway-ts/dist/gateway_router.js"
run_check "API Gateway NPM Dependencies (jsonwebtoken, jose, crypto-js)" \
    "node -e 'require(\"./services/api-gateway-ts/node_modules/jsonwebtoken\"); require(\"./services/api-gateway-ts/node_modules/jose\"); require(\"./services/api-gateway-ts/node_modules/crypto-js\")'"
run_check "Edge Router NPM Dependencies" \
    "node -e 'require(\"./services/edge-router-js/node_modules/crypto-js\"); require(\"./services/edge-router-js/node_modules/jsonwebtoken\")'"

# 4. Go Ledger Microservice
run_check "Go Ledger Module Dependencies (circl, x/crypto)" "cd services/ledger-go && go vet ./..."

# 5. C/C++ Cryptographic Daemons
run_check "C HSM Daemon Binary" "test -f services/hsm-c/build/hsm-daemon"
run_check "C++ Vault Server Binary" "test -f services/vault-cpp/build/vault-server"

# 6. Java Authentication Service
run_check "Java Auth Service Classes" "test -f services/auth-java/target/classes/com/nexis/auth/PasswordHasher.class"

# 7. Rust Cryptographic Engine
run_check "Rust Crypto Storage Engine Check" "(cd services/crypto-rs && cargo check)"

# 8. Certificates & Cryptographic Assets
run_check "Nexis Internal Root CA Installed" "openssl x509 -in certificates/nexis-root-ca.crt -noout -subject"
run_check "Edge Router TLS Certificate & Key" "openssl x509 -in certificates/edge-router.crt -noout -subject && test -f keys/edge-router.key"

echo ""
echo -e "${CYAN}----------------------------------------------------------------------${NC}"
echo -e "Audit Complete: ${GREEN}${PASS_COUNT} Passed${NC}, ${RED}${FAIL_COUNT} Failed${NC}"
echo -e "${CYAN}----------------------------------------------------------------------${NC}"

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✔ ALL SERVICES, RUNTIMES, AND DEPENDENCIES OPERATIONAL.${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠ Some checks had warnings or failures.${NC}"
    exit 1
fi
