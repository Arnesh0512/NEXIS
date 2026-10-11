# NEXIS Core Platform // 9-Language Service Explorer Website

## Overview

This website provides an interactive, executive-grade visual explorer for all **9 microservices** in `nexis-core-platform/services`. It analyzes **604 source files** across 9 programming languages, extracting abstract syntax tree (AST) telemetry, imported module boundaries, function call graphs, and post-quantum/classical cryptographic artifacts.

---

## Directory Structure

```
service_analysis_website/
├── data/
│   ├── services_analysis.json   # Full generated JSON dataset (~5.4 MB, 604 files)
│   └── services_data.js         # JavaScript data bundle (for offline/direct file:// loading)
├── generate_analysis_json.py    # Source code scanner & AST analysis script
├── index.html                   # Responsive single-page application UI (Tailwind CSS)
├── style.css                    # Custom theme tokens & transitions
├── app.js                       # Interactive sidebar, card grids, modal drawer, & inspector
├── server.py                    # Lightweight zero-dependency HTTP server (port 8080)
└── README.md                    # Subsystem documentation (this file)
```

---

## The 9 Services & Languages Analyzed

| Language | Service Directory | Source Files | Primary Cryptographic Focus |
| :--- | :--- | :--- | :--- |
| **TypeScript** | `services/api-gateway-ts` | 76 files | `node:crypto`, `jose`, `jsonwebtoken`, AES-256-GCM, HMAC-SHA256 |
| **Java** | `services/auth-java` | 61 files | Bouncy Castle PQC Dilithium (ML-DSA), JCA RSA-2048, PKCS#12, PBKDF2 |
| **Kotlin** | `services/auth-kotlin` | 62 files | Google Tink AEAD, JCA ECDSA (P-256), jBCrypt, JJWT |
| **Rust** | `services/crypto-rs` | 72 files | `pqcrypto-kyber` (ML-KEM-768), `ring` Ed25519, `aes-gcm` AES-256 |
| **JavaScript** | `services/edge-router-js` | 75 files | `crypto-js`, `node-forge`, TLS 1.2/1.3, Session Token JWT |
| **C** | `services/hsm-c` | 62 files | OpenSSL EVP AES-256-GCM, OpenSSL RSA, liboqs PQC, PKCS#11 |
| **Go** | `services/ledger-go` | 62 files | Cloudflare CIRCL Kyber768, `crypto/ed25519`, `crypto/aes`, ChaCha20 |
| **Python** | `services/payment-py` | 73 files | `cryptography` RSA-OAEP, AES-256-GCM, `bcrypt`, PyJWT |
| **C++** | `services/vault-cpp` | 61 files | OpenSSL Modern EVP RSA, liboqs Kyber, X.509 Certs, jwt-cpp |
| **Total** | **9 Services** | **604 files** | **Full AST & Call-Graph Coverage** |

---

## Features & User Interaction

1. **Sidebar Navigation**:
   - 9 language selectors on the left sidebar with live file count badges.
   - Clicking any language instantly switches the view and renders its files.
2. **File Cards Grid**:
   - Displays clean cards with the **file name** for all files in the selected language (50–76 files per language).
   - Real-time search filter in the top header.
3. **Deep File Inspector (Click Card)**:
   - **Lines of Code (LOC)** & **Total Functions**.
   - **Modules Imported**:
     - *External & Standard Library (Not User Defined)* (e.g. `cryptography.hazmat`, `openssl/evp.h`, `fmt`).
     - *Internal Project Modules (User Defined)* (e.g. `payment_app.vault`, `./session_token`, `com.nexis.*`).
   - **Function List**: Interactive pill buttons for all functions declared in the file.
   - **Function Detail Inspector (Click Function)**:
     - **Cryptographic Artifacts Used**: Specific algorithms (e.g. `RSA-OAEP`, `ML-KEM / Kyber`, `AES-256-GCM`, `Ed25519`, `Bcrypt`, `SHA-256`).
     - **Function Calls**: Table of every external/internal function invoked inside it and its originating module/header.

---

## How to Run & View the Website

### Option 1: Using the Built-in Python Server (Recommended)
```bash
cd "C:\Users\Arnesh\Desktop\nexis-core-platform\service_analysis_website"
python server.py
```
This opens `http://localhost:8080` in your default web browser automatically.

### Option 2: Direct File Double-Click
Simply double-click `index.html` or open `file:///C:/Users/Arnesh/Desktop/nexis-core-platform/service_analysis_website/index.html` in your browser. (The embedded `data/services_data.js` bundle ensures the website functions offline with zero CORS restrictions).

### Re-scanning or Updating the Analysis
To re-run the scanner across the services at any time:
```bash
python generate_analysis_json.py
```
This regenerates `data/services_analysis.json` and updates all file ASTs.
