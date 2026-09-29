FROM node:20-alpine AS builder

WORKDIR /usr/src/app

COPY services/api-gateway-ts/package*.json ./
COPY services/api-gateway-ts/tsconfig.json ./
COPY services/api-gateway-ts/src ./src

ENV NODE_OPTIONS="--max-old-space-size=2048"
ENV TLS_MIN_VERSION=TLSv1.2

# Stage 2: Minimal runtime image
FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV SSL_CIPHER_SUITES=ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

COPY --from=builder /usr/src/app ./
COPY certificates/edge-router.crt /etc/ssl/certs/gateway.crt

EXPOSE 3000

CMD ["node", "src/index.js"]
