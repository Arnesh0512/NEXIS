FROM node:20-alpine AS builder

WORKDIR /usr/src/app

COPY services/api-gateway-ts/package*.json ./
COPY services/api-gateway-ts/tsconfig.json ./
RUN npm install

COPY services/api-gateway-ts/src ./src
RUN npm run build

# Stage 2: Minimal runtime image
FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV SSL_CIPHER_SUITES=ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

COPY services/api-gateway-ts/package*.json ./
RUN npm install --omit=dev

COPY --from=builder /usr/src/app/dist ./dist
COPY certificates/edge-router.crt /etc/ssl/certs/gateway.crt

EXPOSE 3000

CMD ["node", "dist/gateway_router.js"]
