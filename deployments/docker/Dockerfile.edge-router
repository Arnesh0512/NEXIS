FROM nginx:1.25-alpine

LABEL service="edge-router-js"

ENV SSL_CIPHER_SUITES="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
ENV TLS_MIN_VERSION="TLSv1.2"
ENV OPENSSL_CONF="/etc/ssl/openssl.cnf"

# Copy TLS assets and configuration
COPY network/nginx/nginx.conf /etc/nginx/nginx.conf
COPY network/nginx/conf.d/ /etc/nginx/conf.d/
COPY certificates/edge-router.crt /etc/ssl/certs/edge-router.crt
COPY keys/edge-router.key /etc/ssl/private/edge-router.key

EXPOSE 443 8443

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]
