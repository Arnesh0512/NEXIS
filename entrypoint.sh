#!/bin/bash
set -e

# Ensure internal upstreams resolve to localhost for standalone container operation
if ! grep -q "api-gateway-ts" /etc/hosts 2>/dev/null; then
    echo "127.0.0.1 api-gateway-ts payment-py" >> /etc/hosts 2>/dev/null || true
fi

# Ensure Nginx log directory exists
mkdir -p /var/log/nginx /var/run

# Start Nginx service in background
service nginx restart 2>/dev/null || nginx 2>/dev/null || true

# Execute the container command (defaults to sleep infinity)
exec "$@"
