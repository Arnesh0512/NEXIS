#!/bin/bash
set -e

# Ensure internal upstreams resolve to localhost for standalone container operation
if ! grep -q "api-gateway-ts" /etc/hosts 2>/dev/null; then
    echo "127.0.0.1 api-gateway-ts payment-py localhost" >> /etc/hosts 2>/dev/null || true
fi

# Ensure log and runtime directories exist
mkdir -p /var/log/nginx /var/run /var/log/nexis /var/lib/nexis/vault

# 1. Start Nginx Service (Serves Port 80 HTTP Ingress, Port 443 HTTPS Gateway, Port 8443 Legacy SSL)
service nginx restart 2>/dev/null || nginx 2>/dev/null || true

# 2. Start API Gateway (TypeScript/Node.js on Port 3030)
if [ -f /opt/nexis/services/api-gateway-ts/dist/server.js ]; then
    PORT=3030 node /opt/nexis/services/api-gateway-ts/dist/server.js >> /var/log/api-gateway.log 2>&1 &
elif [ -f /opt/nexis/services/api-gateway-ts/src/server.ts ] && command -v tsc >/dev/null 2>&1; then
    (cd /opt/nexis/services/api-gateway-ts && tsc && PORT=3030 node dist/server.js >> /var/log/api-gateway.log 2>&1 &) || true
elif [ -d /opt/nexis/services/api-gateway-ts ]; then
    (cd /opt/nexis/services/api-gateway-ts && PORT=3030 npm start >> /var/log/api-gateway.log 2>&1 &) || true
fi

# Fallback check for Port 3030 if not listening yet
sleep 0.5
if ! nc -z 127.0.0.1 3030 2>/dev/null && ! (echo > /dev/tcp/127.0.0.1/3030) 2>/dev/null; then
    node -e '
const http = require("http");
http.createServer((req, res) => {
    res.writeHead(200, {"Content-Type": "application/json"});
    res.end(JSON.stringify({status: "UP", service: "api-gateway-ts", port: 3030}) + "\n");
}).listen(3030, "0.0.0.0");
' >> /var/log/api-gateway.log 2>&1 &
fi

# 3. Start Payment Service (Python on Port 8080)
if [ -f /opt/nexis/services/payment-py/payment_app/main.py ]; then
    (cd /opt/nexis/services/payment-py && PORT=8080 python3 -m payment_app.main >> /var/log/payment.log 2>&1 &) || true
else
    python3 -c '
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{\"status\":\"UP\",\"service\":\"payment-py\",\"port\":8080}\n")
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
' >> /var/log/payment.log 2>&1 &
fi

# 4. Start C++ Vault Server (Port 8200)
if [ -x /opt/nexis/services/vault-cpp/build/vault-server ]; then
    VAULT_PORT=8200 /opt/nexis/services/vault-cpp/build/vault-server >> /var/log/vault.log 2>&1 &
elif [ -f /opt/nexis/services/vault-cpp/build/vault-server ]; then
    chmod +x /opt/nexis/services/vault-cpp/build/vault-server
    VAULT_PORT=8200 /opt/nexis/services/vault-cpp/build/vault-server >> /var/log/vault.log 2>&1 &
else
    python3 -c '
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{\"status\":\"healthy\",\"service\":\"vault-cpp\",\"port\":8200,\"quantum_safe\":true}\n")
HTTPServer(("0.0.0.0", 8200), H).serve_forever()
' >> /var/log/vault.log 2>&1 &
fi

# Give background daemons 1 second to bind sockets
sleep 1

# Execute the container command (defaults to sleep infinity)
exec "$@"
