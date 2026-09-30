"""
Nexis Core Financial Ledger Platform - Payment Service Entrypoint
=================================================================
Orchestrates PCI-DSS tokenization, fraud heuristics, and webhook delivery.
"""

import os
import sys
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler

# Import local modules
from payment_app.pci_compliance import PciComplianceEngine
from payment_app.webhook_signer import WebhookSigner
from payment_app.fraud_detector import FraudDetector
from payment_app.payment_dispatcher import PaymentDispatcher

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("payment-py")


class PaymentHealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/health", "/healthz", "/", "/status"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"UP","service":"payment-py","zone":"pci-dss"}\n')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress verbose standard request logs
        return


def main():
    logger.info("Initializing Nexis Payment Service (PCI-DSS mode)...")
    
    master_key = os.getenv("PCI_MASTER_KEY_HEX", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    webhook_secret = os.getenv("WEBHOOK_SECRET", "nexis-webhook-secret-key-32b!")
    
    pci_engine = PciComplianceEngine(master_key)
    webhook_signer = WebhookSigner(webhook_secret)
    fraud_detector = FraudDetector()
    dispatcher = PaymentDispatcher(pci_engine, webhook_signer, fraud_detector)
    
    port = int(os.getenv("PORT", "8080"))
    logger.info(f"Payment Service listening on port {port} (PID: {os.getpid()})")
    
    # Self-test sample encryption
    sample_res = pci_engine.encrypt_pan("4111111111111111", "tenant-alpha")
    logger.info(f"PCI Engine verified - Sample PAN masked: {sample_res.get('masked_pan')}")

    server = HTTPServer(("0.0.0.0", port), PaymentHealthHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down payment service gracefully...")
        server.server_close()


if __name__ == "__main__":
    main()
