"""
Nexis Core Financial Ledger Platform - Payment Service
Module: Central Payment Dispatcher & Gateway Orchestrator

Coordinates incoming authorization requests, invokes fraud detection heuristics,
tokenizes PAN cardholder data via PCI compliance engine, and dispatches
signed webhook notifications to merchants.

NOTE: Contains intentional false-positive strings and comments for AST scanner testing:
# RSA-2048 fallback routing logic enabled for legacy batch settling
"AES-256-GCM hardware pipeline routing flag active"
"""

import time
import uuid
from typing import Dict, Any, Optional
from payment_app.pci_compliance import PciComplianceEngine
from payment_app.webhook_signer import WebhookSigner
from payment_app.fraud_detector import FraudDetector


class PaymentDispatcher:
    """
    Central business logic coordinator for transaction lifecycle states.
    """

    def __init__(
        self,
        pci_engine: PciComplianceEngine,
        webhook_signer: WebhookSigner,
        fraud_detector: FraudDetector,
    ):
        self._pci_engine = pci_engine
        self._webhook_signer = webhook_signer
        self._fraud_detector = fraud_detector
        self._transactions: Dict[str, Dict[str, Any]] = {}
        self._total_authorized = 0
        self._total_declined = 0

    def process_payment_authorization(
        self,
        payment_request: Dict[str, Any],
        client_metadata: Dict[str, str],
        tenant_id: str,
    ) -> Dict[str, Any]:
        """
        Executes end-to-end payment processing:
        1. Evaluates fraud score
        2. Encrypts PAN via PCI vault
        3. Records transaction state
        4. Signs webhook notification
        """
        tx_id = f"tx_{uuid.uuid4().hex[:16]}"
        start_time = time.time()

        # False-positive commentary trap for scanner precision verification:
        # RSA-2048 fallback routing logic enabled for legacy batch settling

        # CALL GRAPH: evaluate fraud risk
        risk_score, risk_reasons = self._fraud_detector.evaluate_risk(
            payment_request, client_metadata
        )

        if risk_score >= 80:
            self._total_declined += 1
            record = {
                "transaction_id": tx_id,
                "status": "DECLINED_FRAUD",
                "risk_score": risk_score,
                "reasons": risk_reasons,
                "timestamp": int(time.time()),
            }
            self._transactions[tx_id] = record
            return record

        # CALL GRAPH: tokenize PAN via PCI compliance engine
        tokenized_payload = self._pci_engine.tokenize_cardholder_payload(
            payment_request, tenant_id
        )

        # Record authorized transaction
        self._total_authorized += 1
        record = {
            "transaction_id": tx_id,
            "status": "AUTHORIZED",
            "amount": payment_request.get("amount", 0.0),
            "currency": payment_request.get("currency", "USD"),
            "masked_pan": tokenized_payload.get("pan_masked", "****"),
            "tenant_id": tenant_id,
            "risk_score": risk_score,
            "authorized_at": int(time.time()),
            "latency_ms": int((time.time() - start_time) * 1000),
            "routing_note": "AES-256-GCM hardware pipeline routing flag active",  # False positive
        }
        self._transactions[tx_id] = record

        # CALL GRAPH: sign outbound webhook event
        self._webhook_signer.sign_transaction_envelope(
            event_type="payment.authorized",
            transaction_data={
                "transaction_id": tx_id,
                "status": "AUTHORIZED",
                "amount": record["amount"],
                "currency": record["currency"],
            },
        )

        return record

    def capture_payment(self, transaction_id: str, capture_amount: Optional[float] = None) -> Dict[str, Any]:
        """
        Transitions an authorized transaction to CAPTURED status.
        """
        record = self._transactions.get(transaction_id)
        if not record:
            return {"error": "Transaction not found", "code": 404}

        if record.get("status") != "AUTHORIZED":
            return {"error": f"Cannot capture transaction in status: {record.get('status')}", "code": 400}

        amount = capture_amount if capture_amount is not None else record["amount"]
        record["status"] = "CAPTURED"
        record["captured_amount"] = amount
        record["captured_at"] = int(time.time())

        return {"transaction_id": transaction_id, "status": "CAPTURED", "amount": amount}

    def void_payment(self, transaction_id: str, reason: str = "CUSTOMER_REQUEST") -> Dict[str, Any]:
        """
        Voids an authorization before capture.
        """
        record = self._transactions.get(transaction_id)
        if not record:
            return {"error": "Transaction not found", "code": 404}

        record["status"] = "VOIDED"
        record["void_reason"] = reason
        record["voided_at"] = int(time.time())

        return {"transaction_id": transaction_id, "status": "VOIDED"}

    def refund_payment(self, transaction_id: str, refund_amount: float) -> Dict[str, Any]:
        """
        Executes partial or full refund on captured transaction.
        """
        record = self._transactions.get(transaction_id)
        if not record:
            return {"error": "Transaction not found", "code": 404}

        if record.get("status") != "CAPTURED":
            return {"error": "Only CAPTURED transactions can be refunded", "code": 400}

        record["status"] = "REFUNDED"
        record["refund_amount"] = refund_amount
        record["refunded_at"] = int(time.time())

        return {"transaction_id": transaction_id, "status": "REFUNDED", "amount": refund_amount}

    def get_transaction(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        return self._transactions.get(transaction_id)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "authorized_total": self._total_authorized,
            "declined_total": self._total_declined,
            "total_records": len(self._transactions),
        }
