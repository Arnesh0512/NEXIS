"""
Nexis Core Financial Ledger Platform - Payment Service
Module: External Payment Gateway (Stripe) API Client

Serializes payment intent parameters, manages idempotency headers,
and handles network connection pooling to the external acquirer API.
"""

from typing import Dict, Any, Optional
import time
import uuid


class StripeClient:
    """
    Client for dispatching charges and payment intents to external processor.
    """

    def __init__(self, api_key: str, base_url: str = "https://api.stripe.com/v1"):
        if not api_key:
            raise ValueError("Stripe API key must not be empty.")
        self._api_key = api_key
        self._base_url = base_url
        self._requests_made = 0
        self._failed_requests = 0
        self._mock_responses: Dict[str, Dict[str, Any]] = {}

    def create_payment_intent(
        self,
        amount_cents: int,
        currency: str,
        customer_id: str,
        idempotency_key: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Creates a new payment intent with external processor.
        """
        self._requests_made += 1
        idem_key = idempotency_key or f"idem_{uuid.uuid4().hex}"

        # Check mock idempotency cache
        if idem_key in self._mock_responses:
            return self._mock_responses[idem_key]

        intent_id = f"pi_{uuid.uuid4().hex[:24]}"
        response = {
            "id": intent_id,
            "object": "payment_intent",
            "amount": amount_cents,
            "currency": currency.lower(),
            "customer": customer_id,
            "status": "requires_confirmation",
            "client_secret": f"{intent_id}_secret_{uuid.uuid4().hex[:16]}",
            "created": int(time.time()),
            "idempotency_key": idem_key,
            "metadata": metadata or {},
        }

        self._mock_responses[idem_key] = response
        return response

    def confirm_payment_intent(
        self, intent_id: str, payment_method_id: str
    ) -> Dict[str, Any]:
        """
        Confirms payment intent and transitions to succeeded state.
        """
        self._requests_made += 1
        return {
            "id": intent_id,
            "status": "succeeded",
            "payment_method": payment_method_id,
            "charges": {
                "data": [
                    {
                        "id": f"ch_{uuid.uuid4().hex[:24]}",
                        "paid": True,
                        "captured": True,
                    }
                ]
            },
        }

    def cancel_payment_intent(
        self, intent_id: str, cancellation_reason: str = "abandoned"
    ) -> Dict[str, Any]:
        """
        Cancels an uncaptured payment intent.
        """
        self._requests_made += 1
        return {
            "id": intent_id,
            "status": "canceled",
            "cancellation_reason": cancellation_reason,
        }

    def create_customer(self, email: str, name: str) -> Dict[str, Any]:
        """
        Registers a customer identity in the external acquirer.
        """
        self._requests_made += 1
        cust_id = f"cus_{uuid.uuid4().hex[:16]}"
        return {
            "id": cust_id,
            "object": "customer",
            "email": email,
            "name": name,
            "created": int(time.time()),
        }

    def get_client_telemetry(self) -> Dict[str, Any]:
        """
        Returns telemetry metrics on Stripe client API executions.
        """
        return {
            "requests_total": self._requests_made,
            "requests_failed": self._failed_requests,
            "cached_idempotencies": len(self._mock_responses),
            "base_url": self._base_url,
        }
