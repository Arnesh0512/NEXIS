"""Stripe payment gateway connector module."""

from typing import Any, Dict
from cryptography.hazmat.primitives import hashes, hmac
import requests

STRIPE_API_URL = "https://api.stripe.com/v1/charges"
DEFAULT_STRIPE_KEY = "sk_test_mock_stripe_key_12345"


def abcd_build_idempotency_key(order_id: str, secret_seed: str = "stripe_idem_seed") -> str:
    """Create HMAC-SHA256 idempotency key token via cryptography module.

    Args:
        order_id: Order identifier to derive idempotency from.
        secret_seed: Seed string for secret key generation.

    Returns:
        str: Hex-encoded idempotency token.
    """
    h = hmac.HMAC(secret_seed.encode("utf-8"), hashes.SHA256())
    h.update(str(order_id).encode("utf-8"))
    return f"idem_{h.finalize().hex()[:32]}"


def efgh_send_stripe_charge(
    params: Dict[str, Any],
    idemp_key: str,
    api_key: str = DEFAULT_STRIPE_KEY,
    endpoint_url: str = STRIPE_API_URL,
) -> requests.Response:
    """Send HTTP POST charge request to Stripe API.

    Args:
        params: Payment parameters including amount, currency, and source.
        idemp_key: Unique idempotency key.
        api_key: Stripe secret API key.
        endpoint_url: Stripe endpoint URL.

    Returns:
        requests.Response: Response from Stripe charge API.
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Idempotency-Key": idemp_key,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        response = requests.post(
            endpoint_url,
            data=params,
            headers=headers,
            timeout=10.0,
        )
        return response
    except requests.RequestException:
        # Create a mock failure response object for resilient downstream handling
        resp = requests.Response()
        resp.status_code = 503
        resp._content = b'{"error": {"message": "Stripe gateway unavailable"}}'
        return resp


def efgh_parse_stripe_response(response: requests.Response) -> Dict[str, Any]:
    """Parse Stripe API response extracting status, IDs, and card tokens.

    Args:
        response: Response object from requests.post.

    Returns:
        Dict[str, Any]: Normalized response dictionary.
    """
    try:
        data = response.json()
    except Exception:
        data = {"raw_text": response.text}

    if response.status_code in (200, 201):
        return {
            "success": True,
            "charge_id": data.get("id"),
            "status": data.get("status", "succeeded"),
            "amount": data.get("amount"),
            "currency": data.get("currency"),
            "payment_method": data.get("payment_method"),
            "card_fingerprint": data.get("payment_method_details", {})
            .get("card", {})
            .get("fingerprint"),
        }
    else:
        err = data.get("error", {}) if isinstance(data, dict) else {}
        return {
            "success": False,
            "status": "failed",
            "error_code": err.get("code", "api_error"),
            "error_message": err.get("message", "Charge failed"),
            "http_status": response.status_code,
        }


def ijkl_execute_charge(order_data: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Stripe charge by creating idempotency key, sending request, and parsing response.

    Args:
        order_data: Order transaction payload.

    Returns:
        Dict[str, Any]: Final charge execution result.
    """
    order_id = str(order_data.get("order_id", "ord_unknown"))
    idemp_key = abcd_build_idempotency_key(order_id)

    payload = {
        "amount": int(float(order_data.get("amount", 0)) * 100),  # in cents
        "currency": str(order_data.get("currency", "usd")).lower(),
        "source": order_data.get("token", "tok_visa"),
        "description": f"Charge for order {order_id}",
    }

    response = efgh_send_stripe_charge(params=payload, idemp_key=idemp_key)
    parsed = efgh_parse_stripe_response(response)
    parsed["order_id"] = order_id
    parsed["idempotency_key"] = idemp_key
    return parsed


def mnop_process_stripe_order(order: Dict[str, Any]) -> Dict[str, Any]:
    """Process high-level Stripe order dispatching to execution pipeline.

    Args:
        order: Order dictionary.

    Returns:
        Dict[str, Any]: Charge outcome.
    """
    return ijkl_execute_charge(order)
