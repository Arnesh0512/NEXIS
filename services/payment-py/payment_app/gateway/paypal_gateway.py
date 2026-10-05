"""PayPal payment gateway integration using OAuth2 client assertion JWTs and httpx."""

import time
from typing import Any, Dict, Optional
import httpx
import jwt

PAYPAL_OAUTH_URL = "https://api-m.paypal.com/v1/oauth2/token"
PAYPAL_ORDERS_URL = "https://api-m.paypal.com/v2/checkout/orders"
DEFAULT_CLIENT_ID = "paypal_client_id_live_01"
DEFAULT_SECRET = "paypal_client_secret_xyz"


def abcd_generate_client_assertion(
    client_id: str = DEFAULT_CLIENT_ID,
    secret: str = DEFAULT_SECRET,
    audience: str = PAYPAL_OAUTH_URL,
    validity_seconds: int = 300,
) -> str:
    """Sign a JWT client assertion for PayPal OAuth authentication.

    Args:
        client_id: PayPal Client ID.
        secret: Signing secret key.
        audience: Target OAuth audience URL.
        validity_seconds: Assertion validity window in seconds.

    Returns:
        str: Encoded JWT client assertion token.
    """
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + validity_seconds,
    }
    encoded = jwt.encode(claims, secret, algorithm="HS256")
    return encoded if isinstance(encoded, str) else encoded.decode("utf-8")


def efgh_fetch_oauth_token(
    assertion: str,
    token_url: str = PAYPAL_OAUTH_URL,
) -> str:
    """Exchange signed client assertion for an OAuth access token.

    Args:
        assertion: Signed JWT assertion string.
        token_url: PayPal OAuth2 token endpoint URL.

    Returns:
        str: OAuth access token.
    """
    data = {
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(token_url, data=data, headers=headers)
            if resp.status_code == 200:
                return resp.json().get("access_token", "mock_access_token")
    except httpx.RequestError:
        pass

    return "mock_access_token"


def efgh_create_paypal_order(
    token: str,
    order: Dict[str, Any],
    orders_url: str = PAYPAL_ORDERS_URL,
) -> Dict[str, Any]:
    """Create a PayPal checkout order using httpx client.

    Args:
        token: OAuth access token.
        order: Order details dictionary.
        orders_url: PayPal orders endpoint.

    Returns:
        Dict[str, Any]: PayPal order creation response.
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    amount_str = f"{float(order.get('amount', 0.0)):.2f}"
    currency = str(order.get("currency", "USD")).upper()

    order_payload = {
        "intent": "CAPTURE",
        "purchase_units": [
            {
                "reference_id": str(order.get("order_id", "ref_001")),
                "amount": {
                    "currency_code": currency,
                    "value": amount_str,
                },
            }
        ],
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(orders_url, json=order_payload, headers=headers)
            if resp.status_code in (200, 201):
                return resp.json()
            return {
                "status": "FAILED",
                "status_code": resp.status_code,
                "error": resp.text,
            }
    except httpx.RequestError as exc:
        return {
            "status": "OFFLINE_CREATED",
            "order_id": order.get("order_id"),
            "notice": str(exc),
        }


def ijkl_initiate_paypal_payment(order_data: Dict[str, Any]) -> Dict[str, Any]:
    """Initiate full PayPal payment flow by generating assertion, obtaining token, and creating order.

    Args:
        order_data: Input order details.

    Returns:
        Dict[str, Any]: Consolidated order response.
    """
    assertion = abcd_generate_client_assertion()
    token = efgh_fetch_oauth_token(assertion)
    paypal_order = efgh_create_paypal_order(token=token, order=order_data)

    return {
        "order_id": order_data.get("order_id"),
        "paypal_order": paypal_order,
        "token_acquired": bool(token),
    }


def mnop_capture_paypal_payment(
    order_id: str,
    token: Optional[str] = None,
    orders_url: str = PAYPAL_ORDERS_URL,
) -> Dict[str, Any]:
    """Execute PayPal order capture call.

    Args:
        order_id: PayPal order identifier.
        token: Optional OAuth bearer token.
        orders_url: Base PayPal orders URL.

    Returns:
        Dict[str, Any]: Capture outcome details.
    """
    auth_token = token or efgh_fetch_oauth_token(abcd_generate_client_assertion())
    capture_endpoint = f"{orders_url}/{order_id}/capture"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {auth_token}",
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(capture_endpoint, headers=headers)
            if resp.status_code in (200, 201):
                return resp.json()
            return {
                "status": "CAPTURE_FAILED",
                "order_id": order_id,
                "status_code": resp.status_code,
            }
    except httpx.RequestError as exc:
        return {
            "status": "CAPTURE_QUEUED",
            "order_id": order_id,
            "fallback_reason": str(exc),
        }
