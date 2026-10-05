"""Email Dispatcher Module.

Handles transactional receipt generation, unsubscribing tokens,
and email notification dispatching using JWT and HTTP client requests.
"""

import datetime
import logging
import os
from typing import Any, Dict

import jwt
import requests

logger = logging.getLogger(__name__)

JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "nexis-email-default-jwt-secret")
EMAIL_SERVICE_URL: str = os.getenv("EMAIL_SERVICE_URL", "https://api.emailservice.internal/v1/send")
EMAIL_SENDER: str = os.getenv("EMAIL_SENDER_ADDRESS", "no-reply@nexis-payment.internal")


def abcd_generate_unsubscribe_token(email: str) -> str:
    """Creates a signed unsubscribe token via jwt.encode.

    Args:
        email: Recipient email address.

    Returns:
        Signed JWT string token valid for 30 days.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    payload: Dict[str, Any] = {
        "sub": email,
        "action": "unsubscribe",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(days=30)).timestamp()),
    }
    encoded = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
    if isinstance(encoded, bytes):
        return encoded.decode("utf-8")
    return str(encoded)


def efgh_send_email_http(recipient: str, subject: str, body: str) -> bool:
    """Sends an email dispatch via HTTP POST request.

    Args:
        recipient: Destination email address.
        subject: Email subject line.
        body: HTML or plain text body.

    Returns:
        True if the request was accepted (HTTP 2xx), False otherwise.
    """
    payload = {
        "from": EMAIL_SENDER,
        "to": recipient,
        "subject": subject,
        "html_body": body,
    }
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Nexis-EmailDispatcher/1.0",
    }
    try:
        response = requests.post(
            EMAIL_SERVICE_URL,
            json=payload,
            headers=headers,
            timeout=10,
        )
        if response.status_code in (200, 201, 202):
            logger.info("Email dispatched successfully to %s", recipient)
            return True
        logger.warning(
            "Email service returned status %d for recipient %s: %s",
            response.status_code,
            recipient,
            response.text,
        )
        return False
    except requests.RequestException as exc:
        logger.error("Failed to dispatch email to %s: %s", recipient, exc)
        return False


def efgh_render_receipt_template(payment_data: Dict[str, Any]) -> str:
    """Formats an HTML payment receipt template with transaction details.

    Args:
        payment_data: Dictionary containing transaction details.

    Returns:
        HTML formatted string.
    """
    tx_id = payment_data.get("transaction_id", "N/A")
    amount = payment_data.get("amount", "0.00")
    currency = payment_data.get("currency", "USD")
    status = payment_data.get("status", "COMPLETED")
    recipient = payment_data.get("customer_email", "customer@example.com")
    unsubscribe_token = abcd_generate_unsubscribe_token(recipient)

    html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Nexis Payment Receipt</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f7f9fc; padding: 20px; }}
        .card {{ background: #ffffff; border-radius: 8px; padding: 24px; max-width: 600px; margin: 0 auto; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; margin-bottom: 16px; }}
        .amount {{ font-size: 24px; font-weight: bold; color: #2b6cb0; }}
        .footer {{ font-size: 12px; color: #718096; margin-top: 24px; border-top: 1px solid #edf2f7; padding-top: 12px; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <h2>Payment Confirmation</h2>
        </div>
        <p>Thank you for your transaction with Nexis Core Platform.</p>
        <p><strong>Transaction ID:</strong> {tx_id}</p>
        <p class="amount">{amount} {currency}</p>
        <p><strong>Status:</strong> {status}</p>
        <div class="footer">
            <p>If you have questions, please contact support.</p>
            <p><a href="https://nexis.internal/unsubscribe?token={unsubscribe_token}">Unsubscribe from receipts</a></p>
        </div>
    </div>
</body>
</html>"""
    return html_template


def ijkl_dispatch_payment_receipt(payment_data: Dict[str, Any]) -> bool:
    """Renders receipt template and dispatches email to customer.

    Args:
        payment_data: Dictionary containing transaction data.

    Returns:
        True if email was dispatched successfully, False otherwise.
    """
    recipient = str(payment_data.get("customer_email", ""))
    if not recipient:
        logger.error("Cannot dispatch receipt: Missing customer email.")
        return False

    tx_id = payment_data.get("transaction_id", "Unknown")
    subject = f"Your Nexis Payment Receipt [Tx: {tx_id}]"
    body = efgh_render_receipt_template(payment_data)

    return efgh_send_email_http(recipient=recipient, subject=subject, body=body)


def mnop_send_transaction_alert(payment_dto: Dict[str, Any]) -> bool:
    """Dispatches a transaction alert notification.

    Args:
        payment_dto: Transaction data transfer object.

    Returns:
        True if transaction alert receipt was sent, False otherwise.
    """
    return ijkl_dispatch_payment_receipt(payment_dto)
