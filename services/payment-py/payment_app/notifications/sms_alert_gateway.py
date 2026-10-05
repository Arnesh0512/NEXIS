"""SMS Alert Gateway Module.

Provides SMS notification capabilities with Redis-based cooldown rate limiting
and carrier API integration via HTTPX.
"""

import logging
import os
from typing import Any, Dict, Optional

import httpx
import redis

logger = logging.getLogger(__name__)

REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD: Optional[str] = os.getenv("REDIS_PASSWORD", None)

CARRIER_SMS_URL: str = os.getenv("CARRIER_SMS_URL", "https://carrier.sms-provider.internal/v2/messages")
CARRIER_API_KEY: str = os.getenv("CARRIER_API_KEY", "nexis-carrier-default-key")
COOLDOWN_SECONDS: int = 60

_redis_client: Optional[redis.Redis] = None


def _get_redis_client() -> redis.Redis:
    """Retrieves or creates a singleton Redis client instance."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=REDIS_PASSWORD,
            decode_responses=True,
            socket_timeout=3.0,
        )
    return _redis_client


def abcd_check_sms_rate_limit(phone: str) -> bool:
    """Checks Redis to verify if an SMS to the phone number is allowed under the 60s cooldown.

    Args:
        phone: Destination phone number in E.164 format.

    Returns:
        True if the cooldown has elapsed (can send), False if rate-limited.
    """
    key = f"sms_cooldown:{phone}"
    try:
        r = _get_redis_client()
        exists = r.exists(key)
        if exists:
            logger.info("SMS rate-limit active for phone: %s", phone)
            return False
        return True
    except Exception as exc:
        logger.warning("Redis error checking SMS rate limit for %s: %s. Defaulting to allow.", phone, exc)
        return True


def efgh_post_sms_carrier(phone: str, message: str) -> bool:
    """Posts an SMS dispatch payload to the cellular carrier gateway via HTTPX.

    Args:
        phone: Destination mobile number.
        message: SMS body text.

    Returns:
        True if the carrier accepted the message (HTTP 2xx), False otherwise.
    """
    headers = {
        "Authorization": f"Bearer {CARRIER_API_KEY}",
        "Content-Type": "application/json",
        "User-Agent": "Nexis-SMSAlertGateway/1.0",
    }
    payload = {
        "to": phone,
        "body": message,
        "sender_id": "NEXIS-SEC",
    }
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(CARRIER_SMS_URL, json=payload, headers=headers)
            if resp.status_code in (200, 201, 202):
                logger.info("SMS successfully queued with carrier for %s", phone)
                return True
            logger.error(
                "Carrier SMS dispatch rejected [%d] for %s: %s",
                resp.status_code,
                phone,
                resp.text,
            )
            return False
    except httpx.HTTPError as exc:
        logger.error("HTTP error during carrier SMS dispatch to %s: %s", phone, exc)
        return False


def efgh_update_sms_cooldown(phone: str) -> None:
    """Sets a Redis cooldown key to prevent duplicate SMS within 60 seconds.

    Args:
        phone: Phone number to lock in cooldown.
    """
    key = f"sms_cooldown:{phone}"
    try:
        r = _get_redis_client()
        r.set(key, "cooldown_active", ex=COOLDOWN_SECONDS)
        logger.debug("Set SMS cooldown for %s for %d seconds", phone, COOLDOWN_SECONDS)
    except Exception as exc:
        logger.warning("Failed to update SMS cooldown key in Redis for %s: %s", phone, exc)


def ijkl_send_fraud_warning_sms(phone: str, tx_summary: Dict[str, Any]) -> bool:
    """Sends a fraud warning alert via SMS if rate limits permit.

    Args:
        phone: Customer mobile phone.
        tx_summary: Dictionary containing transaction details.

    Returns:
        True if the SMS was sent, False if rate limited or carrier dispatch failed.
    """
    if not abcd_check_sms_rate_limit(phone):
        logger.warning("SMS fraud warning throttled by 60s cooldown for %s", phone)
        return False

    tx_id = tx_summary.get("transaction_id", "N/A")
    amount = tx_summary.get("amount", "0.00")
    currency = tx_summary.get("currency", "USD")
    message = (
        f"[NEXIS FRAUD ALERT] Suspicious activity detected on tx {tx_id} "
        f"for {amount} {currency}. If this was not you, reply STOP to freeze your card."
    )

    success = efgh_post_sms_carrier(phone, message)
    if success:
        efgh_update_sms_cooldown(phone)
    return success


def mnop_notify_fraud_alert(phone: str, tx: Dict[str, Any]) -> bool:
    """Top-level handler to notify a customer of fraud alerts on a transaction.

    Args:
        phone: Recipient telephone number.
        tx: Transaction details dictionary.

    Returns:
        True if notification was dispatched, False otherwise.
    """
    return ijkl_send_fraud_warning_sms(phone, tx)
