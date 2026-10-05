"""Partner Event Publisher Module.

Responsible for notifying merchant and partner webhook endpoints of critical events,
persisting configurations and delivery logs in MongoDB with retry resilience.
"""

import datetime
import logging
import os
import time
from typing import Any, Dict, Optional

import pymongo
import requests

logger = logging.getLogger(__name__)

MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "nexis_partners")

_mongo_client: Optional[pymongo.MongoClient] = None


def _get_mongo_db() -> pymongo.database.Database:
    """Returns the MongoDB database handle for partner management."""
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    return _mongo_client[MONGO_DB_NAME]


def abcd_fetch_merchant_webhook_url(merchant_id: str) -> Optional[str]:
    """Queries MongoDB partner registry to fetch configured webhook endpoint.

    Args:
        merchant_id: Identifier of the merchant.

    Returns:
        The merchant's webhook URL string, or None if not configured.
    """
    try:
        db = _get_mongo_db()
        merchant_doc = db["merchants"].find_one({"merchant_id": merchant_id})
        if merchant_doc and "webhook_url" in merchant_doc:
            return str(merchant_doc["webhook_url"])
        logger.warning("No webhook URL configured for merchant_id: %s", merchant_id)
        return None
    except Exception as exc:
        logger.error("Failed to query MongoDB for merchant webhook (%s): %s", merchant_id, exc)
        return None


def efgh_send_webhook_request(url: str, event_data: Dict[str, Any]) -> int:
    """Dispatches event payload to webhook URL with exponential backoff retries.

    Args:
        url: Webhook destination address.
        event_data: Event payload dictionary.

    Returns:
        HTTP response status code of the final attempt.
    """
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Nexis-PartnerWebhookDispatcher/1.0",
    }
    max_retries = 3
    delay = 1.0

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(url, json=event_data, headers=headers, timeout=5)
            if resp.status_code in (200, 201, 202, 204):
                return resp.status_code
            logger.warning(
                "Attempt %d/%d to %s yielded status %d: %s",
                attempt,
                max_retries,
                url,
                resp.status_code,
                resp.text,
            )
        except requests.RequestException as exc:
            logger.warning("Attempt %d/%d failed to %s: %s", attempt, max_retries, url, exc)

        if attempt < max_retries:
            time.sleep(delay)
            delay *= 2.0

    return 500


def efgh_log_delivery_attempt(merchant_id: str, status_code: int) -> None:
    """Logs the result of a webhook delivery attempt in MongoDB.

    Args:
        merchant_id: Identifier of the merchant.
        status_code: Returned HTTP status code.
    """
    try:
        db = _get_mongo_db()
        record = {
            "merchant_id": merchant_id,
            "status_code": status_code,
            "success": status_code in (200, 201, 202, 204),
            "timestamp": datetime.datetime.now(datetime.timezone.utc),
        }
        db["delivery_logs"].insert_one(record)
    except Exception as exc:
        logger.error("Failed to record delivery attempt in MongoDB for %s: %s", merchant_id, exc)


def ijkl_publish_event_to_merchant(merchant_id: str, event: Dict[str, Any]) -> bool:
    """Coordinates resolution of merchant endpoint, retry dispatch, and attempt logging.

    Args:
        merchant_id: Identifier of the target partner.
        event: Event details dictionary.

    Returns:
        True if the event was delivered successfully, False otherwise.
    """
    url = abcd_fetch_merchant_webhook_url(merchant_id)
    if not url:
        efgh_log_delivery_attempt(merchant_id, 404)
        return False

    status_code = efgh_send_webhook_request(url, event)
    efgh_log_delivery_attempt(merchant_id, status_code)
    return status_code in (200, 201, 202, 204)


def mnop_notify_merchant_order_complete(order: Dict[str, Any]) -> bool:
    """Convenience entrypoint to notify merchant of an ORDER_COMPLETED event.

    Args:
        order: Order and payment metadata dictionary.

    Returns:
        True if webhook notification was successful, False otherwise.
    """
    merchant_id = str(order.get("merchant_id", ""))
    event_payload = {
        "event_type": "ORDER_COMPLETED",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "data": order,
    }
    return ijkl_publish_event_to_merchant(merchant_id, event_payload)
