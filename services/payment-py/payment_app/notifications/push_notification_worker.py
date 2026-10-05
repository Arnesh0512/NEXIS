"""Push Notification Worker Module.

Handles customer mobile push notifications via Firebase Cloud Messaging (FCM),
retrieving service credentials from Google Cloud Storage and sending requests via HTTPX.
"""

import json
import logging
import os
from typing import Any, Dict

from google.cloud import storage
import httpx

logger = logging.getLogger(__name__)

GCS_CREDENTIALS_BUCKET: str = os.getenv("GCS_CREDENTIALS_BUCKET", "nexis-fcm-secrets")
GCS_CREDENTIALS_BLOB: str = os.getenv("GCS_CREDENTIALS_BLOB", "fcm-credentials.json")
FCM_V1_URL: str = os.getenv("FCM_API_URL", "https://fcm.googleapis.com/fcm/send")

_cached_credentials: Dict[str, Any] = {}


def abcd_load_fcm_credentials() -> Dict[str, Any]:
    """Loads FCM configuration credentials from a Google Cloud Storage bucket.

    Returns:
        Dictionary containing service account or FCM server authentication keys.
    """
    global _cached_credentials
    if _cached_credentials:
        return _cached_credentials

    try:
        client = storage.Client()
        bucket = client.bucket(GCS_CREDENTIALS_BUCKET)
        blob = bucket.blob(GCS_CREDENTIALS_BLOB)
        data = blob.download_as_text()
        _cached_credentials = json.loads(data)
        logger.info("Successfully loaded FCM credentials from gs://%s/%s", GCS_CREDENTIALS_BUCKET, GCS_CREDENTIALS_BLOB)
        return _cached_credentials
    except Exception as exc:
        logger.warning(
            "Unable to download FCM credentials from GCS: %s. Using environment/fallback credentials.", exc
        )
        _cached_credentials = {
            "project_id": os.getenv("FCM_PROJECT_ID", "nexis-payment-prod"),
            "server_key": os.getenv("FCM_SERVER_KEY", "default-fcm-mock-server-key"),
        }
        return _cached_credentials


def abcd_validate_device_token(fcm_token: str) -> bool:
    """Validates device FCM token syntax and minimum length constraint.

    Args:
        fcm_token: Token string to evaluate.

    Returns:
        True if token format is valid, False otherwise.
    """
    return bool(fcm_token and len(fcm_token.strip()) >= 16)


def efgh_send_fcm_message(fcm_token: str, title: str, body: str) -> bool:
    """Dispatches a push notification challenge to FCM endpoint via HTTPX.

    Args:
        fcm_token: Target device registration token.
        title: Push notification headline.
        body: Notification body text.

    Returns:
        True if FCM accepted the message (HTTP 200), False otherwise.
    """
    if not abcd_validate_device_token(fcm_token):
        logger.warning("Invalid device token format: %s", fcm_token)
        return False

    creds = abcd_load_fcm_credentials()
    server_key = creds.get("server_key", "default-fcm-mock-server-key")

    headers = {
        "Authorization": f"key={server_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "to": fcm_token,
        "notification": {
            "title": title,
            "body": body,
            "sound": "default",
        },
        "priority": "high",
    }

    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.post(FCM_V1_URL, json=payload, headers=headers)
            if resp.status_code == 200:
                logger.info("Push notification accepted by FCM for token: %s...", fcm_token[:10])
                return True
            logger.error("FCM dispatch error [%d]: %s", resp.status_code, resp.text)
            return False
    except httpx.HTTPError as exc:
        logger.error("HTTP error sending FCM push notification: %s", exc)
        return False


def ijkl_send_customer_push(user_id: str, message: str) -> bool:
    """Retrieves customer device token and dispatches push alert.

    Args:
        user_id: Identifier of the target platform customer.
        message: Notification alert content.

    Returns:
        True if push was transmitted, False otherwise.
    """
    _ = abcd_load_fcm_credentials()
    # In production, lookup user device FCM token from user directory / database
    customer_device_token = os.getenv("DEFAULT_DEVICE_FCM_TOKEN", f"token_device_{user_id}_sample")
    title = "Nexis Payment Alert"

    return efgh_send_fcm_message(
        fcm_token=customer_device_token,
        title=title,
        body=message,
    )


def mnop_push_payment_update(user_id: str, status: str) -> bool:
    """Convenience handler to notify customer about transaction status changes.

    Args:
        user_id: Customer identifier.
        status: Updated transaction status string.

    Returns:
        True if push notification was dispatched, False otherwise.
    """
    msg = f"Your transaction status has transitioned to: {status.upper()}"
    return ijkl_send_customer_push(user_id=user_id, message=msg)
