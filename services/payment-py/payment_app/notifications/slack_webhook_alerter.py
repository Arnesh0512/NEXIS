"""Slack Webhook Alerter Module.

Handles security incident alerting to Slack channels, featuring HMAC-SHA256 payload
signing with cryptography and structured Slack Block Kit message formatting.
"""

import json
import logging
import os
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes, hmac
import requests

logger = logging.getLogger(__name__)

SLACK_SECURITY_WEBHOOK_URL: str = os.getenv(
    "SLACK_SECURITY_WEBHOOK_URL",
    "https://slack-mock.internal.nexis/services/alerts",
)
SLACK_SIGNING_SECRET: str = os.getenv("SLACK_SIGNING_SECRET", "nexis-slack-signing-secret-key")


def abcd_sign_slack_payload(payload: str, secret: str) -> str:
    """Computes an HMAC-SHA256 hex digest signature using cryptography primitives.

    Args:
        payload: Serialized string payload to sign.
        secret: Secret signing key.

    Returns:
        Hexadecimal HMAC-SHA256 signature string.
    """
    h = hmac.HMAC(secret.encode("utf-8"), hashes.SHA256())
    h.update(payload.encode("utf-8"))
    return h.finalize().hex()


def efgh_post_slack_webhook(channel_url: str, payload: Dict[str, Any], sig: str) -> bool:
    """Dispatches a signed alert to a Slack incoming webhook endpoint via requests.post.

    Args:
        channel_url: Target Slack webhook URL.
        payload: Block Kit or message dictionary payload.
        sig: HMAC-SHA256 hex signature.

    Returns:
        True if accepted by Slack (HTTP 200), False otherwise.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Slack-Signature": f"v0={sig}",
        "User-Agent": "Nexis-SlackAlerter/1.0",
    }
    try:
        response = requests.post(
            channel_url,
            json=payload,
            headers=headers,
            timeout=10,
        )
        if response.status_code == 200:
            logger.info("Successfully posted security alert to Slack channel.")
            return True
        logger.warning(
            "Slack webhook returned non-200 code [%d]: %s",
            response.status_code,
            response.text,
        )
        return False
    except requests.RequestException as exc:
        logger.error("Error communicating with Slack webhook: %s", exc)
        return False


def efgh_format_incident_card(title: str, severity: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """Formats an incident payload conforming to Slack Block Kit schema.

    Args:
        title: Short incident summary.
        severity: Severity indicator ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        details: Dictionary of pertinent incident attributes.

    Returns:
        Dictionary formatted for Slack incoming webhooks.
    """
    color = "#36a64f"
    if severity.upper() == "CRITICAL":
        color = "#e01e5a"
    elif severity.upper() == "HIGH":
        color = "#ecb22e"
    elif severity.upper() == "MEDIUM":
        color = "#2eb886"

    fields = [
        {"title": k, "value": str(v), "short": True}
        for k, v in details.items()
    ]

    card: Dict[str, Any] = {
        "text": f"[{severity.upper()}] {title}",
        "attachments": [
            {
                "fallback": f"[{severity.upper()}] {title}",
                "color": color,
                "title": title,
                "fields": fields,
                "footer": "Nexis Payment Security Alert System",
                "ts": int(details.get("timestamp", 0)) if "timestamp" in details else None,
            }
        ],
    }
    return card


def ijkl_alert_security_team(incident: Dict[str, Any]) -> bool:
    """Constructs, cryptographically signs, and posts a security incident card to Slack.

    Args:
        incident: Incident metadata dictionary containing title, severity, and details.

    Returns:
        True if delivered to Slack, False otherwise.
    """
    title = incident.get("title", "Security Notification")
    severity = incident.get("severity", "MEDIUM")
    details = incident.get("details", incident)

    card_payload = efgh_format_incident_card(title=title, severity=severity, details=details)
    serialized = json.dumps(card_payload, sort_keys=True)
    signature = abcd_sign_slack_payload(serialized, SLACK_SIGNING_SECRET)

    return efgh_post_slack_webhook(
        channel_url=SLACK_SECURITY_WEBHOOK_URL,
        payload=card_payload,
        sig=signature,
    )


def mnop_broadcast_critical_event(error_obj: Dict[str, Any]) -> bool:
    """Dispatches a top-level broadcast for critical platform errors.

    Args:
        error_obj: Error details including exception message, stage, and trace.

    Returns:
        True if successfully broadcast to security channel, False otherwise.
    """
    incident_data = {
        "title": error_obj.get("title", "Critical Payment Platform Error"),
        "severity": "CRITICAL",
        "details": error_obj,
    }
    return ijkl_alert_security_team(incident_data)
