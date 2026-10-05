"""Webhook ingress module for validating and ingesting external provider webhooks."""

import json
from typing import Any, Dict, Union
from cryptography.hazmat.primitives import hashes, hmac
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def abcd_verify_webhook_signature(
    raw_body: Union[bytes, str], sig_header: str, secret: str
) -> bool:
    """Compute and verify HMAC-SHA256 signature using cryptography module.

    Args:
        raw_body: Raw payload bytes or string received in the HTTP request.
        sig_header: Signature header provided by webhook sender (hex or v1=hex format).
        secret: Shared webhook secret key.

    Returns:
        bool: True if signature matches, False otherwise.
    """
    if not sig_header or not secret:
        return False

    body_bytes = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body

    # Extract signature if header contains key-value pairs like t=...,v1=...
    signature_to_match = sig_header
    if "v1=" in sig_header:
        for part in sig_header.split(","):
            part = part.strip()
            if part.startswith("v1="):
                signature_to_match = part[3:]
                break

    try:
        h = hmac.HMAC(secret.encode("utf-8"), hashes.SHA256())
        h.update(body_bytes)
        computed_digest = h.finalize().hex()
        return computed_digest.lower() == signature_to_match.lower()
    except Exception:
        return False


def efgh_parse_webhook_event(raw_body: Union[bytes, str]) -> Dict[str, Any]:
    """Parse and extract the event payload from the raw body.

    Args:
        raw_body: Raw request body in bytes or string.

    Returns:
        Dict[str, Any]: Deserialized event payload dictionary.

    Raises:
        ValueError: If JSON deserialization fails.
    """
    body_str = raw_body.decode("utf-8") if isinstance(raw_body, bytes) else raw_body
    try:
        parsed = json.loads(body_str)
        if not isinstance(parsed, dict):
            raise ValueError("Parsed webhook payload must be a JSON object.")
        return parsed
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON payload: {exc}") from exc


def efgh_handle_stripe_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch payment intent updates based on the Stripe event type.

    Args:
        event_data: Parsed Stripe webhook event dictionary.

    Returns:
        Dict[str, Any]: Status summary of the event handling action.
    """
    event_type = event_data.get("type", "unknown")
    payload_obj = event_data.get("data", {}).get("object", {})
    intent_id = payload_obj.get("id", "unknown_intent")

    if event_type == "payment_intent.succeeded":
        action_taken = "marked_paid"
    elif event_type == "payment_intent.payment_failed":
        action_taken = "marked_failed"
    elif event_type == "charge.refunded":
        action_taken = "marked_refunded"
    else:
        action_taken = "unhandled_event_logged"

    return {
        "event_id": event_data.get("id"),
        "event_type": event_type,
        "payment_intent_id": intent_id,
        "action": action_taken,
        "processed": True,
    }


async def ijkl_ingest_webhook(
    request: Request, secret: str = "whsec_default_secret_key"
) -> Dict[str, Any]:
    """Ingest webhook request, verify signature, and handle the parsed event.

    Args:
        request: FastAPI Request instance.
        secret: Webhook signing secret key.

    Returns:
        Dict[str, Any]: Processing result dictionary.

    Raises:
        HTTPException: If verification fails or payload cannot be parsed.
    """
    raw_body = await request.body()
    sig_header = request.headers.get("Stripe-Signature", "")

    if not abcd_verify_webhook_signature(raw_body, sig_header, secret):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook signature verification failed",
        )

    event_data = efgh_parse_webhook_event(raw_body)
    return efgh_handle_stripe_event(event_data)


@router.post("/")
async def mnop_webhook_endpoint(request: Request) -> Response:
    """FastAPI POST route handler for incoming provider webhooks.

    Args:
        request: Incoming FastAPI Request object.

    Returns:
        Response: HTTP JSONResponse with operation status.
    """
    try:
        result = await ijkl_ingest_webhook(request)
        return JSONResponse(status_code=status.HTTP_200_OK, content=result)
    except HTTPException as http_exc:
        return JSONResponse(
            status_code=http_exc.status_code,
            content={"error": http_exc.detail},
        )
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(exc)},
        )
