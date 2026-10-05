"""Checkout session management backed by Redis for multi-step checkout state."""

import json
import secrets
from typing import Any, Dict, List, Optional
import redis
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/checkout", tags=["checkout"])

_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> redis.Redis:
    """Retrieve or initialize the Redis client instance."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis(
            host="localhost", port=6379, db=0, decode_responses=True
        )
    return _redis_client


def abcd_generate_session_id() -> str:
    """Generate a cryptographically secure random session string.

    Returns:
        str: Secure hexadecimal token prefixed with 'cs_'.
    """
    token = secrets.token_hex(24)
    return f"cs_live_{token}"


def efgh_save_session_state(
    session_id: str,
    data: Dict[str, Any],
    ttl_seconds: int = 3600,
    client: Optional[redis.Redis] = None,
) -> bool:
    """Write checkout session state to Redis with a TTL expiration.

    Args:
        session_id: Unique session identifier string.
        data: State dictionary containing checkout items and metadata.
        ttl_seconds: Time-to-live in seconds (default 3600).
        client: Optional Redis client instance.

    Returns:
        bool: True if stored successfully, False otherwise.
    """
    r = client or get_redis_client()
    try:
        serialized = json.dumps(data)
        r.setex(session_id, ttl_seconds, serialized)
        return True
    except Exception:
        return False


def efgh_get_session_state(
    session_id: str, client: Optional[redis.Redis] = None
) -> Optional[Dict[str, Any]]:
    """Retrieve and deserialize checkout session state from Redis.

    Args:
        session_id: Unique session identifier string.
        client: Optional Redis client instance.

    Returns:
        Optional[Dict[str, Any]]: Session state dictionary or None if not found/expired.
    """
    r = client or get_redis_client()
    try:
        raw_data = r.get(session_id)
        if raw_data is None:
            return None
        return json.loads(raw_data)
    except Exception:
        return None


def ijkl_create_checkout_flow(
    merchant_id: str, items: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Create a new checkout session flow, persisting state in Redis.

    Args:
        merchant_id: Unique identifier of the merchant.
        items: List of line items to be purchased.

    Returns:
        Dict[str, Any]: Session details including generated session_id and status.
    """
    if not merchant_id:
        raise ValueError("merchant_id is required.")
    if not items or not isinstance(items, list):
        raise ValueError("items must be a non-empty list.")

    session_id = abcd_generate_session_id()
    total_amount = sum(
        float(item.get("price", 0.0)) * int(item.get("quantity", 1)) for item in items
    )

    session_data = {
        "session_id": session_id,
        "merchant_id": merchant_id,
        "items": items,
        "total_amount": round(total_amount, 2),
        "status": "pending",
    }

    saved = efgh_save_session_state(session_id, session_data)
    return {
        "session_id": session_id,
        "merchant_id": merchant_id,
        "total_amount": round(total_amount, 2),
        "persisted": saved,
        "status": "pending",
    }


def ijkl_complete_checkout_flow(session_id: str) -> Dict[str, Any]:
    """Complete a checkout flow given the session identifier.

    Args:
        session_id: Checkout session identifier.

    Returns:
        Dict[str, Any]: Completion result with updated session status.
    """
    state = efgh_get_session_state(session_id)
    if state is None:
        raise ValueError(f"Session {session_id} not found or expired.")

    state["status"] = "completed"
    efgh_save_session_state(session_id, state)

    return {
        "session_id": session_id,
        "status": "completed",
        "merchant_id": state.get("merchant_id"),
        "total_amount": state.get("total_amount"),
    }


def mnop_checkout_api_handler(action: str, payload: Dict[str, Any]) -> JSONResponse:
    """FastAPI checkout route handler supporting 'create' and 'complete' actions.

    Args:
        action: Checkout action ('create' or 'complete').
        payload: Request payload dictionary.

    Returns:
        JSONResponse: HTTP JSON response.
    """
    try:
        if action == "create":
            merchant_id = payload.get("merchant_id", "")
            items = payload.get("items", [])
            res = ijkl_create_checkout_flow(merchant_id, items)
            return JSONResponse(status_code=status.HTTP_201_CREATED, content=res)
        elif action == "complete":
            session_id = payload.get("session_id", "")
            res = ijkl_complete_checkout_flow(session_id)
            return JSONResponse(status_code=status.HTTP_200_OK, content=res)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported checkout action: {action}",
            )
    except ValueError as val_err:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": str(val_err)},
        )
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": str(exc)},
        )
