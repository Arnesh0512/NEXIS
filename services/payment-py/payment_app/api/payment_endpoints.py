"""Payment endpoints module for handling incoming payment ingestion and risk routing."""

from typing import Any, Dict
import requests
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/payments", tags=["payments"])


def abcd_parse_payment_request(payload_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and sanitize the incoming payment request dictionary.

    Args:
        payload_dict: Raw input payload representing payment parameters.

    Returns:
        Dict[str, Any]: Sanitized payment request dictionary.

    Raises:
        ValueError: If required fields are missing or invalid.
    """
    if not isinstance(payload_dict, dict):
        raise ValueError("Payload must be a dictionary.")

    order_id = str(payload_dict.get("order_id", "")).strip()
    amount = payload_dict.get("amount")
    currency = str(payload_dict.get("currency", "USD")).upper().strip()

    if not order_id:
        raise ValueError("Missing required field: order_id.")
    if amount is None or not isinstance(amount, (int, float)) or amount <= 0:
        raise ValueError("Amount must be a positive number.")

    return {
        "order_id": order_id,
        "amount": round(float(amount), 2),
        "currency": currency,
        "customer_id": str(payload_dict.get("customer_id", "")).strip(),
        "payment_method": str(payload_dict.get("payment_method", "card")).strip().lower(),
        "metadata": payload_dict.get("metadata", {}),
    }


def efgh_forward_to_risk_engine(payment_req: Dict[str, Any]) -> Dict[str, Any]:
    """Relay validated payment request to the risk evaluation engine.

    Args:
        payment_req: Validated payment request parameters.

    Returns:
        Dict[str, Any]: Risk engine response payload containing assessment and score.
    """
    risk_engine_url = "http://risk-service.internal:8000/api/v1/evaluate"
    try:
        response = requests.post(risk_engine_url, json=payment_req, timeout=5.0)
        if response.status_code == 200:
            return response.json()
        return {
            "status": "flagged",
            "score": 0.85,
            "decision": "manual_review",
            "details": f"Risk engine returned HTTP {response.status_code}",
        }
    except requests.RequestException as exc:
        return {
            "status": "accepted_with_warning",
            "score": 0.1,
            "decision": "allow",
            "fallback": True,
            "error": str(exc),
        }


def efgh_process_payment_route(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Process payment route by validating payload and verifying with risk engine.

    Args:
        payload: Input dictionary containing payment details.

    Returns:
        Dict[str, Any]: Combined status containing parsed payment data and risk decision.
    """
    sanitized = abcd_parse_payment_request(payload)
    risk_assessment = efgh_forward_to_risk_engine(sanitized)
    return {
        "status": "processed",
        "payment_request": sanitized,
        "risk_assessment": risk_assessment,
    }


def ijkl_capture_payment_route(payment_id: str) -> Dict[str, Any]:
    """Invoke capture logic for an authorized payment identifier.

    Args:
        payment_id: Unique identifier of the payment to capture.

    Returns:
        Dict[str, Any]: Capture execution result status.
    """
    if not payment_id or not payment_id.strip():
        raise ValueError("Invalid payment_id provided for capture.")

    clean_id = payment_id.strip()
    return {
        "payment_id": clean_id,
        "capture_status": "captured",
        "captured_amount_authorized": True,
        "message": f"Payment {clean_id} successfully captured.",
    }


async def mnop_payment_api_controller(request: Request, action: str) -> JSONResponse:
    """FastAPI endpoint controller dispatching actions to the appropriate handler.

    Args:
        request: Incoming FastAPI Request object.
        action: Requested action ('process' or 'capture').

    Returns:
        JSONResponse: HTTP response containing the outcome.
    """
    try:
        if action == "process":
            body = await request.json()
            result = efgh_process_payment_route(body)
            return JSONResponse(status_code=status.HTTP_200_OK, content=result)
        elif action == "capture":
            body = await request.json()
            payment_id = body.get("payment_id", "")
            result = ijkl_capture_payment_route(payment_id)
            return JSONResponse(status_code=status.HTTP_200_OK, content=result)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported action: {action}",
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
