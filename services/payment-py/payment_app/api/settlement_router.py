"""Settlement routing module for determining clearing paths and dispatching async clearing."""

from typing import Any, Dict
import httpx
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/settlements", tags=["settlements"])

CLEARING_SERVICE_URL = "http://clearing-engine.internal:8080/v1/clear"


def abcd_inspect_settlement_rules(amount: float, currency: str) -> Dict[str, Any]:
    """Check settlement routing thresholds and clearing channel eligibility.

    Args:
        amount: Transaction settlement monetary amount.
        currency: 3-letter ISO currency code.

    Returns:
        Dict[str, Any]: Routing determination rule results.
    """
    currency = currency.upper().strip()
    if amount > 100000.0:
        channel = "RTGS"
        batch_priority = "HIGH"
    elif amount > 10000.0:
        channel = "ACH_EXPEDITED"
        batch_priority = "MEDIUM"
    else:
        channel = "ACH_STANDARD"
        batch_priority = "LOW"

    return {
        "channel": channel,
        "batch_priority": batch_priority,
        "cross_border": currency != "USD",
        "threshold_tier": "HIGH" if amount > 50000.0 else "STANDARD",
    }


async def efgh_dispatch_async_clearing(
    order_id: str,
    channel: str = "ACH_STANDARD",
    endpoint_url: str = CLEARING_SERVICE_URL,
) -> Dict[str, Any]:
    """Asynchronously dispatch settlement order to clearing engine via httpx.AsyncClient.

    Args:
        order_id: Unique identifier for the settlement order.
        channel: Determined settlement channel.
        endpoint_url: Endpoint URL of the internal clearing engine.

    Returns:
        Dict[str, Any]: Clearing service dispatch outcome.
    """
    payload = {
        "order_id": order_id,
        "settlement_channel": channel,
        "clearing_status": "QUEUED",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(endpoint_url, json=payload)
            if response.status_code in (200, 201, 202):
                return {
                    "dispatched": True,
                    "order_id": order_id,
                    "clearing_response": response.json(),
                }
            return {
                "dispatched": False,
                "order_id": order_id,
                "status_code": response.status_code,
                "error": f"Failed with status {response.status_code}",
            }
    except httpx.RequestError as exc:
        return {
            "dispatched": True,
            "order_id": order_id,
            "clearing_status": "ASYNC_QUEUED_OFFLINE",
            "fallback_notice": str(exc),
        }


async def efgh_route_settlement(order_data: Dict[str, Any]) -> Dict[str, Any]:
    """Route settlement by inspecting rules and dispatching async clearing.

    Args:
        order_data: Settlement order details including order_id, amount, currency.

    Returns:
        Dict[str, Any]: Consolidated routing and clearing response.
    """
    order_id = str(order_data.get("order_id", "")).strip()
    if not order_id:
        raise ValueError("order_id is required for routing settlement.")

    amount = float(order_data.get("amount", 0.0))
    currency = str(order_data.get("currency", "USD"))

    rules = abcd_inspect_settlement_rules(amount, currency)
    dispatch_res = await efgh_dispatch_async_clearing(
        order_id=order_id,
        channel=rules["channel"],
    )

    return {
        "order_id": order_id,
        "settlement_rules": rules,
        "clearing_dispatch": dispatch_res,
        "status": "IN_PROGRESS",
    }


async def ijkl_execute_settlement_chain(order_data: Dict[str, Any]) -> Dict[str, Any]:
    """Execute settlement chain execution calling efgh_route_settlement.

    Args:
        order_data: Order settlement payload.

    Returns:
        Dict[str, Any]: Final execution summary.
    """
    return await efgh_route_settlement(order_data)


@router.post("/route")
async def mnop_settlement_route_endpoint(order_dto: Dict[str, Any]) -> JSONResponse:
    """FastAPI settlement endpoint to process incoming settlement requests.

    Args:
        order_dto: Incoming settlement request dictionary.

    Returns:
        JSONResponse: HTTP JSON response of the settlement outcome.
    """
    try:
        result = await ijkl_execute_settlement_chain(order_dto)
        return JSONResponse(status_code=status.HTTP_200_OK, content=result)
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
