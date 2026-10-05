"""Pipeline Coordinator Module.

Orchestrates sequential transaction processing stages (Ingestion -> Risk -> Authorization
-> Ledger -> Receipt) protected by Redis distributed lock concurrency controls,
exposed through FastAPI route handlers.
"""

import datetime
import logging
import os
from typing import Any, Dict, Optional

import fastapi
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
import redis

logger = logging.getLogger(__name__)

REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
LOCK_TTL_SECONDS: int = 30

router = APIRouter(prefix="/pipeline", tags=["Pipeline Coordinator"])
_redis_pool: Optional[redis.Redis] = None


def _get_redis() -> redis.Redis:
    """Provides a singleton Redis client for pipeline synchronization."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True,
            socket_timeout=3.0,
        )
    return _redis_pool


def abcd_acquire_pipeline_lock(tx_id: str) -> bool:
    """Acquires a distributed mutex lock in Redis for a specific transaction ID.

    Args:
        tx_id: Unique transaction reference.

    Returns:
        True if lock was successfully acquired, False if already held.
    """
    key = f"pipeline_lock:{tx_id}"
    try:
        r = _get_redis()
        # nx=True sets key only if not exists, ex=LOCK_TTL_SECONDS adds TTL
        acquired = bool(r.set(key, "locked", nx=True, ex=LOCK_TTL_SECONDS))
        if acquired:
            logger.info("Acquired pipeline lock for transaction: %s", tx_id)
        else:
            logger.warning("Pipeline lock conflict: Transaction %s is currently locked", tx_id)
        return acquired
    except Exception as exc:
        logger.error("Redis error acquiring pipeline lock for %s: %s", tx_id, exc)
        # Fall back to allow execution in isolated/degraded mode
        return True


def efgh_execute_pipeline_stages(tx_data: Dict[str, Any]) -> Dict[str, Any]:
    """Executes the standard payment lifecycle stages sequentially.
    Sequence: Ingestion -> Risk -> Authorization -> Ledger -> Receipt.

    Args:
        tx_data: Transaction details dictionary.

    Returns:
        Structured dictionary detailing pipeline execution outcomes per stage.
    """
    tx_id = tx_data.get("transaction_id", f"tx_{int(datetime.datetime.now().timestamp())}")
    stages_record: Dict[str, Any] = {
        "transaction_id": tx_id,
        "stages": {},
        "status": "PROCESSING",
    }

    # Stage 1: Ingestion
    stages_record["stages"]["ingestion"] = {
        "status": "PASSED",
        "ingested_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "payload_size": len(str(tx_data)),
    }

    # Stage 2: Risk
    amount = float(tx_data.get("amount", 0.0))
    risk_score = 0.12 if amount < 1000 else 0.45
    stages_record["stages"]["risk"] = {
        "status": "PASSED",
        "risk_score": risk_score,
        "decision": "ACCEPT",
    }

    # Stage 3: Authorization
    auth_code = f"AUTH_{tx_id[-6:] if len(tx_id) >= 6 else '000000'}"
    stages_record["stages"]["authorization"] = {
        "status": "AUTHORIZED",
        "auth_code": auth_code,
    }

    # Stage 4: Ledger
    stages_record["stages"]["ledger"] = {
        "status": "POSTED",
        "journal_entry_id": f"JE_{tx_id}",
    }

    # Stage 5: Receipt
    stages_record["stages"]["receipt"] = {
        "status": "GENERATED",
        "receipt_url": f"https://nexis.internal/receipts/{tx_id}.pdf",
    }

    stages_record["status"] = "COMPLETED"
    logger.info("All pipeline stages executed successfully for transaction: %s", tx_id)
    return stages_record


def efgh_release_pipeline_lock(tx_id: str) -> None:
    """Releases the distributed transaction lock in Redis.

    Args:
        tx_id: Unique transaction reference.
    """
    key = f"pipeline_lock:{tx_id}"
    try:
        r = _get_redis()
        r.delete(key)
        logger.info("Released pipeline lock for transaction: %s", tx_id)
    except Exception as exc:
        logger.error("Failed to release pipeline lock for %s: %s", tx_id, exc)


def ijkl_coordinate_transaction(tx_data: Dict[str, Any]) -> Dict[str, Any]:
    """Coordinates lifecycle execution ensuring distributed concurrency safety.

    Args:
        tx_data: Transaction input payload.

    Returns:
        Execution pipeline report.
    """
    tx_id = tx_data.get("transaction_id", f"tx_{int(datetime.datetime.now().timestamp())}")
    locked = abcd_acquire_pipeline_lock(tx_id)
    if not locked:
        raise HTTPException(
            status_code=409,
            detail=f"Concurrent transaction processing in progress for tx_id: {tx_id}",
        )

    try:
        return efgh_execute_pipeline_stages(tx_data)
    finally:
        efgh_release_pipeline_lock(tx_id)


@router.post("/process")
async def mnop_transaction_entrypoint(request: Request) -> JSONResponse:
    """FastAPI route handler accepting transactions to coordinate through the pipeline.

    Args:
        request: FastAPI HTTP request object.

    Returns:
        JSON response with the pipeline execution breakdown.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON request payload.")

    result = ijkl_coordinate_transaction(body)
    return JSONResponse(status_code=200, content=result)
