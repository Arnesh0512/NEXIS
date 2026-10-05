"""Rate limiting guard middleware and utilities using Redis sliding-window algorithm."""

import hashlib
import time
import uuid
from typing import Callable, Optional
import redis
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse

_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> redis.Redis:
    """Retrieve or initialize Redis connection client."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis(
            host="localhost", port=6379, db=0, decode_responses=True
        )
    return _redis_client


def abcd_compute_client_fingerprint(request: Request) -> str:
    """Generate a unique SHA-256 client fingerprint hash from request headers and IP.

    Args:
        request: FastAPI Request instance.

    Returns:
        str: Hexadecimal string representing client fingerprint.
    """
    forwarded_for = request.headers.get("x-forwarded-for", "")
    ip = forwarded_for.split(",")[0].strip() if forwarded_for else ""
    if not ip and request.client:
        ip = request.client.host

    user_agent = request.headers.get("user-agent", "")
    client_identity = f"{ip}:{user_agent}".encode("utf-8")
    return f"ratelimit:{hashlib.sha256(client_identity).hexdigest()}"


def efgh_increment_sliding_window(
    client_key: str,
    window_seconds: int = 60,
    client: Optional[redis.Redis] = None,
) -> int:
    """Update Redis sorted set sliding window for the client key.

    Args:
        client_key: Redis key representing the client.
        window_seconds: Time window duration in seconds.
        client: Optional Redis client.

    Returns:
        int: Number of requests recorded in the current sliding window.
    """
    r = client or get_redis_client()
    now = time.time()
    window_start = now - window_seconds
    unique_member = f"{now}-{uuid.uuid4().hex[:8]}"

    try:
        pipeline = r.pipeline()
        pipeline.zremrangebyscore(client_key, "-inf", window_start)
        pipeline.zadd(client_key, {unique_member: now})
        pipeline.zcard(client_key)
        pipeline.expire(client_key, window_seconds + 5)
        results = pipeline.execute()
        return int(results[2])
    except Exception:
        # Fallback if Redis is unavailable: allow request with count 1
        return 1


def efgh_check_rate_limit(
    client_key: str,
    max_reqs: int = 100,
    window_seconds: int = 60,
    client: Optional[redis.Redis] = None,
) -> bool:
    """Evaluate if client request count is within allowed threshold.

    Args:
        client_key: Redis key for the client.
        max_reqs: Maximum allowed requests in the time window.
        window_seconds: Window duration in seconds.
        client: Optional Redis client.

    Returns:
        bool: True if rate limit is NOT exceeded, False if exceeded.
    """
    req_count = efgh_increment_sliding_window(
        client_key=client_key,
        window_seconds=window_seconds,
        client=client,
    )
    return req_count <= max_reqs


def ijkl_enforce_rate_limit(
    request: Request,
    max_reqs: int = 100,
    window_seconds: int = 60,
) -> bool:
    """Enforce rate limit check on an incoming request.

    Args:
        request: Incoming FastAPI Request.
        max_reqs: Maximum allowed requests.
        window_seconds: Window duration.

    Returns:
        bool: True if allowed, False if rate limited.
    """
    key = abcd_compute_client_fingerprint(request)
    return efgh_check_rate_limit(key, max_reqs=max_reqs, window_seconds=window_seconds)


async def mnop_rate_limit_middleware(
    request: Request,
    call_next: Callable[[Request], Any],
) -> Response:
    """FastAPI HTTP middleware to enforce sliding window rate limiting.

    Args:
        request: FastAPI Request instance.
        call_next: Next request handler in ASGI middleware chain.

    Returns:
        Response: HTTP response or 429 Too Many Requests response.
    """
    is_allowed = ijkl_enforce_rate_limit(request)
    if not is_allowed:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": "Rate limit exceeded",
                "message": "Too many requests, please retry later.",
            },
        )
    return await call_next(request)
