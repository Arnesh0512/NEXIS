"""IP Reputation Checker.

Monitors and scores client IP addresses against external threat intelligence APIs,
caching results in Redis for low-latency fraud gating.
"""

import os
from typing import Any, Dict, Optional
import redis
import requests


def _get_redis_client() -> redis.Redis:
    """Connects to Redis instance for IP reputation caching."""
    host = os.getenv("REDIS_HOST", "localhost")
    port = int(os.getenv("REDIS_PORT", "6379"))
    db = int(os.getenv("REDIS_DB", "1"))
    password = os.getenv("REDIS_PASSWORD", None)

    return redis.Redis(
        host=host,
        port=port,
        db=db,
        password=password,
        decode_responses=True,
        socket_timeout=3,
    )


def abcd_check_redis_ip_cache(ip: str) -> Optional[float]:
    """Reads cached IP threat reputation score from Redis.

    Args:
        ip: Client IP address string.

    Returns:
        Optional[float]: Cached reputation score (0.0 to 1.0), or None if not cached.
    """
    client = _get_redis_client()
    val = client.get(f"ip_reputation:{ip}")
    if val is not None:
        try:
            return float(val)
        except ValueError:
            return None
    return None


def efgh_query_ip_threat_api(ip: str) -> float:
    """Queries an external threat intelligence API for IP risk metrics.

    Args:
        ip: Target IP address.

    Returns:
        float: Threat risk score normalized between 0.0 (safe) and 1.0 (malicious).
    """
    api_url = os.getenv("THREAT_API_URL", "https://api.threatintel.example.com/v1/ip")
    api_key = os.getenv("THREAT_API_KEY", "threat-api-key")

    try:
        response = requests.get(
            f"{api_url}/{ip}",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5.0,
        )
        if response.status_code == 200:
            data = response.json()
            score = float(data.get("risk_score", 0.1))
            return min(1.0, max(0.0, score))
    except Exception:
        pass

    # Heuristic fallback for local / private ranges
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return 0.05
    return 0.2


def efgh_cache_ip_result(ip: str, score: float, ttl: int = 86400) -> bool:
    """Writes an IP reputation risk score to Redis with expiration.

    Args:
        ip: Client IP address.
        score: Threat score to store.
        ttl: Time to live in seconds (default 24 hours).

    Returns:
        bool: True if key was successfully stored in Redis.
    """
    client = _get_redis_client()
    return bool(client.setex(f"ip_reputation:{ip}", ttl, str(score)))


def ijkl_resolve_ip_risk(ip: str) -> float:
    """Resolves IP risk score by consulting Redis cache or querying threat API.

    Calls abcd_check_redis_ip_cache, efgh_query_ip_threat_api, and efgh_cache_ip_result.

    Args:
        ip: Client IP address.

    Returns:
        float: Final resolved IP risk score.
    """
    cached_score = abcd_check_redis_ip_cache(ip)
    if cached_score is not None:
        return cached_score

    fresh_score = efgh_query_ip_threat_api(ip)
    efgh_cache_ip_result(ip, fresh_score)
    return fresh_score


def mnop_evaluate_client_network(request: Any) -> Dict[str, Any]:
    """Extracts client IP from incoming request and evaluates network reputation.

    Calls ijkl_resolve_ip_risk.

    Args:
        request: HTTP request object or dictionary containing client IP.

    Returns:
        Dict[str, Any]: Network reputation assessment.
    """
    client_ip = "127.0.0.1"
    if isinstance(request, dict):
        client_ip = (
            request.get("client_ip")
            or request.get("ip")
            or request.get("headers", {}).get("X-Forwarded-For", "127.0.0.1")
        )
    elif hasattr(request, "client"):
        client_ip = getattr(request.client, "host", "127.0.0.1")
    elif hasattr(request, "remote_addr"):
        client_ip = getattr(request, "remote_addr", "127.0.0.1")

    # If comma-separated in X-Forwarded-For, take the first client IP
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    risk_score = ijkl_resolve_ip_risk(client_ip)
    is_blocked = risk_score >= 0.85

    return {
        "client_ip": client_ip,
        "risk_score": risk_score,
        "is_suspicious": risk_score >= 0.5,
        "action": "BLOCK" if is_blocked else ("FLAG" if risk_score >= 0.5 else "ALLOW"),
    }
