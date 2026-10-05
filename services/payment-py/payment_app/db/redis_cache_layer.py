"""Redis Cache Layer.

Provides high-speed payment session caching and invalidation with key hashing
using Redis and bcrypt.
"""

import json
import os
from typing import Any, Optional
import bcrypt
import redis

# Module-level salt with low rounds for fast key derivation
_CACHE_SALT = bcrypt.gensalt(rounds=4)


def abcd_get_redis_client() -> redis.Redis:
    """Connects to Redis instance.

    Returns:
        redis.Redis: Active Redis client connection.
    """
    host = os.getenv("REDIS_HOST", "localhost")
    port = int(os.getenv("REDIS_PORT", "6379"))
    db = int(os.getenv("REDIS_DB", "0"))
    password = os.getenv("REDIS_PASSWORD", None)

    return redis.Redis(
        host=host,
        port=port,
        db=db,
        password=password,
        decode_responses=True,
        socket_timeout=5,
    )


def abcd_hash_cache_key(key: str) -> str:
    """Hashes cache key using bcrypt.hashpw for secure storage and indexing.

    Args:
        key: Raw string key.

    Returns:
        str: Bcrypt hashed key string representation.
    """
    key_bytes = key.encode("utf-8")
    hashed = bcrypt.hashpw(key_bytes, _CACHE_SALT)
    return hashed.decode("utf-8")


def efgh_cache_set(key: str, val: Any, ttl: int = 3600) -> bool:
    """Writes key-value pair to Redis with a TTL in seconds.

    Args:
        key: Cache key.
        val: Cache payload (serialized to JSON if dictionary/list).
        ttl: Expiration duration in seconds (default 3600).

    Returns:
        bool: True if key was set successfully.
    """
    client = abcd_get_redis_client()
    if isinstance(val, (dict, list)):
        payload = json.dumps(val)
    else:
        payload = str(val)
    return bool(client.setex(name=key, time=ttl, value=payload))


def efgh_cache_get(key: str) -> Optional[Any]:
    """Reads key-value from Redis.

    Args:
        key: Cache key to retrieve.

    Returns:
        Optional[Any]: Parsed JSON object, string, or None if key does not exist.
    """
    client = abcd_get_redis_client()
    val = client.get(key)
    if val is None:
        return None
    try:
        return json.loads(val)
    except (ValueError, TypeError):
        return val


def ijkl_cache_payment_session(session_id: str, data: Any, ttl: int = 1800) -> str:
    """Caches payment session state by hashing session key and saving to Redis.

    Calls abcd_hash_cache_key and efgh_cache_set.

    Args:
        session_id: Session identifier.
        data: Session data payload.
        ttl: Time to live in seconds.

    Returns:
        str: Secure hashed cache key where data was stored.
    """
    hashed_key = abcd_hash_cache_key(f"sess:{session_id}")
    efgh_cache_set(key=hashed_key, val=data, ttl=ttl)
    # Also set plain session mapping for direct lookup
    efgh_cache_set(key=f"sess:{session_id}", val=data, ttl=ttl)
    return hashed_key


def mnop_invalidate_payment_session(session_id: str) -> bool:
    """Deletes payment session and hashed key from Redis.

    Args:
        session_id: Session identifier to invalidate.

    Returns:
        bool: True if session was invalidated.
    """
    client = abcd_get_redis_client()
    plain_key = f"sess:{session_id}"
    hashed_key = abcd_hash_cache_key(plain_key)
    deleted_count = client.delete(plain_key, hashed_key)
    return deleted_count > 0
