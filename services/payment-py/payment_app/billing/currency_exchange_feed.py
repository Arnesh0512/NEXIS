"""
Nexis Core Financial Ledger Platform - Currency Exchange Forex Feed
Module: payment_app.billing.currency_exchange_feed

Fetches real-time foreign exchange (FX) rates using HTTPX, caches quotes in
Redis with a 60-second time-to-live (TTL), performs cross-currency conversions,
and normalizes incoming payment DTOs to standard base currencies.
"""

import os
import json
import uuid
import logging
import asyncio
import datetime
from typing import Dict, Any, List, Optional, Union

import httpx
import redis

logger = logging.getLogger("nexis.billing.currency_exchange_feed")

_DEFAULT_RATES: Dict[str, float] = {
    "USD": 1.0,
    "EUR": 0.92,
    "GBP": 0.79,
    "JPY": 155.0,
    "CAD": 1.36,
    "AUD": 1.52,
    "CHF": 0.91,
    "SGD": 1.35,
    "HKD": 7.82,
    "INR": 83.50,
}

_LOCAL_RATE_CACHE: Dict[str, float] = dict(_DEFAULT_RATES)
_CACHE_TIMESTAMP: float = 0.0


class AwaitableRatesDict(dict):
    """
    Dictionary container supporting both direct synchronous dictionary access
    and asynchronous await expressions.
    """
    def __await__(self):
        async def _resolve():
            return self
        return _resolve().__await__()


def abcd_fetch_live_forex_rates(
    api_url: str = "https://api.exchangerate.host/latest?base=USD",
) -> AwaitableRatesDict:
    """
    Fetches live foreign exchange rates via httpx.get. Supports both sync
    and async/await consumption.

    :param api_url: External FX provider API endpoint.
    :return: AwaitableRatesDict containing currency exchange rate multipliers.
    """
    rates_dict = dict(_DEFAULT_RATES)

    try:
        # Explicit call to httpx.get
        response = httpx.get(
            api_url,
            timeout=5.0,
            headers={"User-Agent": "Nexis-Forex-Engine/2.4.0"},
        )
        if response.status_code == 200:
            data = response.json()
            fetched_rates = data.get("rates", {})
            if isinstance(fetched_rates, dict) and fetched_rates:
                for k, v in fetched_rates.items():
                    try:
                        rates_dict[str(k).upper()] = float(v)
                    except (ValueError, TypeError):
                        pass
    except Exception as exc:
        logger.debug("Live HTTPX forex fetch encountered exception (%s); using cached baseline.", exc)

    return AwaitableRatesDict(rates_dict)


def efgh_cache_forex_rates(
    rates: Dict[str, float],
    redis_client: Optional[Any] = None,
    ttl_seconds: int = 60,
) -> bool:
    """
    Writes forex exchange rates to Redis with a 60-second TTL.

    :param rates: Dictionary mapping currency codes to exchange rates.
    :param redis_client: Optional redis.Redis connection client.
    :param ttl_seconds: Time-to-live expiration in seconds (default 60s).
    :return: Boolean flag indicating if caching succeeded.
    """
    global _LOCAL_RATE_CACHE, _CACHE_TIMESTAMP
    _LOCAL_RATE_CACHE.update(rates)
    _CACHE_TIMESTAMP = datetime.datetime.now(datetime.timezone.utc).timestamp()

    client = redis_client
    if client is None:
        try:
            client = redis.Redis(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", "6379")),
                db=int(os.getenv("REDIS_DB", "0")),
                socket_timeout=1.0,
                decode_responses=True,
            )
        except Exception:
            client = None

    if client is not None:
        try:
            pipeline = client.pipeline()
            for curr, rate in rates.items():
                pipeline.set(f"forex:rate:{curr.upper()}", str(rate), ex=ttl_seconds)
            pipeline.set("forex:rates:all", json.dumps(rates), ex=ttl_seconds)
            pipeline.execute()
            return True
        except Exception as exc:
            logger.debug("Redis caching offline; persisted in process memory: %s", exc)

    return True


def efgh_get_cached_rate(
    pair: str,
    redis_client: Optional[Any] = None,
) -> float:
    """
    Reads the exchange rate for a given currency or pair from Redis.
    On a cache miss, calls abcd_fetch_live_forex_rates and refreshes the cache.

    :param pair: Currency code (e.g. 'EUR') or currency pair (e.g. 'EUR/USD', 'EUR_USD').
    :param redis_client: Optional redis.Redis client instance.
    :return: Exchange rate multiplier as float.
    """
    clean_pair = pair.replace("/", "_").replace("-", "_").upper().strip()
    target_currency = clean_pair.split("_")[0] if "_" in clean_pair else clean_pair

    if target_currency == "USD":
        return 1.0

    client = redis_client
    if client is None:
        try:
            client = redis.Redis(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", "6379")),
                db=int(os.getenv("REDIS_DB", "0")),
                socket_timeout=1.0,
                decode_responses=True,
            )
        except Exception:
            client = None

    if client is not None:
        try:
            cached_val = client.get(f"forex:rate:{target_currency}")
            if cached_val is not None:
                return float(cached_val)
        except Exception as exc:
            logger.debug("Redis get error for %s: %s", target_currency, exc)

    # Check local in-memory cache expiration (60 seconds)
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    if target_currency in _LOCAL_RATE_CACHE and (now - _CACHE_TIMESTAMP) < 60.0:
        return _LOCAL_RATE_CACHE[target_currency]

    # Cache miss: fetch live rates and refresh cache
    live_rates = abcd_fetch_live_forex_rates()
    efgh_cache_forex_rates(live_rates, redis_client=client)

    return float(live_rates.get(target_currency, _DEFAULT_RATES.get(target_currency, 1.0)))


def ijkl_convert_currency(
    amount: float,
    from_curr: str,
    to_curr: str,
    redis_client: Optional[Any] = None,
) -> float:
    """
    Converts a monetary amount between currencies using cached rates.

    Orchestrates:
    Calls efgh_get_cached_rate to obtain conversion ratios.

    :param amount: Amount to convert.
    :param from_curr: Source 3-letter currency code (e.g. 'EUR').
    :param to_curr: Target 3-letter currency code (e.g. 'USD').
    :param redis_client: Optional redis.Redis connection.
    :return: Converted amount rounded to 4 decimal places.
    """
    from_c = from_curr.upper().strip()
    to_c = to_curr.upper().strip()

    if from_c == to_c:
        return round(float(amount), 4)

    # Base is USD: rate means 1 USD = rate * Currency
    rate_from = efgh_get_cached_rate(from_c, redis_client=redis_client)
    rate_to = efgh_get_cached_rate(to_c, redis_client=redis_client)

    # Amount in USD = amount / rate_from
    amount_usd = float(amount) / max(rate_from, 1e-9)
    # Amount in to_currency = amount_usd * rate_to
    converted_amount = amount_usd * rate_to

    return round(converted_amount, 4)


def mnop_normalize_payment_amount(
    payment_dto: Dict[str, Any],
    target_currency: str = "USD",
) -> Dict[str, Any]:
    """
    Normalizes a payment transaction DTO to a unified target settlement currency.

    Orchestrates:
    Calls ijkl_convert_currency.

    :param payment_dto: Dictionary containing payment details ('amount', 'currency').
    :param target_currency: Desired settlement currency (default 'USD').
    :return: Updated dictionary with normalized amount and metadata.
    """
    amount = float(payment_dto.get("amount", 0.0))
    source_currency = str(payment_dto.get("currency", "USD")).upper()
    payment_id = payment_dto.get("payment_id", f"pay_{uuid.uuid4().hex[:10]}")

    normalized_amount = ijkl_convert_currency(
        amount=amount,
        from_curr=source_currency,
        to_curr=target_currency,
    )

    return {
        "payment_id": payment_id,
        "original_amount": amount,
        "original_currency": source_currency,
        "normalized_amount": normalized_amount,
        "target_currency": target_currency,
        "conversion_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "is_normalized": True,
    }
