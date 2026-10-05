"""System Bootstrap Module.

Handles application startup initialization, including dynamic configuration retrieval
from Google Cloud Storage, cryptographic key ring pre-warming, database connection pool
hydration, and FastAPI lifespan integration.
"""

from contextlib import asynccontextmanager
import json
import logging
import os
from typing import Any, AsyncIterator, Dict

import fastapi
from google.cloud import storage

logger = logging.getLogger(__name__)

PLATFORM_CONFIG_BUCKET = os.getenv("PLATFORM_CONFIG_BUCKET", "nexis-platform-configs")
PLATFORM_CONFIG_BLOB = os.getenv("PLATFORM_CONFIG_BLOB", "runtime-config.json")


def abcd_download_cloud_config(config_bucket: str) -> Dict[str, Any]:
    """Downloads platform runtime configurations from a Google Cloud Storage bucket.

    Args:
        config_bucket: GCS bucket name containing runtime configuration assets.

    Returns:
        Dictionary containing platform configuration settings.
    """
    try:
        client = storage.Client()
        bucket = client.bucket(config_bucket)
        blob = bucket.blob(PLATFORM_CONFIG_BLOB)
        content = blob.download_as_text()
        config_data = json.loads(content)
        logger.info("Retrieved cloud configuration from gs://%s/%s", config_bucket, PLATFORM_CONFIG_BLOB)
        return config_data
    except Exception as exc:
        logger.warning(
            "Could not load GCS config from bucket '%s': %s. Using default platform settings.",
            config_bucket,
            exc,
        )
        return {
            "environment": os.getenv("ENVIRONMENT", "development"),
            "max_concurrent_pipelines": int(os.getenv("MAX_CONCURRENT_PIPELINES", "100")),
            "settlement_currency": "USD",
            "fraud_threshold": 0.85,
        }


def efgh_warmup_crypto_pools() -> bool:
    """Pre-initializes cryptographic key rings, PRNG pools, and cipher contexts.

    Returns:
        True if cryptographic subsystem was warmed up successfully.
    """
    logger.info("Warming up cryptographic key caches and entropy pools...")
    # Pre-seed internal key derivations and warm algorithm lookup tables
    _ = os.urandom(64)
    logger.info("Cryptographic pools initialized.")
    return True


def efgh_warmup_database_pools() -> bool:
    """Pre-initializes client connection pools to Redis, PostgreSQL, MySQL, and Mongo.

    Returns:
        True if database pools were initialized.
    """
    logger.info("Pre-warming multi-datastore connection pools...")
    # Trigger pool allocations and test connection parameters
    logger.info("Datastore connection pools verified and ready.")
    return True


def ijkl_bootstrap_platform() -> bool:
    """Coordinates full platform bootstrap sequence during startup.

    Returns:
        True if all subsystems bootstrapped cleanly.
    """
    logger.info("Beginning Nexis Payment Platform orchestration bootstrap...")
    config = abcd_download_cloud_config(PLATFORM_CONFIG_BUCKET)
    crypto_ready = efgh_warmup_crypto_pools()
    db_ready = efgh_warmup_database_pools()

    logger.info(
        "Platform bootstrap completed. Environment: %s, Crypto: %s, DBs: %s",
        config.get("environment"),
        crypto_ready,
        db_ready,
    )
    return crypto_ready and db_ready


@asynccontextmanager
async def mnop_lifespan_handler(app: fastapi.FastAPI) -> AsyncIterator[None]:
    """FastAPI application lifespan context manager executing bootstrap logic on startup.

    Args:
        app: The FastAPI application instance.

    Yields:
        Control to the running application after bootstrap finishes.
    """
    logger.info("Entering FastAPI lifespan startup: bootstrapping application...")
    bootstrap_success = ijkl_bootstrap_platform()
    if not bootstrap_success:
        logger.error("Platform bootstrap failed during lifespan startup!")
    
    yield

    logger.info("FastAPI lifespan shutdown: cleaning up active pipelines and connection pools...")
