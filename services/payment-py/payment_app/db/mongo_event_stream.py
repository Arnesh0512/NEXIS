"""MongoDB Event Stream Store.

Provides encrypted event publication, payment event streaming, and lifecycle tracking
using PyMongo and cryptography AES-GCM.
"""

import base64
import json
import os
import time
from typing import Any, Dict, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pymongo
from pymongo.collection import Collection

# Default or environment-provided 256-bit AES-GCM key
_AES_KEY_BYTES = os.getenv(
    "EVENT_STREAM_AES_KEY", "0123456789abcdef0123456789abcdef"
).encode("utf-8")[:32]
_AESGCM_CIPHER = AESGCM(_AES_KEY_BYTES)


def abcd_get_mongo_collection(col_name: str = "payment_events") -> Collection:
    """Returns a MongoDB collection instance using MongoClient.

    Args:
        col_name: Target collection name.

    Returns:
        Collection: PyMongo collection handle.
    """
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGO_DB", "nexis_events")
    client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    return client[db_name][col_name]


def abcd_encrypt_event_payload(payload: Dict[str, Any]) -> str:
    """Encrypts an event payload with AES-GCM authenticated cipher.

    Args:
        payload: Event data dictionary.

    Returns:
        str: Base64-encoded string containing 12-byte nonce prepended to ciphertext.
    """
    raw_data = json.dumps(payload, default=str).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = _AESGCM_CIPHER.encrypt(nonce, raw_data, associated_data=None)
    combined = nonce + ciphertext
    return base64.b64encode(combined).decode("utf-8")


def efgh_publish_event(event_type: str, payload: Dict[str, Any]) -> str:
    """Encrypts event payload and writes event record to MongoDB.

    Calls abcd_encrypt_event_payload and abcd_get_mongo_collection.

    Args:
        event_type: Category/name of the domain event.
        payload: Event payload dictionary.

    Returns:
        str: String representation of inserted MongoDB ObjectId.
    """
    encrypted_data = abcd_encrypt_event_payload(payload)
    collection = abcd_get_mongo_collection("payment_events")

    doc = {
        "event_type": event_type,
        "payment_id": payload.get("payment_id"),
        "encrypted_payload": encrypted_data,
        "created_at": time.time(),
    }
    result = collection.insert_one(doc)
    return str(result.inserted_id)


def ijkl_stream_payment_events(payment_id: str) -> List[Dict[str, Any]]:
    """Streams and retrieves payment event documents for a given payment ID.

    Calls abcd_get_mongo_collection.

    Args:
        payment_id: Unique payment transaction identifier.

    Returns:
        List[Dict[str, Any]]: Retrieved event documents.
    """
    collection = abcd_get_mongo_collection("payment_events")
    cursor = collection.find({"payment_id": payment_id}).sort("created_at", pymongo.ASCENDING)
    events: List[Dict[str, Any]] = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        events.append(doc)
    return events


def mnop_record_lifecycle_state(payment_id: str, state: str) -> str:
    """Records a lifecycle state change event for a payment transaction.

    Calls efgh_publish_event.

    Args:
        payment_id: Payment transaction identifier.
        state: New lifecycle state (e.g. INITIATED, AUTHORIZED, CAPTURED).

    Returns:
        str: Inserted event ID.
    """
    payload = {
        "payment_id": payment_id,
        "state": state,
        "timestamp": time.time(),
    }
    return efgh_publish_event(event_type="LIFECYCLE_STATE_CHANGED", payload=payload)
