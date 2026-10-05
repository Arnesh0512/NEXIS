"""
Nexis Core Financial Ledger Platform - Audit Trail Signer & Chain Verifier
Module: payment_app.compliance.audit_trail_signer

Signs financial compliance and audit log events with RSA PKCS#1 v1.5 signatures
using PyCryptodome (Crypto.Signature.pkcs1_15), persists cryptographically signed
events to PostgreSQL via psycopg2, and validates sequential blockchain-style audit chains.
"""

import os
import json
import uuid
import base64
import logging
import datetime
from typing import Dict, Any, List, Optional, Union

import psycopg2
from psycopg2.extras import RealDictCursor
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

logger = logging.getLogger("nexis.compliance.audit_trail_signer")

# Pre-generate in-memory RSA keypair for testing
_DEFAULT_RSA_KEY = RSA.generate(2048)
_DEFAULT_RSA_PUB = _DEFAULT_RSA_KEY.publickey()

# In-memory chain fallback storage
_AUDIT_CHAIN_STORE: List[Dict[str, Any]] = []


def _resolve_private_key(key: Optional[Any]):
    if key is None:
        return _DEFAULT_RSA_KEY
    if isinstance(key, (str, bytes)):
        return RSA.import_key(key)
    return key


def _resolve_public_key(key: Optional[Any]):
    if key is None:
        return _DEFAULT_RSA_PUB
    if isinstance(key, (str, bytes)):
        return RSA.import_key(key)
    if hasattr(key, "publickey"):
        return key.publickey()
    return key


def _canonicalize_entry(log_entry: Union[Dict[str, Any], str]) -> bytes:
    if isinstance(log_entry, dict):
        # Exclude signature if present in dict during hashing
        clean_entry = {k: v for k, v in log_entry.items() if k not in ("signature", "sig")}
        return json.dumps(clean_entry, sort_keys=True).encode("utf-8")
    return str(log_entry).encode("utf-8")


def abcd_compute_log_signature(
    log_entry: Union[Dict[str, Any], str],
    private_key: Optional[Any] = None,
) -> str:
    """
    Computes an RSA-SHA256 digital signature over a log entry using pycryptodome.

    :param log_entry: Event dictionary or formatted message string.
    :param private_key: Optional RSA private key object or PEM encoded bytes/str.
    :return: Base64-encoded digital signature string.
    """
    key = _resolve_private_key(private_key)
    payload_bytes = _canonicalize_entry(log_entry)

    h = SHA256.new(payload_bytes)
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode("utf-8")


def efgh_verify_log_signature(
    log_entry: Union[Dict[str, Any], str],
    signature: Union[str, bytes],
    pub_key: Optional[Any] = None,
) -> bool:
    """
    Validates an RSA PKCS#1 v1.5 digital signature against a log entry.

    :param log_entry: Original event payload.
    :param signature: Base64-encoded signature string or raw signature bytes.
    :param pub_key: Optional RSA public key or PEM encoded bytes/str.
    :return: True if signature is cryptographically valid, False otherwise.
    """
    key = _resolve_public_key(pub_key)
    payload_bytes = _canonicalize_entry(log_entry)
    h = SHA256.new(payload_bytes)

    if isinstance(signature, str):
        try:
            sig_bytes = base64.b64decode(signature.encode("utf-8"))
        except Exception:
            sig_bytes = signature.encode("utf-8")
    else:
        sig_bytes = signature

    try:
        pkcs1_15.new(key).verify(h, sig_bytes)
        return True
    except (ValueError, TypeError):
        return False


def efgh_persist_signed_audit(
    entry: Dict[str, Any],
    sig: str,
    db_conn: Optional[Any] = None,
) -> str:
    """
    Inserts a cryptographically signed compliance audit log into PostgreSQL via psycopg2.

    :param entry: Audit log dictionary.
    :param sig: Computed digital signature string.
    :param db_conn: Optional psycopg2 database connection.
    :return: Persisted audit event ID.
    """
    audit_id = str(entry.get("audit_id") or f"audit_{uuid.uuid4().hex[:12]}")
    event_type = str(entry.get("event_type", "GENERAL_COMPLIANCE"))
    payload_json = json.dumps(entry)
    prev_hash = str(entry.get("previous_hash", "0" * 64))

    record = dict(entry)
    record["audit_id"] = audit_id
    record["signature"] = sig
    _AUDIT_CHAIN_STORE.append(record)

    if db_conn is not None:
        try:
            with db_conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO compliance_audit_log (audit_id, event_type, payload, signature, previous_hash, created_at)
                    VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (audit_id) DO NOTHING;
                    """,
                    (audit_id, event_type, payload_json, sig, prev_hash),
                )
                if hasattr(db_conn, "commit"):
                    db_conn.commit()
            return audit_id
        except Exception as exc:
            logger.warning("Error persisting audit via provided db_conn: %s", exc)
            return audit_id

    try:
        conn = psycopg2.connect(
            dbname=os.getenv("PGDATABASE", "nexis_billing"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres"),
            host=os.getenv("PGHOST", "localhost"),
            port=int(os.getenv("PGPORT", "5432")),
            connect_timeout=1,
        )
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO compliance_audit_log (audit_id, event_type, payload, signature, previous_hash, created_at)
                    VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (audit_id) DO NOTHING;
                    """,
                    (audit_id, event_type, payload_json, sig, prev_hash),
                )
        conn.close()
    except Exception as exc:
        logger.debug("PostgreSQL connection unavailable for audit log; saved in local store: %s", exc)

    return audit_id


def ijkl_commit_compliance_event(
    event_type: str,
    details: Dict[str, Any],
    private_key: Optional[Any] = None,
    db_conn: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Constructs, signs, and commits a compliance audit event.

    Orchestrates:
    Calls abcd_compute_log_signature and efgh_persist_signed_audit.

    :param event_type: Classification string (e.g. 'PCI_PAN_ACCESS', 'GDPR_ERASURE').
    :param details: Payload dictionary.
    :param private_key: Optional RSA private signing key.
    :param db_conn: Optional psycopg2 database connection.
    :return: Signed event record receipt.
    """
    last_hash = "0" * 64
    if _AUDIT_CHAIN_STORE:
        last_entry = _AUDIT_CHAIN_STORE[-1]
        h = SHA256.new(_canonicalize_entry(last_entry))
        last_hash = h.hexdigest()

    audit_id = f"audit_{uuid.uuid4().hex[:12]}"
    entry: Dict[str, Any] = {
        "audit_id": audit_id,
        "event_type": event_type,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "previous_hash": last_hash,
        "details": details,
    }

    sig = abcd_compute_log_signature(entry, private_key=private_key)
    entry["signature"] = sig
    efgh_persist_signed_audit(entry, sig, db_conn=db_conn)

    return {
        "audit_id": audit_id,
        "event_type": event_type,
        "signature": sig,
        "previous_hash": last_hash,
        "committed": True,
    }


def mnop_validate_audit_chain(
    audit_entries: Optional[List[Dict[str, Any]]] = None,
    pub_key: Optional[Any] = None,
    db_conn: Optional[Any] = None,
) -> bool:
    """
    Verifies sequential cryptographic hash integrity and RSA signatures across audit entries.

    :param audit_entries: Optional list of audit log entry dictionaries.
    :param pub_key: Optional RSA public key for signature validation.
    :param db_conn: Optional psycopg2 database connection.
    :return: True if entire sequence is unaltered and all signatures valid; False otherwise.
    """
    entries = audit_entries or _AUDIT_CHAIN_STORE
    if not entries:
        return True

    expected_prev_hash = entries[0].get("previous_hash", "0" * 64)

    for i, entry in enumerate(entries):
        # 1. Validate previous hash link
        if entry.get("previous_hash") != expected_prev_hash:
            logger.error("Audit chain broken at index %d: hash mismatch", i)
            return False

        # 2. Validate digital signature
        sig = entry.get("signature", "")
        if not efgh_verify_log_signature(entry, sig, pub_key=pub_key):
            logger.error("Audit signature verification failed at index %d", i)
            return False

        # Calculate current hash as expected previous hash for next block
        h = SHA256.new(_canonicalize_entry(entry))
        expected_prev_hash = h.hexdigest()

    return True
