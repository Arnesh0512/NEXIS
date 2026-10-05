"""PostgreSQL Audit Store.

Provides cryptographically verifiable audit trail logging and inspection
using psycopg2 and PyCryptodome SHA256 / HMAC.
"""

import json
import os
from typing import Any, Dict, List, Optional
import psycopg2
import psycopg2.extras
from Crypto.Hash import HMAC, SHA256

_AUDIT_SECRET = os.getenv("AUDIT_LOG_SECRET", "nexis-audit-secret-key-32bytes!!").encode("utf-8")


def abcd_compute_log_digest(log_str: str) -> str:
    """Computes a SHA-256 HMAC digest for log integrity via PyCryptodome.

    Args:
        log_str: Raw log string to compute digest for.

    Returns:
        str: Hexadecimal HMAC SHA-256 digest string.
    """
    hmac_obj = HMAC.new(_AUDIT_SECRET, msg=log_str.encode("utf-8"), digestmod=SHA256)
    return hmac_obj.hexdigest()


def efgh_connect_postgres():
    """Connects to PostgreSQL database using psycopg2.

    Returns:
        psycopg2.extensions.connection: Active PostgreSQL connection.
    """
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = int(os.getenv("POSTGRES_PORT", "5432"))
    user = os.getenv("POSTGRES_USER", "postgres")
    password = os.getenv("POSTGRES_PASSWORD", "secret")
    database = os.getenv("POSTGRES_DB", "nexis_audit")

    return psycopg2.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        dbname=database,
    )


def efgh_write_audit_log(event_type: str, details: Dict[str, Any]) -> str:
    """Computes cryptographic digest and inserts audit log row into PostgreSQL.

    Calls abcd_compute_log_digest.

    Args:
        event_type: Category/type of audit event.
        details: Payload details of the audit event.

    Returns:
        str: Computed cryptographic hash/digest of the inserted log.
    """
    payload_str = json.dumps({"event_type": event_type, "details": details}, sort_keys=True)
    digest = abcd_compute_log_digest(payload_str)

    conn = efgh_connect_postgres()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_logs (event_type, details_json, log_digest, created_at)
                VALUES (%s, %s, %s, NOW())
                RETURNING id;
                """,
                (event_type, json.dumps(details), digest),
            )
            conn.commit()
    finally:
        conn.close()

    return digest


def ijkl_persist_security_audit(security_event: Dict[str, Any]) -> str:
    """Persists a high-severity security audit event into the tamper-evident store.

    Calls efgh_write_audit_log.

    Args:
        security_event: Event dictionary containing severity, actor, action, and payload.

    Returns:
        str: Resulting verification digest.
    """
    event_type = security_event.get("event_type", "SECURITY_ALERT")
    details = {
        "actor": security_event.get("actor", "system"),
        "severity": security_event.get("severity", "HIGH"),
        "payload": security_event.get("payload", {}),
        "timestamp": security_event.get("timestamp"),
    }
    return efgh_write_audit_log(event_type=event_type, details=details)


def mnop_query_audit_trail(start_time: str, end_time: str) -> List[Dict[str, Any]]:
    """Queries PostgreSQL audit trail within a specific timestamp window.

    Calls efgh_connect_postgres.

    Args:
        start_time: ISO-formatted start timestamp string.
        end_time: ISO-formatted end timestamp string.

    Returns:
        List[Dict[str, Any]]: Retrieved audit log records.
    """
    conn = efgh_connect_postgres()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute(
                """
                SELECT id, event_type, details_json, log_digest, created_at
                FROM audit_logs
                WHERE created_at BETWEEN %s AND %s
                ORDER BY created_at ASC;
                """,
                (start_time, end_time),
            )
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    finally:
        conn.close()
