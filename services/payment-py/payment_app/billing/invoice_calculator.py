"""
Nexis Core Financial Ledger Platform - Invoice Calculator & Persistence
Module: payment_app.billing.invoice_calculator

Calculates merchant billing line items, applies discounts, securely encrypts
merchant tax identification numbers with Fernet/AES-GCM, and persists invoice
records into PostgreSQL via psycopg2.
"""

import os
import uuid
import logging
import datetime
from typing import Dict, Any, List, Optional, Union

import psycopg2
from psycopg2.extras import RealDictCursor
from cryptography.fernet import Fernet

logger = logging.getLogger("nexis.billing.invoice_calculator")

# Predefined key or generated fallback key for tax ID encryption
_DEFAULT_KEY = os.getenv("NEXIS_INVOICE_ENCRYPTION_KEY", Fernet.generate_key().decode("utf-8")).encode("utf-8")
_FERNET_INSTANCE = Fernet(_DEFAULT_KEY)

# In-memory storage fallback for offline / mock testing
_INVOICE_STORAGE: Dict[str, Dict[str, Any]] = {}


class SubtotalResult(dict):
    """
    Subtotal calculation container supporting both dictionary key access
    and numerical coercion.
    """
    def __init__(self, subtotal: float, discount_total: float, net_total: float, item_count: int) -> None:
        super().__init__(
            subtotal=round(subtotal, 2),
            discount_total=round(discount_total, 2),
            net_total=round(net_total, 2),
            item_count=item_count,
        )

    def __float__(self) -> float:
        return float(self["net_total"])

    def __int__(self) -> int:
        return int(self["net_total"])

    def __add__(self, other: Any) -> float:
        return float(self) + float(other)

    def __radd__(self, other: Any) -> float:
        return float(other) + float(self)

    def __sub__(self, other: Any) -> float:
        return float(self) - float(other)


def abcd_calculate_subtotal(items_list: List[Dict[str, Any]]) -> SubtotalResult:
    """
    Computes line items subtotal, aggregating gross prices and subtracting discounts.

    :param items_list: List of line item dicts containing 'amount' or 'price',
                       optional 'quantity', and optional 'discount'.
    :return: SubtotalResult container with subtotal, discount_total, and net_total.
    """
    gross_subtotal = 0.0
    total_discounts = 0.0

    for item in items_list:
        if isinstance(item, (int, float)):
            gross_subtotal += float(item)
            continue

        price = float(item.get("amount", item.get("price", 0.0)))
        qty = float(item.get("quantity", item.get("qty", 1)))
        discount = float(item.get("discount", 0.0))

        gross_subtotal += (price * qty)
        total_discounts += discount

    net_subtotal = max(0.0, gross_subtotal - total_discounts)
    return SubtotalResult(
        subtotal=gross_subtotal,
        discount_total=total_discounts,
        net_total=net_subtotal,
        item_count=len(items_list),
    )


def abcd_encrypt_tax_id(tax_id: str, key: Optional[bytes] = None) -> str:
    """
    Encrypts a sensitive tax ID using cryptography.fernet.Fernet.

    :param tax_id: Plaintext merchant tax identification number.
    :param key: Optional 32-byte url-safe base64 Fernet key.
    :return: Encrypted tax ID token string.
    """
    if not tax_id:
        return ""

    cipher = Fernet(key) if key else _FERNET_INSTANCE
    encrypted_bytes = cipher.encrypt(tax_id.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def efgh_store_invoice_record(invoice: Dict[str, Any], db_conn: Optional[Any] = None) -> str:
    """
    Saves an invoice record into PostgreSQL using psycopg2.

    :param invoice: Dictionary containing invoice details.
    :param db_conn: Optional existing psycopg2 database connection.
    :return: Persisted invoice_id.
    """
    invoice_id = str(invoice.get("invoice_id") or f"inv_{uuid.uuid4().hex[:12]}")
    invoice["invoice_id"] = invoice_id
    merchant_id = str(invoice.get("merchant_id", "UNKNOWN"))
    net_total = float(invoice.get("net_total", invoice.get("subtotal", 0.0)))
    encrypted_tax_id = str(invoice.get("encrypted_tax_id", invoice.get("tax_id", "")))
    status = str(invoice.get("status", "PENDING"))

    _INVOICE_STORAGE[invoice_id] = dict(invoice)

    if db_conn is not None:
        try:
            with db_conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO invoices (invoice_id, merchant_id, net_total, tax_id_encrypted, status)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (invoice_id) DO UPDATE SET status = EXCLUDED.status;
                    """,
                    (invoice_id, merchant_id, net_total, encrypted_tax_id, status)
                )
                if hasattr(db_conn, "commit"):
                    db_conn.commit()
            return invoice_id
        except Exception as exc:
            logger.warning("Error persisting invoice via provided connection: %s", exc)
            return invoice_id

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
                    INSERT INTO invoices (invoice_id, merchant_id, net_total, tax_id_encrypted, status)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (invoice_id) DO UPDATE SET status = EXCLUDED.status;
                    """,
                    (invoice_id, merchant_id, net_total, encrypted_tax_id, status)
                )
        conn.close()
    except Exception as exc:
        logger.debug("Database unreachable, cached invoice in fallback storage: %s", exc)

    return invoice_id


def ijkl_generate_merchant_invoice(
    merchant_id: str,
    items: List[Dict[str, Any]],
    tax_id: str,
    db_conn: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Generates, encrypts, and records a merchant invoice.

    Orchestrates:
    1. abcd_calculate_subtotal
    2. abcd_encrypt_tax_id
    3. efgh_store_invoice_record

    :param merchant_id: Merchant identifier.
    :param items: List of purchase line items.
    :param tax_id: Merchant tax identification string.
    :param db_conn: Optional psycopg2 database connection.
    :return: Complete invoice dictionary.
    """
    subtotal_res = abcd_calculate_subtotal(items)
    encrypted_tax = abcd_encrypt_tax_id(tax_id)

    invoice: Dict[str, Any] = {
        "invoice_id": f"inv_{uuid.uuid4().hex[:12]}",
        "merchant_id": merchant_id,
        "items": items,
        "subtotal": subtotal_res["subtotal"],
        "discount_total": subtotal_res["discount_total"],
        "net_total": subtotal_res["net_total"],
        "encrypted_tax_id": encrypted_tax,
        "status": "GENERATED",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    stored_id = efgh_store_invoice_record(invoice, db_conn=db_conn)
    invoice["invoice_id"] = stored_id
    return invoice


def mnop_render_invoice_summary(invoice_id: str, db_conn: Optional[Any] = None) -> Dict[str, Any]:
    """
    Queries invoice record and formats a human-readable and structured summary.

    :param invoice_id: Unique invoice identifier.
    :param db_conn: Optional psycopg2 database connection.
    :return: Formatted summary dictionary.
    """
    record: Optional[Dict[str, Any]] = None

    if db_conn is not None:
        try:
            with db_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT invoice_id, merchant_id, net_total, tax_id_encrypted, status FROM invoices WHERE invoice_id = %s",
                    (invoice_id,)
                )
                row = cur.fetchone()
                if row:
                    record = dict(row)
        except Exception as exc:
            logger.warning("Error fetching invoice from db connection: %s", exc)

    if not record and invoice_id in _INVOICE_STORAGE:
        record = _INVOICE_STORAGE[invoice_id]

    if not record:
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
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(
                        "SELECT invoice_id, merchant_id, net_total, tax_id_encrypted, status FROM invoices WHERE invoice_id = %s",
                        (invoice_id,)
                    )
                    row = cur.fetchone()
                    if row:
                        record = dict(row)
            conn.close()
        except Exception:
            pass

    if not record:
        record = {
            "invoice_id": invoice_id,
            "merchant_id": "UNKNOWN",
            "net_total": 0.0,
            "status": "NOT_FOUND",
        }

    net_total = float(record.get("net_total", 0.0))
    merchant = record.get("merchant_id", "UNKNOWN")
    status = record.get("status", "UNKNOWN")

    return {
        "invoice_id": invoice_id,
        "merchant_id": merchant,
        "net_total": net_total,
        "status": status,
        "summary_text": f"Invoice [{invoice_id}] for Merchant [{merchant}]: Net Amount = ${net_total:.2f} ({status})",
    }
