"""MySQL Ledger Repository.

Provides double-entry bookkeeping, metadata encryption, and balance verification
using PyMySQL and cryptography.
"""

import json
import os
from typing import Any, Dict, Optional
import pymysql
import pymysql.cursors
from cryptography.fernet import Fernet

# Default or environment-provided key for ledger metadata encryption
_DEFAULT_KEY = Fernet.generate_key()
_FERNET_KEY = os.getenv("LEDGER_ENCRYPTION_KEY", _DEFAULT_KEY.decode("utf-8")).encode("utf-8")
_CIPHER = Fernet(_FERNET_KEY)


def abcd_get_db_connection() -> pymysql.connections.Connection:
    """Connects to MySQL database using PyMySQL.

    Returns:
        pymysql.connections.Connection: Active database connection.
    """
    host = os.getenv("MYSQL_HOST", "localhost")
    port = int(os.getenv("MYSQL_PORT", "3306"))
    user = os.getenv("MYSQL_USER", "root")
    password = os.getenv("MYSQL_PASSWORD", "secret")
    database = os.getenv("MYSQL_DATABASE", "nexis_ledger")

    return pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )


def abcd_encrypt_ledger_metadata(meta_dict: Dict[str, Any]) -> str:
    """Encrypts metadata dictionary using cryptography Fernet.

    Args:
        meta_dict: Dictionary containing metadata to encrypt.

    Returns:
        str: Encrypted ciphertext string.
    """
    raw_bytes = json.dumps(meta_dict, default=str).encode("utf-8")
    encrypted = _CIPHER.encrypt(raw_bytes)
    return encrypted.decode("utf-8")


def efgh_insert_journal_entry(conn: pymysql.connections.Connection, entry: Dict[str, Any]) -> int:
    """Inserts a transaction journal entry (debit or credit record).

    Args:
        conn: PyMySQL connection instance.
        entry: Dictionary with journal entry fields.

    Returns:
        int: Primary key ID of inserted journal entry or rows affected.
    """
    sql = """
        INSERT INTO journal_entries (account_id, entry_type, amount, currency, encrypted_metadata, created_at)
        VALUES (%s, %s, %s, %s, %s, NOW())
    """
    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                entry.get("account_id"),
                entry.get("entry_type"),
                entry.get("amount"),
                entry.get("currency", "USD"),
                entry.get("encrypted_metadata", ""),
            ),
        )
        return cursor.lastrowid or 1


def efgh_post_double_entry(
    debit_acc: str, credit_acc: str, amount: float, meta_dict: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Posts balanced double-entry ledger transactions across debit and credit accounts.

    Calls abcd_get_db_connection, abcd_encrypt_ledger_metadata, and efgh_insert_journal_entry.

    Args:
        debit_acc: Source / debit account identifier.
        credit_acc: Destination / credit account identifier.
        amount: Transaction amount.
        meta_dict: Optional metadata to encrypt.

    Returns:
        Dict[str, Any]: Execution result status and entry IDs.
    """
    if meta_dict is None:
        meta_dict = {}

    encrypted_meta = abcd_encrypt_ledger_metadata(meta_dict)
    conn = abcd_get_db_connection()

    try:
        debit_entry = {
            "account_id": debit_acc,
            "entry_type": "DEBIT",
            "amount": amount,
            "currency": meta_dict.get("currency", "USD"),
            "encrypted_metadata": encrypted_meta,
        }
        credit_entry = {
            "account_id": credit_acc,
            "entry_type": "CREDIT",
            "amount": amount,
            "currency": meta_dict.get("currency", "USD"),
            "encrypted_metadata": encrypted_meta,
        }

        debit_id = efgh_insert_journal_entry(conn, debit_entry)
        credit_id = efgh_insert_journal_entry(conn, credit_entry)
        conn.commit()

        return {
            "status": "POSTED",
            "debit_account": debit_acc,
            "credit_account": credit_acc,
            "amount": amount,
            "debit_entry_id": debit_id,
            "credit_entry_id": credit_id,
        }
    except Exception as exc:
        conn.rollback()
        raise RuntimeError(f"Failed to post double-entry ledger: {exc}") from exc
    finally:
        conn.close()


def ijkl_record_transaction_ledger(tx_data: Dict[str, Any]) -> Dict[str, Any]:
    """Records a complete transaction into the double-entry ledger.

    Calls efgh_post_double_entry.

    Args:
        tx_data: Dictionary containing transaction details.

    Returns:
        Dict[str, Any]: Ledger posting receipt.
    """
    debit_acc = str(tx_data.get("debit_account", "AC_ESCROW"))
    credit_acc = str(tx_data.get("credit_account", "AC_MERCHANT"))
    amount = float(tx_data.get("amount", 0.0))
    metadata = tx_data.get("metadata", {})

    return efgh_post_double_entry(
        debit_acc=debit_acc,
        credit_acc=credit_acc,
        amount=amount,
        meta_dict=metadata,
    )


def mnop_verify_ledger_balance(account_id: str) -> Dict[str, Any]:
    """Queries account totals and verifies debit vs credit balance.

    Calls abcd_get_db_connection.

    Args:
        account_id: Account identifier to inspect.

    Returns:
        Dict[str, Any]: Verified balance statistics.
    """
    conn = abcd_get_db_connection()
    try:
        sql = """
            SELECT 
                COALESCE(SUM(CASE WHEN entry_type = 'CREDIT' THEN amount ELSE 0 END), 0) AS total_credits,
                COALESCE(SUM(CASE WHEN entry_type = 'DEBIT' THEN amount ELSE 0 END), 0) AS total_debits
            FROM journal_entries
            WHERE account_id = %s
        """
        with conn.cursor() as cursor:
            cursor.execute(sql, (account_id,))
            result = cursor.fetchone() or {"total_credits": 0, "total_debits": 0}

        credits = float(result.get("total_credits", 0.0))
        debits = float(result.get("total_debits", 0.0))
        net_balance = credits - debits

        return {
            "account_id": account_id,
            "total_credits": credits,
            "total_debits": debits,
            "net_balance": net_balance,
            "is_balanced": (net_balance >= 0),
        }
    finally:
        conn.close()
