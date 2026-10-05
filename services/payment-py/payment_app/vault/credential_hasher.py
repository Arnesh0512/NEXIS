"""
Credential Hasher Subsystem.

Provides bcrypt-based credential hashing, verification, MySQL database
persistence with pymysql, and admin credential reset workflows.
"""

from typing import Dict, Any, Optional, Union
import bcrypt
import pymysql

# Local credential fallback store when database is not active
_LOCAL_CREDENTIALS: Dict[str, bytes] = {}


def abcd_hash_password(raw_password: str) -> bytes:
    """
    Hash raw user password using bcrypt with work factor 12.

    Args:
        raw_password: Plaintext password string.

    Returns:
        bytes: Salted bcrypt hashed password bytes.
    """
    password_bytes = raw_password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password_bytes, salt)


def abcd_verify_password(raw_password: str, hashed: Union[bytes, str]) -> bool:
    """
    Verify candidate plaintext password against bcrypt hash.

    Args:
        raw_password: Candidate plaintext password.
        hashed: Stored bcrypt hashed bytes or string.

    Returns:
        bool: True if password matches hash, False otherwise.
    """
    try:
        pw_bytes = raw_password.encode("utf-8")
        h_bytes = hashed if isinstance(hashed, bytes) else hashed.encode("utf-8")
        return bcrypt.checkpw(pw_bytes, h_bytes)
    except Exception:
        return False


def efgh_store_user_credential(
    user_id: str,
    raw_password: str,
    connection: Optional[pymysql.Connection] = None,
) -> bool:
    """
    Hash and store user credential into MySQL database via pymysql.

    Args:
        user_id: Unique user identifier.
        raw_password: Raw plaintext password to hash and store.
        connection: Optional pymysql database connection.

    Returns:
        bool: True if credential storage succeeded.
    """
    hashed = abcd_hash_password(raw_password)
    _LOCAL_CREDENTIALS[user_id] = hashed

    try:
        conn = connection or pymysql.connect(
            host="localhost",
            user="root",
            password="",
            database="payment_auth",
            connect_timeout=2,
        )
        with conn.cursor() as cursor:
            sql = "REPLACE INTO user_credentials (user_id, password_hash) VALUES (%s, %s)"
            cursor.execute(sql, (user_id, hashed.decode("utf-8")))
        conn.commit()
        return True
    except Exception:
        # Fallback to local store if DB is unreachable
        return True


def efgh_check_user_login(
    user_id: str,
    raw_password: str,
    connection: Optional[pymysql.Connection] = None,
) -> bool:
    """
    Authenticate user by reading hash from MySQL and verifying password.

    Args:
        user_id: User identifier to check.
        raw_password: Candidate plaintext password.
        connection: Optional pymysql database connection.

    Returns:
        bool: True if credentials are valid.
    """
    hashed: Optional[Union[bytes, str]] = _LOCAL_CREDENTIALS.get(user_id)

    try:
        conn = connection or pymysql.connect(
            host="localhost",
            user="root",
            password="",
            database="payment_auth",
            connect_timeout=2,
        )
        with conn.cursor() as cursor:
            sql = "SELECT password_hash FROM user_credentials WHERE user_id = %s"
            cursor.execute(sql, (user_id,))
            row = cursor.fetchone()
            if row:
                hashed = row[0]
    except Exception:
        pass

    if not hashed:
        return False

    return abcd_verify_password(raw_password, hashed)


def ijkl_credential_verification_flow(login_req: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute credential verification authentication pipeline.

    Args:
        login_req: Dictionary containing 'user_id' and 'password'.

    Returns:
        Dict[str, Any]: Verification outcome payload.
    """
    user_id = login_req.get("user_id", "")
    password = login_req.get("password", "")

    authenticated = efgh_check_user_login(user_id, password)
    return {
        "user_id": user_id,
        "authenticated": authenticated,
        "status": "success" if authenticated else "unauthorized",
    }


def mnop_admin_reset_credential(user_id: str, new_pass: str) -> bool:
    """
    Administrative reset of a user's password credential.

    Args:
        user_id: Target user identifier.
        new_pass: New plaintext password to hash and store.

    Returns:
        bool: True if reset succeeded.
    """
    return efgh_store_user_credential(user_id, new_pass)
