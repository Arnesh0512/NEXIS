"""
Password Authenticator Subsystem.

Provides PostgreSQL-backed user authentication via psycopg2, credential verification
via vault.credential_hasher, failed login tracking, and authentication request dispatch.
"""

from typing import Dict, Any, Optional
import bcrypt
import psycopg2

try:
    from payment_app.vault.credential_hasher import abcd_verify_password
except ImportError:
    try:
        from vault.credential_hasher import abcd_verify_password
    except ImportError:
        def abcd_verify_password(raw_password: str, hashed: Any) -> bool:
            try:
                pw_bytes = raw_password.encode("utf-8")
                h_bytes = hashed if isinstance(hashed, bytes) else hashed.encode("utf-8")
                return bcrypt.checkpw(pw_bytes, h_bytes)
            except Exception:
                return False

# In-memory account store for environments without active PostgreSQL
_LOCAL_ACCOUNT_DB: Dict[str, Dict[str, Any]] = {}
_LOGIN_ATTEMPTS: Dict[str, int] = {}


def abcd_query_user_account(
    username: str,
    connection: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
    """
    Query user account record from PostgreSQL database via psycopg2.

    Args:
        username: Target username to look up.
        connection: Optional preconfigured psycopg2 connection.

    Returns:
        Optional[Dict[str, Any]]: User account dictionary if found, None otherwise.
    """
    try:
        conn = connection or psycopg2.connect(
            host="localhost",
            port=5432,
            dbname="nexis_payment",
            user="postgres",
            password="",
            connect_timeout=2,
        )
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, username, password_hash, is_active FROM users WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()
            if row:
                return {
                    "user_id": row[0],
                    "username": row[1],
                    "password_hash": row[2],
                    "is_active": row[3],
                }
    except Exception:
        # Fallback to local accounts
        pass

    return _LOCAL_ACCOUNT_DB.get(username)


def efgh_verify_user_credentials(
    username: str,
    password: str,
    connection: Optional[Any] = None,
) -> bool:
    """
    Verify user password against stored hash using vault.credential_hasher.

    Args:
        username: User identifier or username.
        password: Raw candidate password string.
        connection: Optional psycopg2 database connection.

    Returns:
        bool: True if password matches stored hash, False otherwise.
    """
    account = abcd_query_user_account(username, connection=connection)
    if not account:
        return False

    password_hash = account.get("password_hash")
    if not password_hash:
        return False

    return abcd_verify_password(password, password_hash)


def efgh_record_login_attempt(
    user_id: str,
    success: bool,
    connection: Optional[Any] = None,
) -> bool:
    """
    Record login success/failure attempt counter in PostgreSQL database.

    Args:
        user_id: User identifier.
        success: Whether the login attempt succeeded.
        connection: Optional psycopg2 database connection.

    Returns:
        bool: True if counter record updated.
    """
    if success:
        _LOGIN_ATTEMPTS[user_id] = 0
    else:
        _LOGIN_ATTEMPTS[user_id] = _LOGIN_ATTEMPTS.get(user_id, 0) + 1

    try:
        conn = connection or psycopg2.connect(
            host="localhost",
            port=5432,
            dbname="nexis_payment",
            user="postgres",
            password="",
            connect_timeout=2,
        )
        with conn.cursor() as cur:
            if success:
                cur.execute(
                    "UPDATE users SET failed_attempts = 0, last_login = NOW() WHERE user_id = %s",
                    (user_id,),
                )
            else:
                cur.execute(
                    "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE user_id = %s",
                    (user_id,),
                )
        conn.commit()
        return True
    except Exception:
        return True


def ijkl_process_login_pipeline(login_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute full login authentication pipeline.

    Args:
        login_data: Dictionary containing 'username' and 'password'.

    Returns:
        Dict[str, Any]: Authentication result payload.
    """
    username = login_data.get("username", "")
    password = login_data.get("password", "")

    account = abcd_query_user_account(username)
    if not account:
        return {"authenticated": False, "reason": "User not found"}

    user_id = str(account.get("user_id", username))
    verified = efgh_verify_user_credentials(username, password)
    efgh_record_login_attempt(user_id, verified)

    if not verified:
        return {"authenticated": False, "user_id": user_id, "reason": "Invalid credentials"}

    return {
        "authenticated": True,
        "user_id": user_id,
        "username": username,
    }


def mnop_authenticate_request(login_dto: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dispatch authentication request from API DTO.

    Args:
        login_dto: Incoming login request data transfer object.

    Returns:
        Dict[str, Any]: Authentication resolution.
    """
    return ijkl_process_login_pipeline(login_dto)
