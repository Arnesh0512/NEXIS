"""
Session Authorizer Subsystem.

Provides FastAPI-integrated JWT session authorization, Bearer token extraction,
role-based access control (RBAC), and route protection middleware.
"""

from typing import Dict, Any, List, Optional
import jwt
from fastapi import Request, HTTPException, status

_JWT_SECRET = "nexis_payment_platform_hs512_super_secure_secret_key_2026!"


def abcd_decode_and_validate_jwt(
    token_str: str,
    secret: str = _JWT_SECRET,
    algorithms: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Decode and validate a JSON Web Token against accepted signature algorithms.

    Args:
        token_str: Encoded JWT token string.
        secret: Signing secret or public key.
        algorithms: List of accepted algorithms (defaults to HS512, HS256).

    Returns:
        Dict[str, Any]: Decoded token payload dictionary.

    Raises:
        HTTPException: If token is expired, invalid, or malformed.
    """
    if algorithms is None:
        algorithms = ["HS512", "HS256"]

    try:
        payload = jwt.decode(token_str, secret, algorithms=algorithms)
        return payload
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def efgh_extract_bearer_token(request: Request) -> str:
    """
    FastAPI dependency to extract Bearer token from the incoming HTTP Authorization header.

    Args:
        request: FastAPI HTTP request instance.

    Returns:
        str: Raw Bearer token string.

    Raises:
        HTTPException: If the header is missing or improperly formatted.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme; Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return parts[1]


def efgh_authorize_role(
    required_role: str,
    token_str: str,
    secret: str = _JWT_SECRET,
) -> bool:
    """
    Validate token and verify presence of the required authorization role.

    Args:
        required_role: Name of the role to authorize (e.g. 'admin', 'operator').
        token_str: JWT token string.
        secret: Secret key for token verification.

    Returns:
        bool: True if user holds the required role, False otherwise.
    """
    try:
        claims = abcd_decode_and_validate_jwt(token_str, secret=secret)
        roles = claims.get("roles", [])
        return required_role in roles
    except HTTPException:
        return False


def ijkl_verify_session_security(request: Request, role: str) -> Dict[str, Any]:
    """
    Verify full request security context by extracting Bearer token and checking role.

    Args:
        request: FastAPI HTTP request.
        role: Required authorization role for endpoint access.

    Returns:
        Dict[str, Any]: Security context payload with claims and authorized status.

    Raises:
        HTTPException: If token extraction fails or role authorization is denied.
    """
    token = efgh_extract_bearer_token(request)
    claims = abcd_decode_and_validate_jwt(token)

    authorized = efgh_authorize_role(role, token)
    if not authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Missing required role '{role}'",
        )

    return {
        "authorized": True,
        "user_id": claims.get("sub"),
        "role": role,
        "claims": claims,
    }


def mnop_protect_admin_route(request: Request) -> Dict[str, Any]:
    """
    Enforce administrative security guard on incoming route request.

    Args:
        request: FastAPI HTTP request.

    Returns:
        Dict[str, Any]: Admin session context.
    """
    return ijkl_verify_session_security(request, role="admin")
