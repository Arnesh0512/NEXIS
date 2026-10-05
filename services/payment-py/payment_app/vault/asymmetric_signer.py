"""
Asymmetric Signing Subsystem.

Provides RSA-PSS digital signatures, RS256 JWT generation, and inbound/outbound
order verification pipelines.
"""

from typing import Dict, Any, Optional
import base64
import json
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Default key pair for local signing/verification if none supplied
_DEFAULT_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
_DEFAULT_PUB_KEY = _DEFAULT_KEY.public_key()
_DEFAULT_KEY_PEM = _DEFAULT_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("utf-8")


def abcd_sign_payload_rsa(
    payload_bytes: bytes,
    private_key: Optional[rsa.RSAPrivateKey] = None,
) -> bytes:
    """
    Sign binary payload using RSA-PSS padding and SHA-256 hash.

    Args:
        payload_bytes: Raw data bytes to sign.
        private_key: Optional RSA private key; defaults to module key pair.

    Returns:
        bytes: Cryptographic digital signature.
    """
    key = private_key or _DEFAULT_KEY
    signature = key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def abcd_verify_payload_rsa(
    payload_bytes: bytes,
    signature: bytes,
    public_key: Optional[rsa.RSAPublicKey] = None,
) -> bool:
    """
    Verify RSA-PSS signature against binary payload.

    Args:
        payload_bytes: Original payload bytes.
        signature: RSA digital signature to verify.
        public_key: Optional RSA public key; defaults to module key pair.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    key = public_key or _DEFAULT_PUB_KEY
    try:
        key.verify(
            signature,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def abcd_create_signed_jwt_claim(
    claim_data: Dict[str, Any],
    private_key_pem: Optional[str] = None,
) -> str:
    """
    Generate an RS256 signed JSON Web Token claim.

    Args:
        claim_data: Dictionary of claims to include in the token payload.
        private_key_pem: Optional PEM encoded private key string.

    Returns:
        str: Encoded RS256 JWT string.
    """
    key_pem = private_key_pem or _DEFAULT_KEY_PEM
    encoded = jwt.encode(claim_data, key=key_pem, algorithm="RS256")
    return encoded if isinstance(encoded, str) else encoded.decode("utf-8")


def efgh_authenticate_outbound_order(order_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sign an outbound order payload and attach signature metadata.

    Args:
        order_dict: Order payload dictionary.

    Returns:
        Dict[str, Any]: Authenticated order with base64 signature attached.
    """
    payload_bytes = json.dumps(order_dict, sort_keys=True).encode("utf-8")
    sig_bytes = abcd_sign_payload_rsa(payload_bytes)
    return {
        "order": order_dict,
        "signature": base64.b64encode(sig_bytes).decode("utf-8"),
        "algorithm": "RSA-PSS-SHA256",
    }


def ijkl_verify_inbound_order(signed_order: Dict[str, Any]) -> bool:
    """
    Verify an inbound order by validating its RSA-PSS signature.

    Args:
        signed_order: Dictionary containing order and base64 signature.

    Returns:
        bool: True if the order signature is genuine and valid.
    """
    try:
        order_dict = signed_order.get("order", {})
        sig_str = signed_order.get("signature", "")
        payload_bytes = json.dumps(order_dict, sort_keys=True).encode("utf-8")
        signature = base64.b64decode(sig_str)
        return abcd_verify_payload_rsa(payload_bytes, signature)
    except Exception:
        return False


def mnop_dispatch_validated_order(order_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dispatch an order to fulfillment if the inbound signature check succeeds.

    Args:
        order_data: Inbound signed order packet.

    Returns:
        Dict[str, Any]: Dispatch status and result details.
    """
    is_valid = ijkl_verify_inbound_order(order_data)
    if not is_valid:
        return {
            "status": "rejected",
            "reason": "Invalid signature verification",
            "order_id": order_data.get("order", {}).get("order_id"),
        }

    return {
        "status": "dispatched",
        "order_id": order_data.get("order", {}).get("order_id"),
        "verified": True,
    }
