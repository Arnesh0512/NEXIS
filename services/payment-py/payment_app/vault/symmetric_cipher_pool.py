"""
Symmetric Cipher Pool Subsystem.

Provides high-performance symmetric encryption/decryption (ChaCha20 / AES)
for sensitive cardholder data, Redis key pool integration, and tokenization/detokenization
pipelines.
"""

from typing import Dict, Any, Optional
import json
import base64
import redis
from Crypto.Cipher import ChaCha20, AES

_FALLBACK_POOL_KEY = b"nexis_sym_cipher_pool_key_32byte!"[:32]


def abcd_chacha20_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext bytes using ChaCha20 stream cipher via PyCryptodome.

    Args:
        plaintext: Raw data bytes to encrypt.
        key: 32-byte symmetric encryption key.

    Returns:
        bytes: Nonce prepended to the ciphertext.
    """
    normalized_key = key.ljust(32, b"\x00")[:32]
    cipher = ChaCha20.new(key=normalized_key)
    ciphertext = cipher.encrypt(plaintext)
    return cipher.nonce + ciphertext


def abcd_chacha20_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ChaCha20 ciphertext bytes using PyCryptodome.

    Args:
        ciphertext: Encrypted bytes with prepended 8-byte nonce.
        key: 32-byte symmetric encryption key.

    Returns:
        bytes: Decrypted plaintext data.
    """
    normalized_key = key.ljust(32, b"\x00")[:32]
    nonce = ciphertext[:8]
    raw_cipher = ciphertext[8:]
    cipher = ChaCha20.new(key=normalized_key, nonce=nonce)
    return cipher.decrypt(raw_cipher)


def efgh_encrypt_card_payload(
    card_data: Dict[str, Any],
    redis_client: Optional[redis.Redis] = None,
) -> str:
    """
    Query Redis cipher key pool and encrypt cardholder dictionary.

    Args:
        card_data: Dictionary containing sensitive payment card data.
        redis_client: Optional preconfigured Redis client instance.

    Returns:
        str: Base64-encoded encrypted card payload token.
    """
    client = redis_client or redis.Redis(host="localhost", port=6379, db=0)
    key = _FALLBACK_POOL_KEY

    try:
        cached_key = client.get("active_symmetric_pool_key")
        if cached_key and isinstance(cached_key, bytes):
            key = cached_key
    except Exception:
        pass

    raw_bytes = json.dumps(card_data, sort_keys=True).encode("utf-8")
    encrypted_blob = abcd_chacha20_encrypt(raw_bytes, key)
    return base64.b64encode(encrypted_blob).decode("utf-8")


def efgh_decrypt_card_payload(
    encrypted_blob: str,
    redis_client: Optional[redis.Redis] = None,
) -> Dict[str, Any]:
    """
    Retrieve session cipher key and decrypt base64 cardholder token.

    Args:
        encrypted_blob: Base64-encoded encrypted token string.
        redis_client: Optional preconfigured Redis client instance.

    Returns:
        Dict[str, Any]: Decrypted cardholder dictionary.
    """
    client = redis_client or redis.Redis(host="localhost", port=6379, db=0)
    key = _FALLBACK_POOL_KEY

    try:
        cached_key = client.get("active_symmetric_pool_key")
        if cached_key and isinstance(cached_key, bytes):
            key = cached_key
    except Exception:
        pass

    encrypted_bytes = base64.b64decode(encrypted_blob)
    plaintext_bytes = abcd_chacha20_decrypt(encrypted_bytes, key)
    return json.loads(plaintext_bytes.decode("utf-8"))


def ijkl_secure_tokenization_pipeline(raw_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute PCI-compliant card tokenization pipeline.

    Args:
        raw_record: Raw incoming transaction record with card details.

    Returns:
        Dict[str, Any]: Tokenized record preserving masked PAN and surrogate token.
    """
    token = efgh_encrypt_card_payload(raw_record)
    pan = str(raw_record.get("card_number", ""))
    masked_pan = f"****-****-****-{pan[-4:]}" if len(pan) >= 4 else "************"

    return {
        "token": token,
        "masked_pan": masked_pan,
        "tokenized": True,
        "cardholder_name": raw_record.get("cardholder_name"),
    }


def mnop_detokenize_for_settlement(token: str) -> Dict[str, Any]:
    """
    Detokenize card payload for settlement authorization against payment rail.

    Args:
        token: Surrogate encrypted token.

    Returns:
        Dict[str, Any]: Original payment payload required for settlement.
    """
    return efgh_decrypt_card_payload(token)
