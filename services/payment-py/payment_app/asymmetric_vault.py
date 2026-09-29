"""
Nexis Core Financial Ledger Platform - Payment Service
Module: Asymmetric Public-Key Vault & RSA Keypair Manager

Manages RSA-4096 asymmetric keypair generation, public key serialization,
and OAEP padding payload encryption using the cryptography.hazmat library.
"""

import os
import base64
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class AsymmetricVault:
    """
    Manages RSA public-key encryption and key management for financial partner keys.
    """

    def __init__(self, key_size: int = 4096):
        """
        Initializes vault and generates an initial RSA keypair.
        Captured by Spectra rule: rsa.generate_private_key (ALGO-RSA)
        """
        if key_size < 2048:
            raise ValueError("RSA key size must be at least 2048 bits.")

        self._backend = default_backend()
        self._key_size = key_size

        # Spectra detection target: rsa.generate_private_key
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self._key_size,
            backend=self._backend,
        )
        self._public_key = self._private_key.public_key()
        self._partner_public_keys: Dict[str, Any] = {}
        self._encryptions_count = 0
        self._decryptions_count = 0

    def encrypt_payload_for_partner(self, partner_id: str, plaintext: bytes) -> str:
        """
        Encrypts symmetric key or secret payload using partner's RSA public key with OAEP.
        """
        if partner_id not in self._partner_public_keys:
            raise ValueError(f"No public key registered for partner: {partner_id}")

        partner_pub = self._partner_public_keys[partner_id]

        # Spectra detection target: padding.OAEP & hashes.SHA256
        oaep_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

        ciphertext = partner_pub.encrypt(plaintext, oaep_padding)
        self._encryptions_count += 1
        return base64.b64encode(ciphertext).decode("utf-8")

    def decrypt_inbound_payload(self, ciphertext_b64: str) -> bytes:
        """
        Decrypts inbound encrypted payload using local RSA private key.
        """
        ciphertext = base64.b64decode(ciphertext_b64)

        oaep_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

        plaintext = self._private_key.decrypt(ciphertext, oaep_padding)
        self._decryptions_count += 1
        return plaintext

    def register_partner_public_key(self, partner_id: str, pem_data: str) -> None:
        """
        Parses and stores partner RSA public key from PEM string.
        Captured by Spectra rule: serialization.load_pem_public_key
        """
        pub_key = serialization.load_pem_public_key(
            pem_data.encode("utf-8"),
            backend=self._backend,
        )
        self._partner_public_keys[partner_id] = pub_key

    def export_public_key_pem(self) -> str:
        """
        Exports own public key in SubjectPublicKeyInfo PEM format.
        """
        pem_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_bytes.decode("utf-8")

    def export_private_key_pem(self, password: Optional[str] = None) -> str:
        """
        Exports own private key in PKCS8 format.
        """
        if password:
            enc = serialization.BestAvailableEncryption(password.encode("utf-8"))
        else:
            enc = serialization.NoEncryption()

        pem_bytes = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        return pem_bytes.decode("utf-8")

    def rotate_keypair(self) -> None:
        """
        Generates a fresh RSA keypair and rotates the local keys.
        """
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self._key_size,
            backend=self._backend,
        )
        self._public_key = self._private_key.public_key()

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns telemetry statistics for asymmetric vault.
        """
        return {
            "key_size": self._key_size,
            "registered_partners": len(self._partner_public_keys),
            "encryptions": self._encryptions_count,
            "decryptions": self._decryptions_count,
            "algorithm": "RSA-OAEP-SHA256",
        }
