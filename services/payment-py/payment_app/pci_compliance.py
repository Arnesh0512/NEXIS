"""
Nexis Core Financial Ledger Platform - Payment Service
Module: PCI-DSS Compliance & Cardholder Data Vault Encryption

Implements AES-256-GCM authenticated cipher encryption for Primary Account
Numbers (PAN), CVV verification values, and bank routing numbers according
to PCI Data Security Standard (PCI-DSS) Section 3 requirements.
"""

import os
import json
import base64
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class PciComplianceEngine:
    """
    Cryptographic vault engine managing AES-GCM data tokenization
    and field-level encryption for credit card transactions.
    """

    def __init__(self, master_key_hex: str):
        """
        Initializes the PCI compliance engine with a 256-bit AES master key.
        """
        if not master_key_hex or len(master_key_hex) != 64:
            raise ValueError("Master key must be exactly 64 hex characters (32 bytes / 256 bits).")
        self._key = bytes.fromhex(master_key_hex)
        self._backend = default_backend()
        self._encryption_count = 0
        self._decryption_count = 0

    def encrypt_pan(self, pan: str, tenant_id: str) -> Dict[str, str]:
        """
        Encrypts a raw cardholder PAN using AES-256-GCM authenticated cipher.
        Captured by Spectra rule: Cipher(algorithms.AES, modes.GCM) (ALGO-AES)

        :param pan: The raw Primary Account Number string
        :param tenant_id: Multi-tenant context acting as Additional Authenticated Data (AAD)
        :return: Dictionary containing ciphertext, nonce, tag, and masked PAN
        """
        if not pan or len(pan) < 12:
            raise ValueError("PAN must be at least 12 digits.")

        # Standard 12-byte nonce for GCM
        nonce = os.urandom(12)

        # Spectra detection target: algorithms.AES & modes.GCM
        algorithm = algorithms.AES(self._key)
        mode = modes.GCM(nonce)

        # Spectra detection target: Cipher instantiation
        cipher = Cipher(algorithm, mode, backend=self._backend)
        encryptor = cipher.encryptor()

        # Bind tenant_id as Additional Authenticated Data
        aad = tenant_id.encode("utf-8")
        encryptor.authenticate_additional_data(aad)

        pan_bytes = pan.encode("utf-8")
        ciphertext = encryptor.update(pan_bytes) + encryptor.finalize()
        tag = encryptor.tag

        self._encryption_count += 1

        return {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "auth_tag": base64.b64encode(tag).decode("utf-8"),
            "masked_pan": self.mask_card_number(pan),
            "algorithm": "AES-256-GCM",
        }

    def decrypt_pan(self, encrypted_record: Dict[str, str], tenant_id: str) -> str:
        """
        Decrypts an encrypted PAN record and verifies authentication tag integrity.
        Captured by Spectra rule: Cipher(algorithms.AES, modes.GCM) (ALGO-AES)

        :param encrypted_record: Dict containing ciphertext, nonce, and auth_tag
        :param tenant_id: Matching AAD tenant identifier
        :return: Decrypted PAN plaintext string
        """
        ciphertext = base64.b64decode(encrypted_record["ciphertext"])
        nonce = base64.b64decode(encrypted_record["nonce"])
        tag = base64.b64decode(encrypted_record["auth_tag"])

        # Spectra detection target: modes.GCM with tag
        algorithm = algorithms.AES(self._key)
        mode = modes.GCM(nonce, tag)

        cipher = Cipher(algorithm, mode, backend=self._backend)
        decryptor = cipher.decryptor()

        aad = tenant_id.encode("utf-8")
        decryptor.authenticate_additional_data(aad)

        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        self._decryption_count += 1

        return decrypted_bytes.decode("utf-8")

    def tokenize_cardholder_payload(
        self, raw_payload: Dict[str, Any], tenant_id: str
    ) -> Dict[str, Any]:
        """
        Processes a raw payment request payload, extracting PAN and CVV,
        encrypting them into a secure vault container, and returning sanitized payload.
        """
        sanitized = dict(raw_payload)

        if "pan" in sanitized:
            pan_val = str(sanitized["pan"]).replace(" ", "").replace("-", "")
            encrypted_data = self.encrypt_pan(pan_val, tenant_id)
            sanitized["pan_vault_token"] = encrypted_data
            sanitized["pan_masked"] = encrypted_data["masked_pan"]
            del sanitized["pan"]

        if "cvv" in sanitized:
            # Ephemeral encryption for CVV
            cvv_val = str(sanitized["cvv"])
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(self._key), modes.GCM(nonce), backend=self._backend)
            enc = cipher.encryptor()
            enc.authenticate_additional_data(tenant_id.encode("utf-8"))
            ct = enc.update(cvv_val.encode("utf-8")) + enc.finalize()
            sanitized["cvv_vault_token"] = {
                "ciphertext": base64.b64encode(ct).decode("utf-8"),
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "auth_tag": base64.b64encode(enc.tag).decode("utf-8"),
            }
            del sanitized["cvv"]

        return sanitized

    @staticmethod
    def mask_card_number(pan: str) -> str:
        """
        Applies PCI-compliant masking, preserving first 6 (BIN) and last 4 digits.
        """
        clean = pan.replace(" ", "").replace("-", "")
        if len(clean) < 12:
            return "****"
        first6 = clean[:6]
        last4 = clean[-4:]
        mask_len = len(clean) - 10
        return f"{first6}{'*' * mask_len}{last4}"

    @staticmethod
    def validate_luhn(pan: str) -> bool:
        """
        Executes standard Mod-10 Luhn checksum algorithm.
        """
        clean = pan.replace(" ", "").replace("-", "")
        if not clean.isdigit():
            return False

        digits = [int(c) for c in clean]
        checksum = 0
        should_double = False

        for d in reversed(digits):
            if should_double:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
            should_double = not should_double

        return checksum % 10 == 0

    def get_telemetry(self) -> Dict[str, Any]:
        """
        Returns runtime encryption/decryption counter statistics.
        """
        return {
            "encryptions": self._encryption_count,
            "decryptions": self._decryption_count,
            "algorithm": "AES-256-GCM",
            "backend": "cryptography.hazmat",
        }
