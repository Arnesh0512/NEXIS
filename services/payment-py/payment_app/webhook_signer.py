"""
Nexis Core Financial Ledger Platform - Payment Service
Module: Outbound Webhook Cryptographic Signer & Dispatch Verifier

Generates and validates HMAC-SHA256 digital signatures on outbound payment
event notifications dispatched to external merchant webhooks and settlement partners.
"""

import hmac
import hashlib
import time
from typing import Dict, Any, Tuple, Optional


class WebhookSigner:
    """
    Computes and verifies HMAC message authentication codes on webhook JSON payloads.
    """

    def __init__(self, signing_secret: str, tolerance_seconds: int = 300):
        """
        Initializes the signer with a shared merchant signing secret.
        """
        if not signing_secret or len(signing_secret) < 16:
            raise ValueError("Signing secret must be at least 16 characters.")
        self._secret = signing_secret.encode("utf-8")
        self._tolerance = tolerance_seconds
        self._signatures_created = 0
        self._signatures_verified = 0

    def compute_signature(self, payload: str, timestamp: Optional[int] = None) -> Tuple[str, int]:
        """
        Computes HMAC-SHA256 signature for a string payload and timestamp.
        Captured by Spectra rule: hmac.new(..., digestmod=hashlib.sha256) (ALGO-HMAC)

        :param payload: Serialized JSON payload string
        :param timestamp: Unix epoch timestamp in seconds (default: current time)
        :return: Tuple of (hex_signature, timestamp)
        """
        if timestamp is None:
            timestamp = int(time.time())

        signed_payload = f"{timestamp}.{payload}".encode("utf-8")

        # Spectra detection target: hmac.new with hashlib.sha256
        mac = hmac.new(self._secret, signed_payload, digestmod=hashlib.sha256)
        signature = mac.hexdigest()

        self._signatures_created += 1
        return signature, timestamp

    def generate_header(self, payload: str) -> str:
        """
        Constructs standard Nexis webhook header: t=12345678,v1=abcdef...
        """
        sig, ts = self.compute_signature(payload)
        return f"t={ts},v1={sig}"

    def verify_header(
        self, payload: str, header_value: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Verifies incoming webhook signature header against computed HMAC.
        Uses constant-time comparison to prevent timing attacks.

        :param payload: Raw payload string
        :param header_value: Formatted header string 't=...,v1=...'
        :return: Tuple of (is_valid, error_reason)
        """
        if not header_value:
            return False, "Missing signature header"

        parsed = self._parse_header(header_value)
        if not parsed.get("t") or not parsed.get("v1"):
            return False, "Malformed signature header components"

        try:
            timestamp = int(parsed["t"])
        except ValueError:
            return False, "Invalid timestamp format"

        now = int(time.time())
        if abs(now - timestamp) > self._tolerance:
            return False, f"Timestamp drift of {abs(now - timestamp)}s exceeds tolerance of {self._tolerance}s"

        expected_sig, _ = self.compute_signature(payload, timestamp=timestamp)

        # Constant-time comparison
        # Spectra detection target: hmac.compare_digest
        is_valid = hmac.compare_digest(expected_sig, parsed["v1"])
        self._signatures_verified += 1

        if not is_valid:
            return False, "Signature mismatch"

        return True, None

    def sign_transaction_envelope(
        self, event_type: str, transaction_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Packages financial transaction into an authenticated webhook envelope.
        """
        import json

        envelope = {
            "event": event_type,
            "data": transaction_data,
            "created_at": int(time.time()),
        }
        serialized = json.dumps(envelope, sort_keys=True)
        sig, ts = self.compute_signature(serialized, envelope["created_at"])

        return {
            "payload": envelope,
            "signature": sig,
            "signature_timestamp": ts,
            "header": f"t={ts},v1={sig}",
        }

    @staticmethod
    def _parse_header(header_value: str) -> Dict[str, str]:
        """
        Parses comma-delimited key=value signature header string.
        """
        parts = header_value.split(",")
        parsed = {}
        for part in parts:
            kv = part.strip().split("=", 1)
            if len(kv) == 2:
                parsed[kv[0]] = kv[1]
        return parsed

    def compute_sha256_checksum(self, data: bytes) -> str:
        """
        Computes standalone SHA-256 digest for payload integrity verification.
        Captured by Spectra rule: hashlib.sha256 (ALGO-SHA2-256)
        """
        hasher = hashlib.sha256()
        hasher.update(data)
        return hasher.hexdigest()

    def get_telemetry(self) -> Dict[str, Any]:
        """
        Returns telemetry regarding webhook signing operations.
        """
        return {
            "signatures_created": self._signatures_created,
            "signatures_verified": self._signatures_verified,
            "tolerance_seconds": self._tolerance,
            "algorithm": "HMAC-SHA256",
        }
