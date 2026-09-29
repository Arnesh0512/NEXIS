"""
Nexis Core Financial Ledger Platform - Payment Service
Module: Fraud Detection Engine & Fingerprint Hasher

Evaluates high-risk transaction anomalies, velocity patterns, and device
fingerprints using cryptographic hash algorithms (SHA-256 and BLAKE2b).
"""

import hashlib
import time
from typing import Dict, Any, List, Tuple, Set


class FraudDetector:
    """
    Evaluates real-time risk scores for financial payment authorizations.
    """

    def __init__(self, risk_threshold: int = 70):
        self._risk_threshold = risk_threshold
        self._blacklisted_fingerprints: Set[str] = set()
        self._ip_velocity_tracker: Dict[str, List[float]] = {}
        self._account_velocity_tracker: Dict[str, List[float]] = {}
        self._evaluations_count = 0
        self._high_risk_flagged = 0

    def compute_device_fingerprint(
        self, user_agent: str, accept_headers: str, ip_address: str
    ) -> str:
        """
        Computes a cryptographic fingerprint of device attributes using SHA-256.
        Captured by Spectra rule: hashlib.sha256 (ALGO-SHA2-256)
        """
        raw_attributes = f"{user_agent}|{accept_headers}|{ip_address}".encode("utf-8")

        # Spectra detection target: hashlib.sha256
        hasher = hashlib.sha256()
        hasher.update(raw_attributes)
        fingerprint = hasher.hexdigest()

        return fingerprint

    def compute_transaction_hash(self, transaction: Dict[str, Any]) -> str:
        """
        Computes a fast, keyed-like BLAKE2b digest of the transaction parameters.
        Captured by Spectra rule: hashlib.blake2b (ALGO-BLAKE2B)
        """
        account = transaction.get("account_id", "")
        amount = str(transaction.get("amount", 0.0))
        currency = transaction.get("currency", "USD")
        timestamp = str(transaction.get("timestamp", time.time()))

        data_blob = f"{account}:{amount}:{currency}:{timestamp}".encode("utf-8")

        # Spectra detection target: hashlib.blake2b
        blake_hasher = hashlib.blake2b(digest_size=32)
        blake_hasher.update(data_blob)
        return blake_hasher.hexdigest()

    def evaluate_risk(
        self, transaction: Dict[str, Any], client_metadata: Dict[str, str]
    ) -> Tuple[int, List[str]]:
        """
        Executes heuristic rule checks and assigns risk score (0-100).
        """
        self._evaluations_count += 1
        score = 0
        reasons = []

        now = time.time()
        ip = client_metadata.get("ip_address", "127.0.0.1")
        ua = client_metadata.get("user_agent", "unknown")
        account_id = transaction.get("account_id", "")
        amount = float(transaction.get("amount", 0.0))

        # 1. Device Fingerprint Check
        fingerprint = self.compute_device_fingerprint(ua, "*/*", ip)
        if fingerprint in self._blacklisted_fingerprints:
            score += 80
            reasons.append("Device fingerprint is in global fraud blacklist")

        # 2. Transaction Amount Thresholds
        if amount > 50000.0:
            score += 30
            reasons.append("High single transaction amount (> $50,000)")
        elif amount > 10000.0:
            score += 15
            reasons.append("Elevated transaction amount (> $10,000)")

        # 3. IP Velocity Check (rolling 60s window)
        ip_timestamps = self._ip_velocity_tracker.setdefault(ip, [])
        ip_timestamps.append(now)
        # Prune older than 60s
        self._ip_velocity_tracker[ip] = [t for t in ip_timestamps if now - t <= 60]

        if len(self._ip_velocity_tracker[ip]) > 10:
            score += 45
            reasons.append("High velocity detected from source IP (> 10 req/min)")
        elif len(self._ip_velocity_tracker[ip]) > 5:
            score += 20
            reasons.append("Moderate velocity detected from source IP")

        # 4. Account Velocity Check
        if account_id:
            acc_timestamps = self._account_velocity_tracker.setdefault(account_id, [])
            acc_timestamps.append(now)
            self._account_velocity_tracker[account_id] = [t for t in acc_timestamps if now - t <= 60]

            if len(self._account_velocity_tracker[account_id]) > 5:
                score += 50
                reasons.append("Suspicious rapid transactions on single account")

        # Normalize score
        final_score = min(score, 100)
        if final_score >= self._risk_threshold:
            self._high_risk_flagged += 1

        return final_score, reasons

    def add_blacklisted_fingerprint(self, fingerprint: str) -> None:
        """
        Adds a confirmed fraudulent fingerprint to blacklist.
        """
        self._blacklisted_fingerprints.add(fingerprint)

    def remove_blacklisted_fingerprint(self, fingerprint: str) -> bool:
        """
        Removes a fingerprint from blacklist.
        """
        if fingerprint in self._blacklisted_fingerprints:
            self._blacklisted_fingerprints.remove(fingerprint)
            return True
        return False

    def clear_stale_velocity_records(self, max_age_seconds: float = 300) -> None:
        """
        Prunes velocity cache to manage memory overhead.
        """
        now = time.time()
        for ip in list(self._ip_velocity_tracker.keys()):
            self._ip_velocity_tracker[ip] = [
                t for t in self._ip_velocity_tracker[ip] if now - t <= max_age_seconds
            ]
            if not self._ip_velocity_tracker[ip]:
                del self._ip_velocity_tracker[ip]

        for acc in list(self._account_velocity_tracker.keys()):
            self._account_velocity_tracker[acc] = [
                t for t in self._account_velocity_tracker[acc] if now - t <= max_age_seconds
            ]
            if not self._account_velocity_tracker[acc]:
                del self._account_velocity_tracker[acc]

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns fraud detector operational statistics.
        """
        return {
            "evaluations_total": self._evaluations_count,
            "flagged_high_risk": self._high_risk_flagged,
            "blacklisted_fingerprints_count": len(self._blacklisted_fingerprints),
            "tracked_ips": len(self._ip_velocity_tracker),
            "tracked_accounts": len(self._account_velocity_tracker),
        }
