"""
Nexis Core Financial Ledger Platform - Payment Service
Module: Daily Settlement & Clearing Reconciliation Engine

Matches internal payment authorizations against external banking clearing
files, calculates network interchange fees, and flags balance discrepancies.
"""

from typing import Dict, Any, List, Tuple, Optional
import time


class ReconciliationRecord:
    """Represents a matched or unmatched settlement record."""

    def __init__(
        self,
        internal_tx_id: str,
        external_reference: str,
        authorized_amount: float,
        cleared_amount: float,
        interchange_fee: float,
        currency: str,
        status: str,
    ):
        self.internal_tx_id = internal_tx_id
        self.external_reference = external_reference
        self.authorized_amount = authorized_amount
        self.cleared_amount = cleared_amount
        self.interchange_fee = interchange_fee
        self.currency = currency
        self.status = status
        self.timestamp = time.time()


class BillingReconciliationEngine:
    """
    Executes automated ledger reconciliation against bank clearing feed entries.
    """

    def __init__(self, tolerance_cents: float = 0.01):
        self._tolerance = tolerance_cents
        self._matched_records: List[ReconciliationRecord] = []
        self._discrepancies: List[ReconciliationRecord] = []
        self._total_cleared_volume = 0.0
        self._total_interchange_fees = 0.0

    def reconcile_transaction(
        self,
        internal_transaction: Dict[str, Any],
        bank_clearing_entry: Dict[str, Any],
    ) -> ReconciliationRecord:
        """
        Compares internal authorization with clearing house record.
        """
        tx_id = internal_transaction.get("transaction_id", "unknown")
        ext_ref = bank_clearing_entry.get("bank_reference", "unknown")

        auth_amt = float(internal_transaction.get("amount", 0.0))
        clear_amt = float(bank_clearing_entry.get("cleared_amount", 0.0))
        fee = float(bank_clearing_entry.get("interchange_fee", 0.0))
        curr = internal_transaction.get("currency", "USD")

        diff = abs(auth_amt - clear_amt)
        if diff <= self._tolerance:
            status = "MATCHED"
            rec = ReconciliationRecord(tx_id, ext_ref, auth_amt, clear_amt, fee, curr, status)
            self._matched_records.append(rec)
            self._total_cleared_volume += clear_amt
            self._total_interchange_fees += fee
        else:
            status = "DISCREPANCY_AMOUNT_MISMATCH"
            rec = ReconciliationRecord(tx_id, ext_ref, auth_amt, clear_amt, fee, curr, status)
            self._discrepancies.append(rec)

        return rec

    def process_clearing_batch(
        self,
        internal_transactions: List[Dict[str, Any]],
        bank_clearing_entries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Reconciles an entire batch of daily transactions.
        """
        bank_map = {
            entry.get("transaction_id"): entry for entry in bank_clearing_entries
        }

        matched = 0
        unmatched = 0

        for tx in internal_transactions:
            tx_id = tx.get("transaction_id")
            if tx_id in bank_map:
                record = self.reconcile_transaction(tx, bank_map[tx_id])
                if record.status == "MATCHED":
                    matched += 1
                else:
                    unmatched += 1
            else:
                unmatched += 1
                rec = ReconciliationRecord(
                    internal_tx_id=tx_id or "unknown",
                    external_reference="MISSING_BANK_ENTRY",
                    authorized_amount=float(tx.get("amount", 0.0)),
                    cleared_amount=0.0,
                    interchange_fee=0.0,
                    currency=tx.get("currency", "USD"),
                    status="UNMATCHED_MISSING_IN_BANK",
                )
                self._discrepancies.append(rec)

        return {
            "total_processed": len(internal_transactions),
            "matched_count": matched,
            "discrepancy_count": unmatched,
            "cleared_volume": self._total_cleared_volume,
            "interchange_fees": self._total_interchange_fees,
        }

    def resolve_discrepancy(self, internal_tx_id: str, resolution_notes: str) -> bool:
        """
        Manually resolves a ledger discrepancy.
        """
        for i, rec in enumerate(self._discrepancies):
            if rec.internal_tx_id == internal_tx_id:
                rec.status = "RESOLVED_MANUAL"
                self._discrepancies.pop(i)
                self._matched_records.append(rec)
                return True
        return False

    def get_summary(self) -> Dict[str, Any]:
        """
        Returns reconciliation telemetry.
        """
        return {
            "matched_records_count": len(self._matched_records),
            "open_discrepancies_count": len(self._discrepancies),
            "total_volume": self._total_cleared_volume,
            "total_fees": self._total_interchange_fees,
        }
