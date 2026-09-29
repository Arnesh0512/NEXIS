"""
Nexis Core Financial Ledger Platform - Payment Gateway
Module: Core Payment Data Models, Enums & Transaction Contracts

Defines immutable data classes, settlement schemas, currency representations,
and PCI-DSS tokenization records utilized across the Python payment pipeline.

NOTE: Contains intentional false-positive comments and strings for AST scanner precision testing:
"Cardholder data masked prior to AES-256-GCM vault persistence"
"Asymmetric RSA-2048 payment signature assertion contract"
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional
import time
import uuid


class PaymentStatus(Enum):
    PENDING = "PENDING"
    AUTHORIZED = "AUTHORIZED"
    CAPTURED = "CAPTURED"
    SETTLED = "SETTLED"
    DECLINED = "DECLINED"
    REFUNDED = "REFUNDED"
    VOIDED = "VOIDED"
    DISPUTED = "DISPUTED"


class PaymentMethod(Enum):
    CREDIT_CARD = "CREDIT_CARD"
    DEBIT_CARD = "DEBIT_CARD"
    ACH = "ACH"
    SEPA = "SEPA"
    WIRE = "WIRE"
    CRYPTO = "CRYPTO"


class CurrencyCode(Enum):
    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"
    JPY = "JPY"
    CHF = "CHF"
    CAD = "CAD"
    AUD = "AUD"
    SGD = "SGD"
    HKD = "HKD"
    INR = "INR"


@dataclass(frozen=True)
class MonetaryAmount:
    amount_in_cents: int
    currency: CurrencyCode = CurrencyCode.USD

    def to_decimal(self) -> float:
        return self.amount_in_cents / 100.0

    @classmethod
    def from_decimal(cls, amount: float, currency: CurrencyCode = CurrencyCode.USD) -> "MonetaryAmount":
        return cls(amount_in_cents=int(round(amount * 100)), currency=currency)

    def __add__(self, other: "MonetaryAmount") -> "MonetaryAmount":
        if self.currency != other.currency:
            raise ValueError(f"Cannot add different currencies: {self.currency} and {other.currency}")
        return MonetaryAmount(amount_in_cents=self.amount_in_cents + other.amount_in_cents, currency=self.currency)


@dataclass
class PaymentSourceDescriptor:
    token_id: str
    last4: str
    brand: str
    exp_month: int
    exp_year: int
    country_code: str = "US"
    fingerprint: Optional[str] = None
    is_corporate: bool = False

    def is_expired(self, current_year: int, current_month: int) -> bool:
        if self.exp_year < current_year:
            return True
        if self.exp_year == current_year and self.exp_month < current_month:
            return True
        return False


@dataclass
class ChargeRequest:
    amount: MonetaryAmount
    source: PaymentSourceDescriptor
    merchant_id: str
    customer_id: str
    idempotency_key: str
    order_id: str
    description: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def validate(self) -> List[str]:
        errors: List[str] = []
        if self.amount.amount_in_cents <= 0:
            errors.append("Charge amount must be strictly greater than zero")
        if not self.merchant_id:
            errors.append("Merchant identifier is required")
        if not self.idempotency_key or len(self.idempotency_key) < 16:
            errors.append("Idempotency key must be at least 16 characters")
        return errors


@dataclass
class ChargeResult:
    charge_id: str
    status: PaymentStatus
    amount: MonetaryAmount
    merchant_id: str
    customer_id: str
    order_id: str
    idempotency_key: str
    authorization_code: Optional[str] = None
    decline_reason: Optional[str] = None
    fee_in_cents: int = 0
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_successful(self) -> bool:
        return self.status in (PaymentStatus.AUTHORIZED, PaymentStatus.CAPTURED, PaymentStatus.SETTLED)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "charge_id": self.charge_id,
            "status": self.status.value,
            "amount_cents": self.amount.amount_in_cents,
            "currency": self.amount.currency.value,
            "merchant_id": self.merchant_id,
            "order_id": self.order_id,
            "authorization_code": self.authorization_code,
            "fee_cents": self.fee_in_cents,
            "created_at": self.created_at,
            "security_note": "Cardholder data masked prior to AES-256-GCM vault persistence",  # False positive
        }


@dataclass
class RefundRequest:
    refund_id: str
    original_charge_id: str
    amount: MonetaryAmount
    reason: str
    merchant_id: str
    idempotency_key: str
    created_at: float = field(default_factory=time.time)


@dataclass
class SettlementBatch:
    batch_id: str
    merchant_id: str
    currency: CurrencyCode
    total_volume_cents: int
    charges_count: int
    refunds_count: int
    settlement_status: str
    settlement_date: str
    created_at: float = field(default_factory=time.time)
    reconciled: bool = False

    def net_settlement_cents(self, total_refund_cents: int, platform_fees_cents: int) -> int:
        return self.total_volume_cents - total_refund_cents - platform_fees_cents


class CardValidator:
    """
    Utility helpers for validating payment card metadata.
    """
    @staticmethod
    def validate_luhn(card_number: str) -> bool:
        cleaned = "".join(filter(str.isdigit, card_number))
        if len(cleaned) < 13 or len(cleaned) > 19:
            return False

        total = 0
        reverse_digits = cleaned[::-1]
        for i, char in enumerate(reverse_digits):
            n = int(char)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    @staticmethod
    def detect_brand(card_number: str) -> str:
        cleaned = "".join(filter(str.isdigit, card_number))
        if cleaned.startswith("4"):
            return "VISA"
        elif 51 <= int(cleaned[:2] or 0) <= 55 or 2221 <= int(cleaned[:4] or 0) <= 2720:
            return "MASTERCARD"
        elif cleaned.startswith(("34", "37")):
            return "AMEX"
        elif cleaned.startswith("6011") or cleaned.startswith("65"):
            return "DISCOVER"
        return "UNKNOWN"

    @staticmethod
    def mask_pan(card_number: str) -> str:
        cleaned = "".join(filter(str.isdigit, card_number))
        if len(cleaned) < 10:
            return "****"
        return f"{cleaned[:6]}{'*' * (len(cleaned) - 10)}{cleaned[-4:]}"
