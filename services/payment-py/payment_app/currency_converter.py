"""
Nexis Core Financial Ledger Platform - Payment Service
Module: FX Currency Conversion & Cross-Border Fee Engine

Calculates foreign exchange spot rates, network markup spreads, and
converts cross-border payment values across major ISO 4217 currencies.
"""

from typing import Dict, Any, Tuple, Optional
import time


class CurrencyConverter:
    """
    Manages currency conversion matrices and wholesale FX spread markups.
    """

    def __init__(self, base_currency: str = "USD"):
        self.base_currency = base_currency
        # Base FX rates relative to 1 USD
        self._rates: Dict[str, float] = {
            "USD": 1.0,
            "EUR": 0.92,
            "GBP": 0.79,
            "JPY": 154.50,
            "CHF": 0.89,
            "CAD": 1.36,
            "AUD": 1.52,
            "SGD": 1.35,
            "HKD": 7.82,
            "INR": 83.35,
        }
        self._spread_basis_points = 50  # 0.50% markup
        self._last_rate_update = time.time()
        self._conversions_executed = 0

    def convert_amount(
        self,
        amount: float,
        from_currency: str,
        to_currency: str,
        apply_spread: bool = True,
    ) -> Tuple[float, float]:
        """
        Converts a numerical amount between two currencies.

        :param amount: Source currency value
        :param from_currency: 3-letter ISO code
        :param to_currency: 3-letter ISO code
        :param apply_spread: Whether to include foreign exchange spread fee
        :return: Tuple of (converted_amount, applied_exchange_rate)
        """
        from_curr = from_currency.upper()
        to_curr = to_currency.upper()

        if from_curr not in self._rates:
            raise ValueError(f"Unsupported source currency: {from_curr}")
        if to_curr not in self._rates:
            raise ValueError(f"Unsupported target currency: {to_curr}")

        self._conversions_executed += 1

        if from_curr == to_curr:
            return amount, 1.0

        # Convert to USD base first
        usd_amount = amount / self._rates[from_curr]

        # Convert USD to target
        target_amount = usd_amount * self._rates[to_curr]
        effective_rate = self._rates[to_curr] / self._rates[from_curr]

        if apply_spread:
            markup_factor = 1.0 - (self._spread_basis_points / 10000.0)
            target_amount = target_amount * markup_factor
            effective_rate = effective_rate * markup_factor

        # Round to 2 decimal places (or 0 for JPY)
        decimals = 0 if to_curr == "JPY" else 2
        rounded_amount = round(target_amount, decimals)

        return rounded_amount, effective_rate

    def update_exchange_rate(self, currency: str, rate_to_usd: float) -> None:
        """
        Updates exchange rate against USD base.
        """
        if rate_to_usd <= 0:
            raise ValueError("Exchange rate must be positive.")
        self._rates[currency.upper()] = rate_to_usd
        self._last_rate_update = time.time()

    def set_spread_basis_points(self, bps: int) -> None:
        """
        Adjusts FX margin spread in basis points (1 bp = 0.01%).
        """
        if bps < 0 or bps > 500:
            raise ValueError("Spread must be between 0 and 500 basis points.")
        self._spread_basis_points = bps

    def calculate_fx_fee(
        self, amount: float, from_currency: str, to_currency: str
    ) -> float:
        """
        Computes the isolated spread fee deducted during conversion.
        """
        converted_with_spread, _ = self.convert_amount(
            amount, from_currency, to_currency, apply_spread=True
        )
        converted_without_spread, _ = self.convert_amount(
            amount, from_currency, to_currency, apply_spread=False
        )
        return round(abs(converted_without_spread - converted_with_spread), 2)

    def get_supported_currencies(self) -> list:
        return sorted(list(self._rates.keys()))

    def get_telemetry(self) -> Dict[str, Any]:
        return {
            "conversions_executed": self._conversions_executed,
            "supported_currencies_count": len(self._rates),
            "spread_basis_points": self._spread_basis_points,
            "last_updated": self._last_rate_update,
        }
