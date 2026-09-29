"""
Nexis Core Financial Ledger Platform - Payment Service
Module: Itemized Billing & Invoice Document Generator

Generates itemized invoice statements, calculates sales tax and VAT,
computes net payment terms, and outputs structured invoice ledger records.
"""

from typing import Dict, Any, List, Optional
import time
import uuid


class LineItem:
    """Represents a billable line item."""

    def __init__(
        self,
        description: str,
        quantity: int,
        unit_price: float,
        tax_rate: float = 0.0,
    ):
        self.description = description
        self.quantity = quantity
        self.unit_price = unit_price
        self.tax_rate = tax_rate
        self.subtotal = round(quantity * unit_price, 2)
        self.tax_amount = round(self.subtotal * tax_rate, 2)
        self.total = round(self.subtotal + self.tax_amount, 2)


class InvoiceGenerator:
    """
    Renders structured invoices and manages receivables billing ledgers.
    """

    def __init__(self, merchant_name: str, tax_id: str):
        self.merchant_name = merchant_name
        self.tax_id = tax_id
        self._invoices_generated = 0
        self._total_billed = 0.0

    def generate_invoice(
        self,
        customer_id: str,
        customer_name: str,
        customer_address: str,
        items: List[Dict[str, Any]],
        currency: str = "USD",
        payment_terms_days: int = 30,
    ) -> Dict[str, Any]:
        """
        Assembles an itemized invoice document.
        """
        inv_id = f"INV-{time.strftime('%Y%m')}-{uuid.uuid4().hex[:8].upper()}"
        created_at = int(time.time())
        due_at = created_at + (payment_terms_days * 86400)

        line_items: List[LineItem] = []
        subtotal_sum = 0.0
        tax_sum = 0.0

        for it in items:
            item = LineItem(
                description=it.get("description", "Service Fee"),
                quantity=int(it.get("quantity", 1)),
                unit_price=float(it.get("unit_price", 0.0)),
                tax_rate=float(it.get("tax_rate", 0.0)),
            )
            line_items.append(item)
            subtotal_sum += item.subtotal
            tax_sum += item.tax_amount

        grand_total = round(subtotal_sum + tax_sum, 2)
        self._invoices_generated += 1
        self._total_billed += grand_total

        serialized_items = [
            {
                "description": li.description,
                "quantity": li.quantity,
                "unit_price": li.unit_price,
                "tax_rate": li.tax_rate,
                "subtotal": li.subtotal,
                "tax_amount": li.tax_amount,
                "total": li.total,
            }
            for li in line_items
        ]

        return {
            "invoice_number": inv_id,
            "merchant": {
                "name": self.merchant_name,
                "tax_id": self.tax_id,
            },
            "customer": {
                "id": customer_id,
                "name": customer_name,
                "address": customer_address,
            },
            "currency": currency.upper(),
            "created_at": created_at,
            "due_at": due_at,
            "payment_terms": f"Net {payment_terms_days}",
            "items": serialized_items,
            "subtotal": round(subtotal_sum, 2),
            "tax_total": round(tax_sum, 2),
            "grand_total": grand_total,
            "status": "ISSUED",
        }

    def render_html_preview(self, invoice_data: Dict[str, Any]) -> str:
        """
        Renders a clean HTML preview string of the invoice.
        """
        inv_num = invoice_data["invoice_number"]
        cust_name = invoice_data["customer"]["name"]
        total = invoice_data["grand_total"]
        curr = invoice_data["currency"]

        return (
            f"<html><body>"
            f"<h1>Invoice {inv_num}</h1>"
            f"<p>Billed to: {cust_name}</p>"
            f"<p>Total Due: {total} {curr}</p>"
            f"</body></html>"
        )

    def get_generator_metrics(self) -> Dict[str, Any]:
        """
        Returns telemetry regarding invoice emission volumes.
        """
        return {
            "invoices_generated": self._invoices_generated,
            "total_billed_volume": round(self._total_billed, 2),
            "merchant_name": self.merchant_name,
        }
