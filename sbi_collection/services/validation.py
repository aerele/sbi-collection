"""Shared amount validation for the SBI Dealer and MIS contracts."""

from decimal import Decimal, InvalidOperation

import frappe


def validate_amount(value, *, allow_zero):
	"""Reject invalid/nonfinite amounts before customer lookup or payment creation."""
	try:
		amount = Decimal(str(value))
	except (InvalidOperation, ValueError):
		raise frappe.ValidationError("Invalid Amount") from None
	if not amount.is_finite():
		raise frappe.ValidationError("Invalid Amount")
	if amount < 0:
		raise frappe.ValidationError("Amount Cannot be Negative")
	if not allow_zero and amount == 0:
		raise frappe.ValidationError("Amount Cannot be Zero")
