# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""VAN (Virtual Account Number) generation for SBI Collection.

The VAN is built as `van_prefix + customer_identifier`, where the customer
identifier is the Customer docname with the prefix stripped from the front (so
the prefix appears exactly once in the final VAN). All validation happens
server-side; the client only adds a button and invokes `generate_van`.
"""

import re

import frappe
from frappe import _

# Default max total VAN length; overridable per-site via the
# `van_max_length` field on SBI Collection Settings.
DEFAULT_VAN_MAX_LENGTH = 20

# VAN prefix must be exactly 6 alphanumeric characters, per the requirement.
PREFIX_PATTERN = re.compile(r"[A-Za-z0-9]{6}")


def build_van(prefix: str, customer_name: str) -> str:
	"""Return the VAN for a customer identifier.

	The prefix is stripped from the front of `customer_name` when present so it
	isn't doubled in the result. Comparison is case-insensitive; the strip
	preserves the original casing of the remainder.
	"""
	identifier = customer_name
	if identifier[: len(prefix)].upper() == prefix.upper():
		identifier = identifier[len(prefix) :]
	return f"{prefix}{identifier}"


def _validate_prefix(prefix: str) -> None:
	if not prefix or not PREFIX_PATTERN.fullmatch(prefix):
		frappe.throw(_("VAN Prefix must be exactly 6 alphanumeric characters."))


@frappe.whitelist()
def generate_van(customer: str) -> str:
	"""Generate and persist the Collection VAN for the given Customer.

	Called by the "Generate VAN" custom button on the Customer form. The VAN is
	derived from the SBI Collection Settings `van_prefix` and the Customer
	docname, stored into the read-only `collection_van` custom field, and
	returned so the client can refresh the field and show a success message.

	Raises frappe.exceptions.ValidationError via `frappe.throw` on any invalid
	input or duplicate VAN.
	"""
	customer_doc = frappe.get_doc("Customer", customer)

	if customer_doc.collection_van:
		frappe.throw(_("VAN already generated: {0}").format(customer_doc.collection_van))

	settings = frappe.get_cached_doc("SBI Collection Settings")
	prefix = (settings.van_prefix or "").strip()
	_validate_prefix(prefix)

	max_length = frappe.utils.cint(settings.van_max_length) or DEFAULT_VAN_MAX_LENGTH

	van = build_van(prefix, customer_doc.name)
	if len(van) > max_length:
		frappe.throw(_("Generated VAN exceeds {0} characters: {1}").format(max_length, van))

	# Global uniqueness across all customers - a duplicate VAN would misroute
	# collections to the wrong customer.
	if frappe.db.exists("Customer", {"collection_van": van}):
		frappe.throw(_("VAN {0} already exists on another customer").format(van))

	customer_doc.db_set("collection_van", van)
	return van
