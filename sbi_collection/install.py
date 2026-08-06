# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Custom-field setup for the sbi_collection app.

Follows the india_banking convention: fields are created imperatively via
`create_custom_fields` (plural), never via fixtures. Patches that need to
re-sync fields call `make_custom_fields()` directly.
"""

import frappe
from frappe.custom.doctype.custom_field.custom_field import create_custom_fields


def after_install():
	make_custom_fields()


def make_custom_fields():
	"""Create the `collection_van` custom field on the ERPNext Customer DocType.

	The field is exposed as `collection_van` on the Customer document and stored
	in a `collection_van` column on `tabCustomer` (in this Frappe version custom
	fields are not name-prefixed). All Python, meta, and DB access uses
	`collection_van`.
	"""
	create_custom_fields(
		{
			"Customer": [
				{
					"fieldname": "collection_van",
					"label": "Collection VAN",
					"fieldtype": "Data",
					"read_only": 1,
					"no_copy": 1,
					"insert_after": "customer_name",
					"description": "SBI Virtual Account Number generated for this customer.",
				}
			]
		}
	)
