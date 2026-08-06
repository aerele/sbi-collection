# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

import frappe

from sbi_collection.install import make_custom_fields


def execute():
	"""Add the `collection_van` custom field on Customer for existing sites.

	Idempotent: `create_custom_fields` skips fields that already exist, so this
	is safe to re-run. Delegates to install.make_custom_fields() per the
	india_banking convention (patches never re-implement field creation).
	"""
	make_custom_fields()
	frappe.clear_cache(doctype="Customer")
