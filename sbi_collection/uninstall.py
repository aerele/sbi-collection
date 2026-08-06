# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Uninstall cleanup for the sbi_collection app.

Removes the custom field(s) added on install. Mirrors the india_banking
uninstall convention.
"""

import frappe


def before_uninstall():
	frappe.db.delete("Custom Field", {"dt": "Customer", "fieldname": "collection_van"})
	frappe.clear_cache(doctype="Customer")
