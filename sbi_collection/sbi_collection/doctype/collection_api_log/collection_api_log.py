# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class CollectionAPILog(Document):
	"""Log row for an SBI Collection API request/response.

	All creation and updates happen through `sbi_collection.utils.logger` - this
	controller intentionally has no `validate`/`autoname` hooks (matching the
	India Banking Request Log / Bank Request Log reference pattern).
	"""

	pass
