# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Dealer Validation business logic for the SBI Collection API.

This service is pure business logic: it validates the (already-decrypted) SBI
Dealer Validation request, looks up the Customer owning the VAN, and builds the
exact response payload mandated by the SBI Collection integration document.

SBI Dealer Validation contract (from the integration document):
    - Request  (decrypted): {"van","amount","date_time"}  (date_time = DD-MM-YYYY)
    - Success response:     {"status_code":"00","message":"Dealer verified Successfully"}
    - Failure response:     {"status_code":"01","message":"<rejection text>"}
    - status_code 00 = Success, 01 = Failure/rejection.

The service deliberately knows nothing about crypto, logging, or HTTP - those
concerns live in `sbi_collection.crypto` and `sbi_collection.utils.logger`.
`process()` never raises on expected SBI failures (missing field, unknown VAN);
it returns a failure response so the caller can always produce an SBI-shaped
reply. Only genuinely unexpected errors propagate.
"""

import frappe
from frappe import _

# Mandatory request fields per the SBI Dealer Validation specification.
MANDATORY_FIELDS = ("van", "amount", "date_time")

# SBI status codes.
STATUS_SUCCESS = "00"
STATUS_FAILURE = "01"

SUCCESS_MESSAGE = "Dealer verified Successfully"


class DealerValidationService:
	"""Validate a Dealer/VAN against ERPNext customers."""

	def validate_request(self, payload):
		"""Validate that all SBI-mandated fields are present and non-empty.

		Raises frappe.ValidationError naming the first missing mandatory field.
		"""
		for field in MANDATORY_FIELDS:
			value = payload.get(field)
			if value is None or (isinstance(value, str) and not value.strip()):
				frappe.throw(_("Missing mandatory field: {0}").format(field))

	def extract_van(self, payload):
		"""Return the VAN from the decrypted payload, whitespace-stripped."""
		return frappe.utils.cstr(payload.get("van")).strip()

	def get_customer_by_van(self, van):
		"""Return the Customer docname that owns `van`, or None.

		The VAN is stored on the Customer's `collection_van` custom field
		(no `custom_` prefix in this Frappe version).
		"""
		if not van:
			return None
		return frappe.db.get_value("Customer", {"collection_van": van})

	def build_success_response(self, customer):
		"""Build the SBI success payload.

		Note: the document lists `request_id` as OPTIONAL and the Dealer
		Validation request carries none, so we omit it by default. If SBI's UAT
		requires a correlation id, add it here.
		"""
		return {
			"status_code": STATUS_SUCCESS,
			"message": SUCCESS_MESSAGE,
		}

	def build_failure_response(self, message):
		"""Build the SBI failure payload with the given rejection message."""
		return {
			"status_code": STATUS_FAILURE,
			"message": message,
		}

	def process(self, decrypted_payload):
		"""Run the full dealer validation against a decrypted request payload.

		Returns a result dict:
		    {
		        "response": <plaintext SBI response dict>,
		        "van": str,            # the VAN extracted (may be "" if absent)
		        "customer": str|None,  # matched Customer docname, if any
		        "succeeded": bool,
		    }
		"""
		van = ""
		customer = None

		try:
			self.validate_request(decrypted_payload)
		except frappe.ValidationError as error:
			return self._result(
				response=self.build_failure_response(str(error)),
				van=van,
				customer=customer,
				succeeded=False,
			)

		van = self.extract_van(decrypted_payload)
		customer = self.get_customer_by_van(van)
		if not customer:
			return self._result(
				response=self.build_failure_response(_("Dealer not found for VAN: {0}").format(van)),
				van=van,
				customer=None,
				succeeded=False,
			)

		return self._result(
			response=self.build_success_response(customer),
			van=van,
			customer=customer,
			succeeded=True,
		)

	@staticmethod
	def _result(*, response, van, customer, succeeded):
		return {
			"response": response,
			"van": van,
			"customer": customer,
			"succeeded": succeeded,
		}


def process(decrypted_payload):
	"""Module-level convenience wrapper around DealerValidationService.process."""
	return DealerValidationService().process(decrypted_payload)
