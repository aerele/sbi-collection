# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Transaction Post business logic for the SBI Collection API.

SBI Transaction Post contract (from the integration document):
    - Request  (decrypted): {"van","amount","date_time","request_id",
                            "trans_typ","ref_id","utr_no"}
      Mandatory: van, amount, date_time, utr_no.
    - Success response:     {"status_code":"00","message":"Success"}
    - Failure response:     {"status_code":"01","message":"<text>"}

Flow: validate -> find Customer by VAN -> duplicate-check by UTR -> create a
DRAFT Payment Entry -> build SBI response. Pure business logic (no crypto/logging).
"""

import frappe
from frappe import _

from sbi_collection.services import payment_service
from sbi_collection.services.validation import validate_amount

# Mandatory request fields per the SBI Transaction Post specification.
MANDATORY_FIELDS = ("van", "amount", "date_time", "utr_no")

# SBI status codes.
STATUS_SUCCESS = "00"
STATUS_FAILURE = "01"

# SBI's latest UAT email overrides the PDF's single-space success message.
SUCCESS_MESSAGE = "Success"


class TransactionPostService:
	"""Process an SBI Transaction Post notification."""

	def validate_request(self, payload):
		"""Validate that all SBI-mandated fields are present and non-empty.

		Raises frappe.ValidationError naming the first missing field.
		"""
		for field in MANDATORY_FIELDS:
			value = payload.get(field)
			if value is None or (isinstance(value, str) and not value.strip()):
				raise frappe.ValidationError(_("Missing mandatory field: {0}").format(field))
		validate_amount(payload["amount"], allow_zero=False)

	def extract_fields(self, payload):
		"""Return a dict of the SBI-relevant fields from the decrypted payload."""
		return {
			"van": frappe.utils.cstr(payload.get("van")).strip(),
			"amount": payload.get("amount"),
			# date_time kept as the raw SBI string (DD-MM-YYYY); payment_service parses it.
			"date_time": payload.get("date_time"),
			"utr": frappe.utils.cstr(payload.get("utr_no")).strip(),
			"trans_typ": payload.get("trans_typ"),
			"ref_id": payload.get("ref_id"),
			"request_id": payload.get("request_id"),
		}

	def get_customer_by_van(self, van):
		"""Return the Customer docname owning `van`, or None.

		The VAN lives on the Customer's `collection_van` custom field.
		"""
		if not van:
			return None
		return frappe.db.get_value("Customer", {"collection_van": van})

	def check_duplicate_transaction(self, utr, company):
		"""Return the name of an existing non-cancelled Payment Entry with
		`reference_no == utr` for `company`, or None if none.

		Idempotency: ERPNext Payment Entry has NO built-in uniqueness on
		reference_no, so this guard is what prevents a redelivered SBI
		notification from creating a duplicate receipt.
		"""
		if not utr:
			return None
		return frappe.db.exists(
			"Payment Entry",
			{"reference_no": utr, "company": company, "docstatus": ["<", 2]},
		)

	def build_success_response(self):
		"""SBI success payload from the latest UAT contract."""
		return {"status_code": STATUS_SUCCESS, "message": SUCCESS_MESSAGE}

	def build_failure_response(self, message):
		"""SBI failure payload with the given message text."""
		return {"status_code": STATUS_FAILURE, "message": message}

	def build_duplicate_response(self, existing_pe):
		"""SBI failure payload for a duplicate (already-processed) transaction."""
		return {
			"status_code": STATUS_FAILURE,
			"message": _("Duplicate transaction, already processed: {0}").format(existing_pe),
		}

	def process(self, decrypted_payload):
		"""Run the full transaction-post flow against a decrypted request.

		Returns a result dict:
		    {
		        "response": <plaintext SBI response dict>,
		        "van": str,
		        "customer": str|None,
		        "transaction_reference": str,   # the UTR
		        "payment_entry": str|None,      # the created PE name, if any
		        "succeeded": bool,
		    }
		"""
		try:
			self.validate_request(decrypted_payload)
		except frappe.ValidationError as error:
			return self._result(
				response=self.build_failure_response(str(error)),
				**self._empty_extract(),
			)

		fields = self.extract_fields(decrypted_payload)
		customer = self.get_customer_by_van(fields["van"])
		if not customer:
			return self._result(
				response=self.build_failure_response("Invalid Van"),
				van=fields["van"],
				customer=None,
				transaction_reference=fields["utr"],
				payment_entry=None,
				succeeded=False,
			)

		settings = frappe.get_cached_doc("SBI Collection Settings")
		company = settings.default_company
		bank_account = settings.bank_account
		payment_entry_user = settings.payment_entry_user
		if not company:
			return self._result(
				response=self.build_failure_response(
					_("SBI Collection Settings: default_company is not configured")
				),
				van=fields["van"],
				customer=customer,
				transaction_reference=fields["utr"],
				payment_entry=None,
				succeeded=False,
			)
		if not bank_account:
			return self._result(
				response=self.build_failure_response(
					_("SBI Collection Settings: bank_account is not configured")
				),
				van=fields["van"],
				customer=customer,
				transaction_reference=fields["utr"],
				payment_entry=None,
				succeeded=False,
			)
		if not payment_entry_user:
			return self._result(
				response=self.build_failure_response(
					_("SBI Collection Settings: payment_entry_user is not configured")
				),
				van=fields["van"],
				customer=customer,
				transaction_reference=fields["utr"],
				payment_entry=None,
				succeeded=False,
			)

		# Duplicate check by UTR (idempotency).
		existing = self.check_duplicate_transaction(fields["utr"], company)
		if existing:
			return self._result(
				response=self.build_duplicate_response(existing),
				van=fields["van"],
				customer=customer,
				transaction_reference=fields["utr"],
				payment_entry=existing,
				succeeded=False,
			)

		# Create the Payment Entry (draft, not submitted).
		payment_entry = payment_service.create_payment_entry(
			customer=customer,
			company=company,
			amount=fields["amount"],
			utr=fields["utr"],
			date_time=fields["date_time"],
			bank_account=bank_account,
			payment_entry_user=payment_entry_user,
			trans_typ=fields["trans_typ"],
			ref_id=fields["ref_id"],
			request_id=fields["request_id"],
		)

		return self._result(
			response=self.build_success_response(),
			van=fields["van"],
			customer=customer,
			transaction_reference=fields["utr"],
			payment_entry=payment_entry,
			succeeded=True,
		)

	@staticmethod
	def _empty_extract():
		return {
			"van": "",
			"customer": None,
			"transaction_reference": "",
			"payment_entry": None,
			"succeeded": False,
		}

	@staticmethod
	def _result(*, response, van, customer, transaction_reference, payment_entry, succeeded):
		return {
			"response": response,
			"van": van,
			"customer": customer,
			"transaction_reference": transaction_reference,
			"payment_entry": payment_entry,
			"succeeded": succeeded,
		}


def process(decrypted_payload):
	"""Module-level convenience wrapper around TransactionPostService.process."""
	return TransactionPostService().process(decrypted_payload)
