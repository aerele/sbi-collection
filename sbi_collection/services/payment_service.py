# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Payment Entry creation for the SBI Collection Transaction Post API.

Creates a DRAFT INBOUND (Receive) Payment Entry when SBI notifies us of a
collection against a VAN. The entry is intentionally left as a draft (docstatus
0) for manual verification + reconciliation before submission. This module is
pure ERPNext accounting glue - it knows nothing about SBI semantics, crypto, or
logging. Duplicate detection is the caller's responsibility
(see transaction_post_service).

Accounting direction for an inbound collection:
    paid_from = Customer's receivable account (party account)
    paid_to   = the configured collection Bank Account's ledger account

The Payment Entry is recorded as an UNALLOCATED ADVANCE (no `references` rows;
full amount in `unallocated_amount`). Invoice allocation / reconciliation is a
later phase - doing it here would risk auto-allocating against the wrong invoice.
"""

import frappe
from erpnext.accounts.party import get_party_account
from frappe.utils import flt, getdate

# SBI date_time format (per the integration document) is DD-MM-YYYY.
SBI_DATE_FORMAT = "%d-%m-%Y"


def _resolve_receivable_account(customer, company):
	"""Return the Customer's receivable account for `company`."""
	account = get_party_account("Customer", customer, company)
	if not account:
		frappe.throw(
			frappe._(
				"No receivable account found for Customer {0} in company {1}. "
				"Configure the Customer's Default Accounts (Party Account) row."
			).format(customer, company)
		)
	return account


def _resolve_bank_ledger_account(bank_account):
	"""Return the ledger Account linked to a Bank Account master record.

	Uses a direct DB read instead of get_bank_account_details() because the
	latter enforces a read-permission check that fails under the guest SBI
	endpoint context.
	"""
	account = frappe.db.get_value("Bank Account", bank_account, "account")
	if not account:
		frappe.throw(
			frappe._(
				"Bank Account {0} has no linked ledger account. Set the account on the Bank Account master."
			).format(bank_account)
		)
	return account


def _account_currency_and_type(account):
	"""Return ``(account_currency, account_type)`` for an Account via direct DB read.

	Avoids ERPNext's ``get_account_details()``, which does an unconditional
	``frappe.has_permission("Payment Entry", throw=True)`` that fails for the
	Guest SBI endpoint caller (the standalone has_permission ignores every
	permission flag). Pre-populating these four fields also short-circuits the
	``if not self.paid_from_account_currency...`` guard in
	PaymentEntry.set_missing_values, so get_account_details is never reached.
	Same bypass rationale as _resolve_bank_ledger_account.
	"""
	row = frappe.db.get_value("Account", account, ["account_currency", "account_type"], as_dict=True)
	if not row:
		frappe.throw(frappe._("Account {0} not found").format(account))
	return row.account_currency, row.account_type


def _parse_sbi_date(date_time):
	"""Parse an SBI date_time string (DD-MM-YYYY) into a date object.

	Falls back to today on parse failure so a malformed date never blocks a
	real collection (the SBI notification must still be recorded).
	"""
	try:
		return getdate(date_time, parse_day_first=True)
	except Exception:
		frappe.log_error(
			title="SBI Collection: unparseable date_time",
			message=f"date_time={date_time!r}",
		)
		return getdate()


def create_payment_entry(
	*,
	customer,
	company,
	amount,
	utr,
	date_time,
	bank_account,
	trans_typ=None,
	ref_id=None,
	request_id=None,
):
	"""Create a DRAFT inbound Payment Entry. Returns its name.

	The entry is intentionally left as a draft (docstatus 0) so the accounts
	team can verify the collection and reconcile it manually before submission.
	Duplicate detection in transaction_post_service covers drafts (docstatus < 2),
	so a redelivered SBI notification still matches this draft and won't create a
	second Payment Entry.

	Args:
		customer: Customer docname (the VAN owner).
		company: Company to book the entry in.
		amount: collection amount (string or number; parsed via flt).
		utr: bank UTR / unique transaction reference -> stored as reference_no
			(also the duplicate-detection key).
		date_time: SBI transaction date (DD-MM-YYYY).
		bank_account: the collection Bank Account master (paid_to ledger source).
		trans_typ, ref_id, request_id: optional SBI fields, captured in remarks.
	"""
	paid_amount = flt(amount)
	receivable = _resolve_receivable_account(customer, company)
	bank_ledger = _resolve_bank_ledger_account(bank_account)
	cost_center = frappe.db.get_value("Company", company, "cost_center")
	posting_date = _parse_sbi_date(date_time)

	remarks_parts = ["SBI Collection", f"VAN ref: {utr}"]
	if trans_typ:
		remarks_parts.append(f"type: {trans_typ}")
	if ref_id:
		remarks_parts.append(f"ref_id: {ref_id}")
	if request_id:
		remarks_parts.append(f"request_id: {request_id}")
	remarks = ", ".join(remarks_parts)

	pe = frappe.new_doc("Payment Entry")
	pe.payment_type = "Receive"
	pe.company = company
	pe.cost_center = cost_center
	pe.posting_date = posting_date
	pe.party_type = "Customer"
	pe.party = customer
	pe.paid_from = receivable
	pe.paid_to = bank_ledger
	pe.paid_amount = paid_amount
	pe.received_amount = paid_amount
	# Unallocated advance: full amount, no invoice allocation.
	pe.unallocated_amount = paid_amount
	# Bank reference / idempotency key.
	pe.reference_no = utr
	pe.reference_date = posting_date
	pe.bank_account = bank_account
	pe.remarks = remarks

	# Pre-populate account currency/type to avoid ERPNext's get_account_details(),
	# which does an unconditional has_permission("Payment Entry", throw=True) that
	# fails for the Guest caller and ignores all permission flags.
	pe.paid_from_account_currency, pe.paid_from_account_type = _account_currency_and_type(receivable)
	pe.paid_to_account_currency, pe.paid_to_account_type = _account_currency_and_type(bank_ledger)

	# Bypass GL account perms (india_banking idiom) + doctype role perms (Guest caller).
	frappe.flags.ignore_account_permission = True
	pe.flags.ignore_permissions = True
	try:
		pe.setup_party_account_field()
		pe.set_missing_values()
		pe.validate()
		pe.insert(ignore_permissions=True, ignore_mandatory=True)
		# Intentionally NOT submitted - left as a draft for manual reconciliation.
	finally:
		frappe.flags.ignore_account_permission = False

	return pe.name
