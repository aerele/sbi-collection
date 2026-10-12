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

from contextlib import contextmanager

import frappe
from erpnext.accounts.party import get_party_gle_account, get_party_gle_currency
from erpnext.controllers.accounts_controller import validate_account_head
from frappe.utils import cint, flt, getdate

# SBI date_time format (per the integration document) is DD-MM-YYYY.
SBI_DATE_FORMAT = "%d-%m-%Y"


def _validate_payment_entry_user(user):
	"""Require an enabled System User for accounting work."""
	if not user:
		frappe.throw(frappe._("SBI Collection Settings: payment_entry_user is not configured"))
	if user == "Guest":
		frappe.throw(frappe._("Payment Entry User cannot be Guest"))

	row = frappe.db.get_value("User", user, ["enabled", "user_type"], as_dict=True)
	if not row:
		frappe.throw(frappe._("Payment Entry User {0} does not exist").format(user))
	if not cint(row.enabled):
		frappe.throw(frappe._("Payment Entry User {0} is disabled").format(user))
	if row.user_type != "System User":
		frappe.throw(frappe._("Payment Entry User {0} must be a System User").format(user))

	for permission_type in ("read", "create"):
		if not frappe.has_permission("Payment Entry", permission_type, user=user):
			frappe.throw(
				frappe._("Payment Entry User {0} requires {1} permission on Payment Entry").format(
					user, permission_type
				)
			)

	return user


@contextmanager
def _payment_entry_user_scope(user):
	"""Run ERPNext accounting validation as the configured integration user."""
	user = _validate_payment_entry_user(user)
	previous_user = frappe.session.user
	frappe.set_user(user)
	try:
		yield
	finally:
		frappe.set_user(previous_user)


def _get_configured_receivable_account(customer, company):
	"""Resolve Customer -> Customer Group -> Company receivable configuration."""
	account = frappe.db.get_value(
		"Party Account",
		{"parenttype": "Customer", "parent": customer, "company": company},
		"account",
	)
	if account:
		return account

	customer_group = frappe.get_cached_value("Customer", customer, "customer_group")
	if customer_group:
		account = frappe.db.get_value(
			"Party Account",
			{"parenttype": "Customer Group", "parent": customer_group, "company": company},
			"account",
		)
	if account:
		return account

	return frappe.get_cached_value("Company", company, "default_receivable_account")


def _validate_receivable_account(account, company):
	"""Validate a trusted receivable account without applying Guest permissions."""
	row = frappe.db.get_value(
		"Account",
		account,
		["company", "account_type", "account_currency", "is_group", "disabled"],
		as_dict=True,
	)
	if not row:
		frappe.throw(frappe._("Receivable Account {0} does not exist").format(account))

	# Reuse ERPNext's core company and ledger-vs-group validation.
	validate_account_head(0, account, company, frappe._("Receivable"))
	if cint(row.disabled):
		frappe.throw(frappe._("Receivable Account {0} is disabled").format(account))
	if row.account_type != "Receivable":
		frappe.throw(frappe._("Account {0} must have Account Type Receivable").format(account))
	if not row.account_currency:
		frappe.throw(frappe._("Receivable Account {0} has no currency configured").format(account))

	return account


def _resolve_receivable_account(customer, company):
	"""Return the trusted receivable account without Guest permission checks.

	ERPNext's public ``get_party_account`` performs an unconditional Account
	permission check in some versions. The SBI endpoint runs as Guest after its
	JWT is verified, so resolve the same trusted master-data hierarchy directly.
	"""
	account = _get_configured_receivable_account(customer, company)

	# Match ERPNext's existing-ledger compatibility rule: a party that already
	# has GL activity must continue on an account with that ledger currency.
	existing_currency = get_party_gle_currency("Customer", customer, company)
	if existing_currency:
		account_currency = (
			frappe.get_cached_value("Account", account, "account_currency") if account else None
		)
		if account_currency != existing_currency:
			account = get_party_gle_account("Customer", customer, company)

	if not account:
		frappe.throw(
			frappe._(
				"No receivable account found for Customer {0} in company {1}. "
				"Configure the Customer, Customer Group, or Company receivable account."
			).format(customer, company)
		)
	return _validate_receivable_account(account, company)


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
	payment_entry_user,
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
		payment_entry_user: dedicated System User used for ERPNext accounting validation.
		trans_typ, ref_id, request_id: optional SBI fields, captured in remarks.
	"""
	with _payment_entry_user_scope(payment_entry_user):
		return _create_payment_entry(
			customer=customer,
			company=company,
			amount=amount,
			utr=utr,
			date_time=date_time,
			bank_account=bank_account,
			trans_typ=trans_typ,
			ref_id=ref_id,
			request_id=request_id,
		)


def _create_payment_entry(
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
	"""Build and insert the draft while already running as the integration user."""
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

	# Pre-populate stable account metadata. ERPNext versions that also require
	# account balances may still call get_account_details(); that is safe because
	# this function runs as the configured, least-privilege integration user.
	pe.paid_from_account_currency, pe.paid_from_account_type = _account_currency_and_type(receivable)
	pe.paid_to_account_currency, pe.paid_to_account_type = _account_currency_and_type(bank_ledger)

	pe.setup_party_account_field()
	pe.set_missing_values()
	pe.validate()
	pe.insert()
	# Intentionally NOT submitted - left as a draft for manual reconciliation.

	return pe.name
