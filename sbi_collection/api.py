# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""
SBI Collection API endpoints for ERPNext integration.

This module exposes the three entry points consumed by the SBI Collection flow.
The current implementation is an initial scaffold only: each endpoint records
the incoming request and acknowledges receipt. Authentication validation,
dealer validation logic, encryption, Payment Entry creation, logging DocTypes
and reconciliation are intentionally deferred to later phases.

Routes (all POST):

    /api/method/sbi_collection.api.authenticate
    /api/method/sbi_collection.api.dealer_validation
    /api/method/sbi_collection.api.transaction_post
"""

import frappe


def _get_request_payload():
	"""Return the JSON body of the current request as a dict.

	Returns an empty dict when the request has no body, an empty body, or a
	body that is not valid JSON, so callers never have to handle the missing
	body case themselves.
	"""
	try:
		if not frappe.request or not frappe.request.data:
			return {}
		payload = frappe.request.get_json()
		return payload if isinstance(payload, dict) else {}
	except Exception:
		return {}


@frappe.whitelist(allow_guest=True)
def authenticate():
	"""SBI authentication callback.

	POST /api/method/sbi_collection.api.authenticate
	"""
	try:
		payload = _get_request_payload()
		frappe.logger().info("SBI Collection authenticate payload: %s", payload)
		return {
			"status": "success",
			"message": "Authentication endpoint reached",
			"payload": payload,
		}
	except Exception as exception:
		frappe.logger().exception("SBI Collection authenticate failed")
		return {
			"status": "error",
			"message": f"Authentication endpoint error: {exception}",
		}


@frappe.whitelist(allow_guest=True)
def dealer_validation():
	"""Validate a dealer/account against ERPNext.

	POST /api/method/sbi_collection.api.dealer_validation
	"""
	try:
		payload = _get_request_payload()
		frappe.logger().info("SBI Collection dealer_validation payload: %s", payload)
		return {
			"status": "success",
			"message": "Dealer validation endpoint reached",
			"payload": payload,

		}
	except Exception as exception:
		frappe.logger().exception("SBI Collection dealer_validation failed")
		return {
			"status": "error",
			"message": f"Dealer validation endpoint error: {exception}",
		}


@frappe.whitelist(allow_guest=True)
def transaction_post():
	"""Record a transaction posted by SBI.

	POST /api/method/sbi_collection.api.transaction_post
	"""
	try:
		payload = _get_request_payload()
		frappe.logger().info("SBI Collection transaction_post payload: %s", payload)
		return {
			"status": "success",
			"message": "Transaction post endpoint reached",
			"payload": payload,

		}
	except Exception as exception:
		frappe.logger().exception("SBI Collection transaction_post failed")
		return {
			"status": "error",
			"message": f"Transaction post endpoint error: {exception}",
		}
