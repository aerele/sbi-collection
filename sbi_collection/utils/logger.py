# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Pure data-sink for the `Collection API Log` DocType.

Knows nothing about SBI semantics, crypto, or business logic. Every write is
wrapped in try/except so a logging failure can never break an API response.
"""

import json
from datetime import datetime

import frappe
from frappe.utils import flt, now_datetime

LOG_DOCTYPE = "Collection API Log"


def _pretty(data):
	"""Render `data` as pretty JSON. Falls back to `str(data)` on any error.

	None stays None (so an unset field stays empty rather than storing "null").
	"""
	if data is None:
		return None
	try:
		return json.dumps(data, indent=2, default=str, ensure_ascii=False, sort_keys=True)
	except Exception:
		return str(data)


def _live_request_field(attr, default=None):
	"""Read an attribute off the current Flask request, None-safe."""
	try:
		request = frappe.request
		if request is None:
			return default
		return getattr(request, attr, default)
	except Exception:
		return default


def _live_remote_ip(default=None):
	"""Return the caller IP Frappe resolved for this request, if any."""
	try:
		ip = getattr(frappe.local, "request_ip", None)
		return ip or default
	except Exception:
		return default


def _processing_time_seconds(started_at_str):
	"""Return elapsed seconds from `started_at` to now, or None if unknown."""
	if not started_at_str:
		return None
	try:
		started = datetime.fromisoformat(str(started_at_str))
	except (ValueError, TypeError):
		return None
	delta = (now_datetime() - started).total_seconds()
	return flt(delta, 3) if delta >= 0 else None


def _set_values(name, values):
	"""Persist `values` onto an existing log row, defensively.

	Uses ignore_permissions because the SBI endpoints are allow_guest=True
	(SBI is not a logged-in Desk user). Returns True on success, False on error.
	"""
	if not name or not values:
		return False
	if not frappe.db.exists(LOG_DOCTYPE, name):
		return False
	try:
		frappe.db.set_value(
			LOG_DOCTYPE,
			name,
			values,
			update_modified=False,
		)
		return True
	except Exception:
		frappe.log_error(
			title="Collection API Log update failed",
			message=frappe.get_traceback(with_context=True),
		)
		return False


@frappe.whitelist()
def create_api_log(
	*,
	api_name,
	request_payload=None,
	request_id=None,
	van=None,
	customer=None,
	transaction_reference=None,
	amount=None,
	http_method=None,
	endpoint=None,
	remote_ip=None,
	status="Pending",
):
	"""Create a Collection API Log row in `Pending` state. Returns its name.

	Transport fields (http_method/endpoint/remote_ip) are auto-filled from the
	live request when the caller doesn't supply them. `request_payload` is
	stored pretty-printed. Never raises - on failure it logs to Error Log and
	returns None, so callers can treat the log name as optional.
	"""
	try:
		doc = frappe.new_doc(LOG_DOCTYPE)
		doc.api_name = api_name
		doc.status = status
		doc.started_at = now_datetime()
		doc.request_id = request_id
		doc.van = van
		doc.customer = customer
		doc.transaction_reference = transaction_reference
		doc.amount = flt(amount) if amount not in (None, "") else None
		doc.http_method = http_method or _live_request_field("method")
		doc.endpoint = endpoint or _live_request_field("path")
		doc.remote_ip = remote_ip or _live_remote_ip()
		doc.request_payload = _pretty(request_payload)
		doc.insert(ignore_permissions=True)
		return doc.name
	except Exception:
		frappe.log_error(
			title="Collection API Log creation failed",
			message=frappe.get_traceback(with_context=True),
		)
		return None


def update_api_log(name, **fields):
	"""Patch arbitrary fields on an existing log row (best-effort).

	Any dict-like value in `fields` that is a payload (e.g. `request_payload`,
	`response_payload`) is pretty-printed automatically.
	"""
	if not fields:
		return
	payload_keys = {"request_payload", "response_payload"}
	values = {
		key: (_pretty(value) if key in payload_keys else value)
		for key, value in fields.items()
		if value is not None
	}
	_set_values(name, values)


def mark_success(name, *, response_payload=None, **extra):
	"""Mark a log row as Success, optionally recording the response payload.

	Computes `processing_time` from the row's `started_at`. `extra` is merged
	into the update (e.g. van/customer resolved during processing).
	"""
	values = {"status": "Success"}
	if response_payload is not None:
		values["response_payload"] = _pretty(response_payload)
	values.update(extra)

	started_at = frappe.db.get_value(LOG_DOCTYPE, name, "started_at")
	elapsed = _processing_time_seconds(started_at)
	if elapsed is not None:
		values["processing_time"] = elapsed

	_set_values(name, values)


def mark_failed(name, *, error, response_payload=None, **extra):
	"""Mark a log row as Failed with an error message + optional response payload.

	The full stack trace is written to Error Log via `frappe.log_error` (called
	by `_set_values` on failure) rather than stored inline, to keep the log row
	compact - matching the reference pattern. `error` should be a short string.

	`response_payload`, when given, is pretty-printed and stored in the log row's
	`response_payload` field - mirroring `mark_success`. Pass the actual response
	dict that was returned to the caller so the log records what the caller
	received, not just the short error string.
	"""
	values = {"status": "Failed", "error_message": str(error)}
	if response_payload is not None:
		values["response_payload"] = _pretty(response_payload)
	values.update(extra)
	_set_values(name, values)
