"""Temporary SBI UAT diagnostics. Review and disable before production."""

import json

import frappe

# Retained for UAT at the user's request; no Settings/database flag is introduced.
UAT_DIAGNOSTICS_ENABLED = True


def log_diagnostic(api_name, event, *, error=None, **signals):
	"""Write explicit diagnostics without request metadata, secrets or traceback locals.

	Only pass application-defined events and boolean/status signals. Exception
	locations and types are retained, but messages and source lines are omitted.
	Redact form data while frappe.log_error gathers its request metadata.
	"""
	if not UAT_DIAGNOSTICS_ENABLED:
		return
	try:
		details = {"api": api_name, "event": event, **signals}
		if error is not None:
			details["error_type"] = type(error).__name__
			frames = []
			traceback = error.__traceback__
			while traceback is not None:
				code = traceback.tb_frame.f_code
				frames.append(
					{"file": code.co_filename, "function": code.co_name, "line": traceback.tb_lineno}
				)
				traceback = traceback.tb_next
			details["locations"] = frames
		titles = {
			"authenticate": "SBI Auth Debug",
			"dealer_validation": "SBI Dealer Validation Debug",
			"transaction_post": "SBI Transaction Post Debug",
		}
		form_dict = getattr(frappe.local, "form_dict", None)
		try:
			# Frappe otherwise adds request fields (including username) to metadata.
			frappe.local.form_dict = frappe._dict(request="<redacted>")
			frappe.log_error(
				title=titles.get(api_name, "SBI Request Parsing Debug"),
				message=json.dumps(details, indent=2),
			)
		finally:
			frappe.local.form_dict = form_dict
	except Exception:
		# Diagnostics must never change HTTP status or prevent an encrypted reply.
		pass
