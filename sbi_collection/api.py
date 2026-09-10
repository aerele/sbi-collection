# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""SBI callbacks: verify/decrypt -> business validation -> encrypt, always HTTP 200."""

import json

import frappe
import jwt
from werkzeug.wrappers import Response

from sbi_collection import crypto
from sbi_collection.sbi_collection.doctype.sbi_collection_settings.sbi_collection_settings import (
	get_settings,
)
from sbi_collection.services import (
	authentication_service,
	dealer_validation_service,
	transaction_post_service,
)
from sbi_collection.utils.diagnostics import log_diagnostic
from sbi_collection.utils.logger import create_api_log, mark_failed, mark_success, update_api_log

ENVELOPE_FIELDS = ("data", "hash_digest", "session_key")
ENDPOINTS = ("authenticate", "dealer_validation", "transaction_post")


def _http_response(payload):
	"""Return SBI JSON directly; Frappe otherwise wraps it under ``message``."""
	request = getattr(frappe, "request", None)
	if request is not None and callable(getattr(request, "get_data", None)):
		return Response(
			json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
			status=200,
			content_type="application/json",
		)
	return payload


def _get_request_payload():
	"""Read JSON even when the client's Content-Type prevents get_json()."""
	try:
		request = frappe.request
		if not request:
			return {}
		# Cache the raw body before any client/parser code can consume it.
		get_data = getattr(request, "get_data", None)
		raw = get_data(cache=True) if callable(get_data) else request.data
		if not raw:
			log_diagnostic("request", "empty_body")
			return {}
		try:
			payload = request.get_json()
		except Exception as error:
			log_diagnostic("request", "get_json_failed", error=error)
			payload = None
		if payload is None:
			payload = json.loads(raw)
			log_diagnostic("request", "raw_json_fallback", is_object=isinstance(payload, dict))
		return payload if isinstance(payload, dict) else {}
	except Exception as error:
		log_diagnostic("request", "body_parse_failed", error=error)
		return {}


def _looks_like_envelope(body):
	return isinstance(body, dict) and all(
		isinstance(body.get(key), str) and body[key] for key in ENVELOPE_FIELDS
	)


def _failure(message, api_name, payload=None):
	response = {"status_code": "01", "message": message}
	if api_name == "dealer_validation":
		response["request_id"] = (payload or {}).get("request_id") or ""
	return response


def _safe_log(function, *args, **kwargs):
	"""A log failure must never change a bank response or expose request locals."""
	try:
		return function(*args, **kwargs)
	except Exception:
		return None


class _TokenError(Exception):
	"""Missing, expired or invalid SBI bearer token."""


def _verify_token(settings):
	"""Check the token after envelope verification, before any business processing."""
	headers = getattr(frappe.local.request, "headers", {}) or {}
	token = headers.get("token", "")
	secret = settings.get_password("jwt_secret", raise_exception=False)
	if not token or not secret:
		raise _TokenError("Invalid token")
	try:
		jwt.decode(token, secret, algorithms=["HS256"])
	except jwt.PyJWTError:
		raise _TokenError("Invalid token") from None


def _handle(api_name, service):
	message_log = getattr(frappe.local, "message_log", None)
	message_count = len(message_log) if message_log is not None else 0
	body = _get_request_payload()
	# Never store arbitrary input: malformed bodies may contain credentials/tokens.
	log_name = _safe_log(create_api_log, api_name=api_name, request_payload={"request": "<redacted>"})
	keys = None
	payload = None
	secure_response = False
	response = _failure("Decryption/signature failed", api_name)
	stage = "settings_load"
	try:
		settings = get_settings()
		log_diagnostic(
			api_name,
			"process_entry",
			is_envelope=_looks_like_envelope(body),
			enable_encryption=bool(settings.enable_encryption),
		)
		# Plain authentication is an explicit local-development opt-out only.
		plain_auth = (
			api_name == "authenticate"
			and settings.enable_encryption in (0, "0", False)
			and not any(key in body for key in ENVELOPE_FIELDS)
		)
		if plain_auth:
			payload = body
		else:
			stage = "envelope_validation"
			if not _looks_like_envelope(body):
				raise ValueError("Invalid envelope")
			stage = "key_load"
			client_private_key, sbi_public_key = settings.load_keys()
			keys = {"client_private_key": client_private_key, "sbi_public_key": sbi_public_key}
			stage = "decrypt"
			payload = crypto.decrypt_request(body, **keys)
			secure_response = True
			log_diagnostic(api_name, "decrypt_success")

		# A verified JSON payload of the wrong type is still answered securely.
		if not isinstance(payload, dict):
			payload = {}
		response = _failure("Invalid request", api_name, payload)
		try:
			if api_name == "authenticate":
				result = service.process(payload=payload, decrypted=True)
			else:
				_verify_token(settings)
				result = service.process(payload)
				_safe_log(
					update_api_log,
					log_name,
					request_id=payload.get("request_id"),
					van=result.get("van"),
					customer=result.get("customer"),
					transaction_reference=result.get("transaction_reference"),
					amount=payload.get("amount"),
				)
			response = result["response"]
		except _TokenError:
			log_diagnostic(api_name, "token_rejected")
			response = _failure("Invalid token", api_name, payload)
		except Exception as error:
			log_diagnostic(api_name, "processing_failed", error=error)
			# Includes Frappe ValidationError: no 417, traceback, or sensitive locals.
			response = _failure("Request processing failed", api_name, payload)
	except Exception as error:
		log_diagnostic(api_name, f"{stage}_failed", error=error)
		# Malformed/unverifiable envelope or unavailable keys: controlled plain failure.
		pass

	logged_response = {**response}
	if "token" in logged_response:
		logged_response["token"] = "<redacted>"
	try:
		wire_response = crypto.encrypt_response(response, **keys) if secure_response else response
	except Exception as error:
		log_diagnostic(api_name, "response_encryption_failed", error=error)
		wire_response = _failure("Response encryption failed", api_name, payload)
		logged_response = wire_response
	log_diagnostic(
		api_name,
		"response_ready",
		status_code=logged_response["status_code"],
		encrypted=_looks_like_envelope(wire_response),
	)
	if logged_response["status_code"] == "00":
		_safe_log(mark_success, log_name, response_payload=logged_response)
	else:
		_safe_log(mark_failed, log_name, error=logged_response["message"], response_payload=logged_response)
	frappe.local.response["http_status_code"] = 200
	# Caught frappe.throw() calls may have queued plaintext framework messages.
	if message_log is not None:
		del message_log[message_count:]
	return wire_response


@frappe.whitelist(allow_guest=True)
def authenticate():
	"""Issue an SBI JWT; plaintext is allowed only with encryption disabled."""
	return _http_response(_handle("authenticate", authentication_service))


@frappe.whitelist(allow_guest=True)
def dealer_validation():
	"""Validate a VAN and amount, echoing the optional request_id."""
	return _http_response(_handle("dealer_validation", dealer_validation_service))


@frappe.whitelist(allow_guest=True)
def transaction_post():
	"""SBI MIS callback: create a draft Payment Entry with the existing UTR guard."""
	return _http_response(_handle("transaction_post", transaction_post_service))


def normalize_parse_failure(request, response):
	"""Handle JSON rejected by Frappe's make_form_dict before endpoint dispatch.

	Only SBI POST JSON parse failures (417) are normalized; unrelated framework
	and infrastructure failures retain their original HTTP behavior.
	"""
	paths = {f"/api/method/sbi_collection.api.{name}": name for name in ENDPOINTS}
	api_name = paths.get(request.path)
	if not api_name or request.method != "POST" or response.status_code != 417 or not request.is_json:
		return
	try:
		parsed = json.loads(request.get_data())
		if isinstance(parsed, dict | list):
			return
	except (ValueError, UnicodeError):
		pass
	response.status_code = 200
	log_diagnostic(api_name, "framework_parse_failure_normalized")
	response.mimetype = "application/json"
	response.set_data(json.dumps(_failure("Decryption/signature failed", api_name)))
