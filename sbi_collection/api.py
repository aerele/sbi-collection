# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""
SBI Collection API endpoints for ERPNext integration.

Routes (all POST):
    /api/method/sbi_collection.api.authenticate
    /api/method/sbi_collection.api.dealer_validation
    /api/method/sbi_collection.api.transaction_post

Each endpoint: create log -> verify token -> decrypt -> service -> encrypt -> log.
See ARCHITECTURE.md for the full flow diagrams and design rationale.
"""

import frappe
import jwt

from sbi_collection import crypto
from sbi_collection.sbi_collection.doctype.sbi_collection_settings.sbi_collection_settings import (
	get_settings,
)
from sbi_collection.services import (
	authentication_service,
	dealer_validation_service,
	transaction_post_service,
)
from sbi_collection.utils.logger import (
	create_api_log,
	mark_failed,
	mark_success,
	update_api_log,
)


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


def _payload_context(payload):
	"""Best-effort extraction of log-enrichment fields (van/amount/ref) from a payload."""
	context = {}
	for key in ("request_id", "van", "amount"):
		if payload.get(key) is not None:
			context[key] = payload.get(key)

	ref = payload.get("utr_no") or payload.get("ref_id")
	if ref is not None:
		context["transaction_reference"] = ref
	return context


def _success_response(message):
	return {"status": "success", "message": message}


def _error_response(message, exception):
	return {"status": "error", "message": f"{message}: {exception}"}


@frappe.whitelist(allow_guest=True)
def _looks_like_envelope(body):
	"""True if the body carries the SBI universal envelope fields."""
	return isinstance(body, dict) and all(k in body for k in ("data", "hash_digest", "session_key"))


class _TokenError(Exception):
	"""Raised when the bearer token is missing, expired, or invalid."""


def _verify_token(settings):
	"""Verify the SBI bearer token from the `token` request header.

	Raises `_TokenError` if missing/expired/invalid, or if `jwt_secret` is
	unconfigured (fail closed). Verified BEFORE decryption so an unauthenticated
	caller can't force a decrypt attempt.
	"""
	# Read from frappe.local.request (works under real HTTP and tests).
	headers = getattr(frappe.local.request, "headers", {}) or {}
	token = headers.get("token", "") if hasattr(headers, "get") else ""
	if not token:
		raise _TokenError("missing token header")

	secret = settings.get_password("jwt_secret", raise_exception=False)
	if not secret:
		raise _TokenError("jwt_secret not configured")

	try:
		jwt.decode(token, secret, algorithms=["HS256"])
	except jwt.PyJWTError as error:
		raise _TokenError(str(error)) from error


@frappe.whitelist(allow_guest=True)
def authenticate():
	"""SBI authentication callback. Issues a JWT on success.

	Routes by body shape: envelope -> production (decrypt/encrypt), plain
	{username, password} -> development (plain JSON). Credentials are never
	logged (the request is stored redacted); the token is redacted in the
	logged response copy only.
	"""
	body = _get_request_payload()
	log_name = create_api_log(api_name="authenticate", request_payload={"request": "<redacted>"})
	try:
		settings = get_settings()
		enable_encryption = bool(settings.enable_encryption)
		is_envelope = _looks_like_envelope(body)

		if is_envelope:
			client_private_key, sbi_public_key = settings.load_keys()
			result = authentication_service.process(
				payload=body,
				decrypted=False,
				client_private_key=client_private_key,
				sbi_public_key=sbi_public_key,
			)
		else:
			client_private_key = sbi_public_key = None
			result = authentication_service.process(payload=body, decrypted=True)

		if result["succeeded"]:
			# Redact the token in the logged copy; return the real token to SBI.
			logged_response = {**result["response"], "token": "<redacted>"}
			mark_success(log_name, response_payload=logged_response)
		else:
			mark_failed(
				log_name,
				error=result["response"].get("message"),
				response_payload=result["response"],
			)

		# Plain JSON for dev mode or crypto failure; envelope only in prod mode.
		encrypt_response = is_envelope and enable_encryption and not result["crypto_failed"]
		if not encrypt_response:
			return result["response"]
		return crypto.encrypt_response(
			result["response"],
			client_private_key=client_private_key,
			sbi_public_key=sbi_public_key,
		)
	except Exception as exception:
		frappe.logger().exception("SBI Collection authenticate failed")
		response = {"status": "FAILED", "message": "Authentication Failed"}
		mark_failed(log_name, error=str(exception), response_payload=response)
		return response


@frappe.whitelist(allow_guest=True)
def dealer_validation():
	"""Validate a dealer/VAN against ERPNext.

	Transport failures (token/decrypt) return plain JSON; business outcomes
	return the encrypted SBI envelope. See ARCHITECTURE.md §7.
	"""
	envelope = _get_request_payload()
	log_name = create_api_log(api_name="dealer_validation", request_payload=envelope)
	try:
		settings = get_settings()
		client_private_key, sbi_public_key = settings.load_keys()

		try:
			_verify_token(settings)
		except _TokenError as token_error:
			frappe.log_error(
				title="SBI Dealer Validation Debug",
				message=f"token_rejected: {token_error}",
			)
			frappe.logger().warning("SBI Collection dealer_validation token rejected: %s", token_error)
			response = {"status_code": "01", "message": "Authentication required"}
			mark_failed(
				log_name,
				error=f"Token rejected: {token_error}",
				response_payload=response,
			)
			return response

		# Debug: payload shape (keys only) for diagnosing dev-vs-prod routing.
		_envelope_keys = sorted(envelope.keys()) if isinstance(envelope, dict) else []
		frappe.log_error(
			title="SBI Dealer Validation Debug",
			message=(
				"process_entry\n"
				f"is_envelope={all(k in envelope for k in ('data', 'hash_digest', 'session_key')) if isinstance(envelope, dict) else False}\n"
				f"payload_keys={_envelope_keys}\n"
				f"enable_encryption={bool(settings.enable_encryption)}"
			),
		)

		try:
			decrypted = crypto.decrypt_request(
				envelope,
				client_private_key=client_private_key,
				sbi_public_key=sbi_public_key,
			)
		except Exception as crypto_error:
			# Debug: capture the decrypt failure point.
			frappe.log_error(
				title="SBI Dealer Validation Debug",
				message=f"decrypt_failed: {type(crypto_error).__name__}: {crypto_error}",
			)
			frappe.logger().warning("SBI Collection dealer_validation crypto failed: %s", crypto_error)
			response = {"status_code": "01", "message": "Decryption/signature failed"}
			mark_failed(
				log_name, error=f"Decryption/signature failed: {crypto_error}", response_payload=response
			)
			return response

		result = dealer_validation_service.process(decrypted)

		update_api_log(
			log_name,
			van=result["van"],
			customer=result["customer"],
			amount=decrypted.get("amount"),
		)
		if result["succeeded"]:
			mark_success(log_name, response_payload=result["response"])
		else:
			mark_failed(
				log_name,
				error=result["response"].get("message"),
				response_payload=result["response"],
			)

		return crypto.encrypt_response(
			result["response"],
			client_private_key=client_private_key,
			sbi_public_key=sbi_public_key,
		)
	except Exception as exception:
		frappe.logger().exception("SBI Collection dealer_validation failed")
		response = {"status_code": "01", "message": "Dealer validation endpoint error"}
		mark_failed(log_name, error=str(exception), response_payload=response)
		return response


@frappe.whitelist(allow_guest=True)
def transaction_post():
	"""Process an SBI inward-collection notification (creates a draft Payment Entry).

	Transport failures (token/decrypt) return plain JSON; business outcomes
	return the encrypted SBI envelope. See ARCHITECTURE.md §7/§11.
	"""
	envelope = _get_request_payload()
	log_name = create_api_log(
		api_name="transaction_post",
		request_payload=envelope,
		**_payload_context(envelope),
	)
	try:
		settings = get_settings()
		client_private_key, sbi_public_key = settings.load_keys()

		try:
			_verify_token(settings)
		except _TokenError as token_error:
			frappe.log_error(
				title="SBI Transaction Post Debug",
				message=f"token_rejected: {token_error}",
			)
			frappe.logger().warning("SBI Collection transaction_post token rejected: %s", token_error)
			response = {"status_code": "01", "message": "Authentication required"}
			mark_failed(
				log_name,
				error=f"Token rejected: {token_error}",
				response_payload=response,
			)
			return response

		# Debug: payload shape (keys only) for diagnosing dev-vs-prod routing.
		_envelope_keys = sorted(envelope.keys()) if isinstance(envelope, dict) else []
		frappe.log_error(
			title="SBI Transaction Post Debug",
			message=(
				"process_entry\n"
				f"is_envelope={all(k in envelope for k in ('data', 'hash_digest', 'session_key')) if isinstance(envelope, dict) else False}\n"
				f"payload_keys={_envelope_keys}\n"
				f"enable_encryption={bool(settings.enable_encryption)}"
			),
		)

		try:
			decrypted = crypto.decrypt_request(
				envelope,
				client_private_key=client_private_key,
				sbi_public_key=sbi_public_key,
			)
		except Exception as crypto_error:
			# Debug: capture the decrypt failure point.
			frappe.log_error(
				title="SBI Transaction Post Debug",
				message=f"decrypt_failed: {type(crypto_error).__name__}: {crypto_error}",
			)
			frappe.logger().warning("SBI Collection transaction_post crypto failed: %s", crypto_error)
			response = {"status_code": "01", "message": "Decryption/signature failed"}
			mark_failed(
				log_name, error=f"Decryption/signature failed: {crypto_error}", response_payload=response
			)
			return response

		result = transaction_post_service.process(decrypted)

		update_api_log(
			log_name,
			van=result["van"],
			customer=result["customer"],
			transaction_reference=result["transaction_reference"],
			amount=decrypted.get("amount"),
		)
		if result["succeeded"]:
			mark_success(log_name, response_payload=result["response"])
		else:
			mark_failed(
				log_name,
				error=result["response"].get("message"),
				response_payload=result["response"],
			)

		return crypto.encrypt_response(
			result["response"],
			client_private_key=client_private_key,
			sbi_public_key=sbi_public_key,
		)
	except Exception as exception:
		frappe.logger().exception("SBI Collection transaction_post failed")
		response = {"status_code": "01", "message": "Transaction post endpoint error"}
		mark_failed(log_name, error=str(exception), response_payload=response)
		return response
