# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Authentication business logic for the SBI Collection API.

SBI Authentication contract:
    - Plain dev request:    {"username":"...","password":"..."}
    - Encrypted prod request: the universal {data, hash_digest, session_key}
      envelope, decrypting to the same {username, password} plaintext.
    - Success response: {"status":"SUCCESS","message":"Authentication Successful","token":"<jwt>"}
    - Failure response: {"status":"FAILED","message":"Authentication Failed"}

Security: credentials are always read from Settings (never hardcoded); the
configured password is never returned/logged/echoed; the failure message is
generic (no user-enumeration oracle); username and password are compared in
constant time. Pure business logic — no crypto/logging here.
"""

import hmac
from datetime import UTC, datetime, timedelta

import frappe
import jwt
from frappe import _

from sbi_collection import crypto

SUCCESS_STATUS = "SUCCESS"
FAILURE_STATUS = "FAILED"
SUCCESS_MESSAGE = "Authentication Successful"
FAILURE_MESSAGE = "Authentication Failed"  # generic - never reveals the cause


class AuthenticationService:
	"""Authenticate SBI credentials and issue a bearer token."""

	def decrypt_request(self, envelope, *, client_private_key, sbi_public_key):
		"""Production mode: decrypt + verify the SBI envelope. Raises on tamper."""
		return crypto.decrypt_request(
			envelope,
			client_private_key=client_private_key,
			sbi_public_key=sbi_public_key,
		)

	def validate_request(self, payload):
		"""Require `username` and `password` present and non-empty."""
		for field in ("username", "password"):
			value = payload.get(field)
			if value is None or (isinstance(value, str) and not value.strip()):
				frappe.throw(_("Missing mandatory field: {0}").format(field))

	def authenticate_user(self, username, password):
		"""Constant-time compare against configured SBI credentials.

		Fails closed (returns False) if settings are unconfigured.
		"""
		# get_doc (not get_cached_doc) kept during debugging.
		settings = frappe.get_doc("SBI Collection Settings")
		configured_username = settings.sbi_username or ""
		configured_password = settings.get_password("sbi_password", raise_exception=False) or ""

		username_match = hmac.compare_digest(str(username or ""), str(configured_username))
		password_match = hmac.compare_digest(str(password or ""), str(configured_password))

		# Debug: safe signals only (presence + match booleans, never the values).
		import json as _json

		frappe.log_error(
			title="SBI Auth Debug",
			message=_json.dumps(
				{
					"configured_username_present": bool(configured_username),
					"incoming_username_present": bool(username),
					"configured_password_present": bool(configured_password),
					"incoming_password_present": bool(password),
					"username_match": bool(username_match),
					"password_match": bool(password_match),
					"authenticated": bool(username_match and password_match),
				},
				indent=2,
			),
		)

		return username_match and password_match

	def issue_token(self, username):
		"""Sign and return a JWT (HS256, Settings.jwt_secret, configurable exp)."""
		# get_doc (not get_cached_doc) kept during debugging.
		settings = frappe.get_doc("SBI Collection Settings")
		secret = settings.get_password("jwt_secret", raise_exception=False)
		if not secret:
			frappe.throw(_("SBI Collection Settings: jwt_secret is not configured."))

		expiry_minutes = frappe.utils.cint(settings.token_expiry_minutes) or 60
		now = datetime.now(UTC)
		payload = {
			"sub": username,
			"iat": now,
			"exp": now + timedelta(minutes=expiry_minutes),
		}
		return jwt.encode(payload, secret, algorithm="HS256")

	def build_success_response(self, token):
		"""SBI success payload including the bearer token."""
		return {
			"status": SUCCESS_STATUS,
			"message": SUCCESS_MESSAGE,
			"token": token,
		}

	def build_failure_response(self):
		"""Generic SBI failure payload (no token, no clue which field failed)."""
		return {"status": FAILURE_STATUS, "message": FAILURE_MESSAGE}

	def process(self, *, payload, decrypted):
		"""Run the full authentication flow.

		`payload` is the incoming body (envelope in prod, plaintext in dev);
		`decrypted=True` means dev mode. Returns {response, succeeded, encrypted,
		crypto_failed}. Never raises on expected SBI failures.
		"""
		plaintext = payload

		# Debug: payload shape (keys only) to spot dev-vs-prod routing.
		import json as _json

		frappe.log_error(
			title="SBI Auth Debug",
			message=_json.dumps(
				{
					"step": "process_entry",
					"decrypted_param": decrypted,
					"payload_is_envelope": all(
						k in (payload or {}) for k in ("data", "hash_digest", "session_key")
					),
					"payload_is_plain": all(k in (payload or {}) for k in ("username", "password")),
					"payload_keys": sorted((payload or {}).keys()),
				},
				indent=2,
			),
		)

		if not decrypted:
			try:
				plaintext = self.decrypt_request(
					payload,
					client_private_key=self._client_private_key,
					sbi_public_key=self._sbi_public_key,
				)
			except Exception as decrypt_error:
				# Debug: capture the decrypt failure point.
				frappe.log_error(
					title="SBI Auth Debug",
					message=_json.dumps(
						{
							"step": "decrypt_failed",
							"error_type": type(decrypt_error).__name__,
							"error": str(decrypt_error),
						},
						indent=2,
					),
				)
				# Tampered/malformed request -> plain-JSON failure (no envelope).
				return {
					"response": self.build_failure_response(),
					"succeeded": False,
					"encrypted": False,
					"crypto_failed": True,
				}

		try:
			self.validate_request(plaintext)
		except frappe.ValidationError:
			return {
				"response": self.build_failure_response(),
				"succeeded": False,
				"encrypted": decrypted is False,  # prod->envelope, dev->plain
				"crypto_failed": False,
			}

		username = frappe.utils.cstr(plaintext.get("username")).strip()
		password = frappe.utils.cstr(plaintext.get("password")).strip()

		if not self.authenticate_user(username, password):
			return {
				"response": self.build_failure_response(),
				"succeeded": False,
				"encrypted": decrypted is False,
				"crypto_failed": False,
			}

		# Success - issue the token. Propagate issuance errors to the caller.
		token = self.issue_token(username)
		return {
			"response": self.build_success_response(token),
			"succeeded": True,
			"encrypted": decrypted is False,
			"crypto_failed": False,
		}

	_client_private_key = None
	_sbi_public_key = None

	def with_keys(self, client_private_key, sbi_public_key):
		"""Inject the RSA keys needed for production-mode decryption."""
		self._client_private_key = client_private_key
		self._sbi_public_key = sbi_public_key
		return self


def process(*, payload, decrypted, client_private_key=None, sbi_public_key=None):
	"""Module-level convenience wrapper around AuthenticationService.process."""
	service = AuthenticationService().with_keys(client_private_key, sbi_public_key)
	return service.process(payload=payload, decrypted=decrypted)
