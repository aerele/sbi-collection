# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""SBI credential validation and JWT issuance with the latest UAT response contract."""

import hmac
from datetime import UTC, datetime, timedelta

import frappe
import jwt

from sbi_collection import crypto
from sbi_collection.utils.diagnostics import log_diagnostic

SUCCESS_STATUS = "00"
FAILURE_STATUS = "01"
SUCCESS_MESSAGE = "Login Successful"
FAILURE_MESSAGE = "Invalid Credential"


class AuthenticationService:
	"""Authenticate SBI credentials and issue a bearer token."""

	def decrypt_request(self, envelope, *, client_private_key, sbi_public_key):
		return crypto.decrypt_request(
			envelope, client_private_key=client_private_key, sbi_public_key=sbi_public_key
		)

	def validate_request(self, payload):
		"""Require nonempty string credentials without adding Frappe message logs."""
		for field in ("username", "password"):
			value = payload.get(field)
			if not isinstance(value, str) or not value.strip():
				raise frappe.ValidationError("Invalid Credential")

	def authenticate_user(self, username, password):
		"""Constant-time comparison; unconfigured credentials fail closed."""
		settings = frappe.get_doc("SBI Collection Settings")
		configured_username = settings.sbi_username or ""
		configured_password = settings.get_password("sbi_password", raise_exception=False) or ""
		username_match = hmac.compare_digest(
			str(username or "").encode("utf-8"), str(configured_username).encode("utf-8")
		)
		password_match = hmac.compare_digest(
			str(password or "").encode("utf-8"), str(configured_password).encode("utf-8")
		)
		log_diagnostic(
			"authenticate",
			"credential_check",
			configured_username_present=bool(configured_username),
			configured_password_present=bool(configured_password),
			incoming_username_present=bool(username),
			incoming_password_present=bool(password),
			username_match=username_match,
			password_match=password_match,
		)
		return bool(configured_username and configured_password and username_match and password_match)

	def issue_token(self, username):
		settings = frappe.get_doc("SBI Collection Settings")
		secret = settings.get_password("jwt_secret", raise_exception=False)
		if not secret:
			raise frappe.ValidationError("SBI Collection Settings: jwt_secret is not configured.")
		expiry_minutes = frappe.utils.cint(settings.token_expiry_minutes) or 60
		now = datetime.now(UTC)
		return jwt.encode(
			{"sub": username, "iat": now, "exp": now + timedelta(minutes=expiry_minutes)},
			secret,
			algorithm="HS256",
		)

	def build_success_response(self, token):
		return {"status_code": SUCCESS_STATUS, "message": SUCCESS_MESSAGE, "token": token}

	def build_failure_response(self):
		return {"status_code": FAILURE_STATUS, "message": FAILURE_MESSAGE}

	def process(self, *, payload, decrypted):
		"""Return a business result; retain the crypto wrapper for service callers."""
		plaintext = payload
		if not decrypted:
			try:
				plaintext = self.decrypt_request(
					payload,
					client_private_key=self._client_private_key,
					sbi_public_key=self._sbi_public_key,
				)
			except Exception as error:
				log_diagnostic("authenticate", "decrypt_failed", error=error)
				return {
					"response": {"status_code": FAILURE_STATUS, "message": "Decryption/signature failed"},
					"succeeded": False,
					"encrypted": False,
					"crypto_failed": True,
				}

		if not isinstance(plaintext, dict):
			plaintext = {}
		response = self.build_failure_response()
		succeeded = False
		try:
			self.validate_request(plaintext)
		except frappe.ValidationError:
			log_diagnostic("authenticate", "credentials_missing_or_invalid")
		else:
			username = plaintext["username"].strip()
			password = plaintext["password"].strip()
			if self.authenticate_user(username, password):
				response = self.build_success_response(self.issue_token(username))
				succeeded = True
		return {
			"response": response,
			"succeeded": succeeded,
			"encrypted": not decrypted,
			"crypto_failed": False,
		}

	_client_private_key = None
	_sbi_public_key = None

	def with_keys(self, client_private_key, sbi_public_key):
		self._client_private_key = client_private_key
		self._sbi_public_key = sbi_public_key
		return self


def process(*, payload, decrypted, client_private_key=None, sbi_public_key=None):
	service = AuthenticationService().with_keys(client_private_key, sbi_public_key)
	return service.process(payload=payload, decrypted=decrypted)
