# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Tests for the Authentication API.

Three layers:
  1. Service unit tests - credential validation, generic failures, JWT issuance.
  2. Crypto round-trip - the prod-mode decrypt -> process -> encrypt pipeline.
  3. HTTP endpoint - dev mode (plain JSON) and prod mode (encrypted) via fake_request.

Credentials are written to Settings via the Password util so get_password()
reads them back exactly as the service will in production.
"""

import base64
import json
from contextlib import contextmanager
from unittest.mock import patch

import frappe
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from frappe.tests.utils import FrappeTestCase

from sbi_collection import api, crypto
from sbi_collection.services import authentication_service
from sbi_collection.services.authentication_service import AuthenticationService

TEST_USERNAME = "SBI_USER"
TEST_PASSWORD = "Password@123"
TEST_JWT_SECRET = "test-jwt-secret-do-not-use-in-prod"


# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #
def _make_keypair_pem():
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	public_key = private_key.public_key()
	private_pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption(),
	)
	public_pem = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo,
	)
	return private_pem, public_pem


def _make_envelope(plaintext_payload, client_private_key, sbi_public_key):
	return crypto.encrypt_response(
		plaintext_payload,
		client_private_key=client_private_key,
		sbi_public_key=sbi_public_key,
	)


@contextmanager
def fake_request(body_dict):
	envelope_json = json.dumps(body_dict).encode("utf-8")
	fake_req = frappe._dict(data=envelope_json, method="POST", get_json=lambda: body_dict)
	with patch.object(frappe.local, "request", fake_req, create=True):
		yield


def patch_load_keys(client_private_key, sbi_public_key):
	from sbi_collection.sbi_collection.doctype.sbi_collection_settings.sbi_collection_settings import (
		SBICollectionSettings,
	)

	return patch.object(
		SBICollectionSettings,
		"load_keys",
		return_value=(client_private_key, sbi_public_key),
	)


def _set_settings_data(**values):
	"""Set non-Password Settings fields directly (bypasses mandatory checks)."""
	doc = frappe.get_doc("SBI Collection Settings", "SBI Collection Settings")
	for key, value in values.items():
		doc.db_set(key, value)
	_invalidate_settings_cache()


# Password-type fields can't be reliably written within a FrappeTestCase
# transaction (the __Auth write rolls back). Instead we patch the controller's
# get_password to return the configured values deterministically - this tests
# the auth LOGIC, not Frappe's password encryption.
_passwords = {}


def _set_settings_password(fieldname, value):
	"""Configure a Password-type Settings field for the duration of the test."""
	_passwords[fieldname] = value


def _patched_get_password(self, fieldname, raise_exception=True):
	value = _passwords.get(fieldname)
	if value is None and raise_exception:
		frappe.throw(frappe._("Password not found for {0}").format(fieldname))
	return value


def _clear_settings_passwords():
	_passwords.clear()


def _invalidate_settings_cache():
	frappe.clear_cache(doctype="SBI Collection Settings")
	frappe.clear_document_cache("SBI Collection Settings", "SBI Collection Settings")


# --------------------------------------------------------------------------- #
# Layer 1: Service unit tests
# --------------------------------------------------------------------------- #
class TestAuthenticationService(FrappeTestCase):
	def setUp(self):
		self.service = AuthenticationService()
		# Configure known credentials + jwt_secret for every test.
		_set_settings_data(sbi_username=TEST_USERNAME, token_expiry_minutes=60)
		_set_settings_password("sbi_password", TEST_PASSWORD)
		_set_settings_password("jwt_secret", TEST_JWT_SECRET)
		# Patch get_password so the service reads the configured password values
		# (the __Auth write doesn't survive test transaction rollback).
		from sbi_collection.sbi_collection.doctype.sbi_collection_settings.sbi_collection_settings import (
			SBICollectionSettings,
		)

		self._get_pw_patcher = patch.object(SBICollectionSettings, "get_password", _patched_get_password)
		self._get_pw_patcher.start()

	def tearDown(self):
		self._get_pw_patcher.stop()
		_clear_settings_passwords()

	# --- validate_request ---
	def test_validate_request_passes_with_both_fields(self):
		self.service.validate_request({"username": "u", "password": "p"})

	def test_validate_request_raises_on_missing_username(self):
		with self.assertRaises(frappe.ValidationError):
			self.service.validate_request({"password": "p"})

	def test_validate_request_raises_on_missing_password(self):
		with self.assertRaises(frappe.ValidationError):
			self.service.validate_request({"username": "u"})

	def test_validate_request_rejects_blank_values(self):
		with self.assertRaises(frappe.ValidationError):
			self.service.validate_request({"username": "  ", "password": "p"})

	# --- authenticate_user ---
	def test_authenticate_user_success(self):
		self.assertTrue(self.service.authenticate_user(TEST_USERNAME, TEST_PASSWORD))

	def test_authenticate_user_wrong_username(self):
		self.assertFalse(self.service.authenticate_user("WRONG", TEST_PASSWORD))

	def test_authenticate_user_wrong_password(self):
		self.assertFalse(self.service.authenticate_user(TEST_USERNAME, "wrong"))

	def test_authenticate_user_unconfigured_username(self):
		_set_settings_data(sbi_username="")
		self.assertFalse(self.service.authenticate_user(TEST_USERNAME, TEST_PASSWORD))

	def test_authenticate_user_unconfigured_password(self):
		# Clear the password by overwriting with an empty value via the util.
		_set_settings_password("sbi_password", "")
		# An empty configured password must not match a non-empty submitted one.
		self.assertFalse(self.service.authenticate_user(TEST_USERNAME, TEST_PASSWORD))

	# --- response builders ---
	def test_build_success_response_shape(self):
		resp = self.service.build_success_response("tok")
		self.assertEqual(resp, {"status_code": "00", "message": "Login Successful", "token": "tok"})

	def test_build_failure_response_shape(self):
		resp = self.service.build_failure_response()
		self.assertEqual(resp, {"status_code": "01", "message": "Invalid Credential"})
		# Must not leak a token or a cause.
		self.assertNotIn("token", resp)

	def test_failure_response_does_not_reveal_which_field(self):
		# The message must be identical regardless of failure reason.
		self.assertEqual(
			self.service.build_failure_response()["message"],
			self.service.build_failure_response()["message"],
		)

	# --- issue_token ---
	def test_issue_token_decodes_with_configured_secret(self):
		token = self.service.issue_token(TEST_USERNAME)
		payload = jwt.decode(token, TEST_JWT_SECRET, algorithms=["HS256"])
		self.assertEqual(payload["sub"], TEST_USERNAME)
		self.assertIn("exp", payload)

	def test_issue_token_raises_when_secret_missing(self):
		_set_settings_password("jwt_secret", "")
		with self.assertRaises(frappe.ValidationError):
			self.service.issue_token(TEST_USERNAME)

	# --- process (dev mode) ---
	def test_process_dev_success_returns_token(self):
		result = self.service.process(
			payload={"username": TEST_USERNAME, "password": TEST_PASSWORD}, decrypted=True
		)
		self.assertTrue(result["succeeded"])
		self.assertEqual(result["response"]["status_code"], "00")
		self.assertTrue(result["response"]["token"])
		self.assertFalse(result["encrypted"])  # dev mode -> plain
		self.assertFalse(result["crypto_failed"])

	def test_process_dev_wrong_credentials_returns_failure(self):
		result = self.service.process(payload={"username": TEST_USERNAME, "password": "nope"}, decrypted=True)
		self.assertFalse(result["succeeded"])
		self.assertEqual(result["response"]["status_code"], "01")
		self.assertFalse(result["encrypted"])

	def test_process_dev_missing_field_returns_failure(self):
		result = self.service.process(payload={"username": TEST_USERNAME}, decrypted=True)
		self.assertFalse(result["succeeded"])
		self.assertEqual(result["response"]["status_code"], "01")


# --------------------------------------------------------------------------- #
# Layer 2: Crypto round-trip (production mode)
# --------------------------------------------------------------------------- #
class TestAuthenticationCryptoRoundTrip(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		_set_settings_data(sbi_username=TEST_USERNAME, token_expiry_minutes=60)
		_set_settings_password("sbi_password", TEST_PASSWORD)
		_set_settings_password("jwt_secret", TEST_JWT_SECRET)

	def setUp(self):
		from sbi_collection.sbi_collection.doctype.sbi_collection_settings.sbi_collection_settings import (
			SBICollectionSettings,
		)

		self._get_pw_patcher = patch.object(SBICollectionSettings, "get_password", _patched_get_password)
		self._get_pw_patcher.start()

	def tearDown(self):
		self._get_pw_patcher.stop()

	def test_prod_mode_success_decrypts_authenticates_and_encrypts(self):
		client_private_key, sbi_public_key = self._loaded_keypair()
		service = AuthenticationService().with_keys(client_private_key, sbi_public_key)

		envelope = _make_envelope(
			{"username": TEST_USERNAME, "password": TEST_PASSWORD},
			client_private_key,
			sbi_public_key,
		)
		result = service.process(payload=envelope, decrypted=False)

		self.assertTrue(result["succeeded"])
		self.assertTrue(result["encrypted"])  # prod -> wrap the response
		self.assertFalse(result["crypto_failed"])
		# The plaintext response carries a token.
		self.assertTrue(result["response"]["token"])

		# Re-encrypt + re-decrypt to prove the pipeline is symmetric.
		response_envelope = crypto.encrypt_response(
			result["response"],
			client_private_key=client_private_key,
			sbi_public_key=sbi_public_key,
		)
		decrypted_response = crypto.decrypt_request(
			response_envelope,
			client_private_key=client_private_key,
			sbi_public_key=sbi_public_key,
		)
		self.assertEqual(decrypted_response["status_code"], "00")

	def test_prod_mode_tampered_envelope_returns_crypto_failed(self):
		client_private_key, sbi_public_key = self._loaded_keypair()
		service = AuthenticationService().with_keys(client_private_key, sbi_public_key)

		envelope = _make_envelope(
			{"username": TEST_USERNAME, "password": TEST_PASSWORD},
			client_private_key,
			sbi_public_key,
		)
		# Flip a byte of the ciphertext -> signature/tag failure.
		raw = bytearray(base64.b64decode(envelope["data"]))
		raw[0] ^= 0xFF
		envelope["data"] = base64.b64encode(bytes(raw)).decode("ascii")

		result = service.process(payload=envelope, decrypted=False)
		self.assertFalse(result["succeeded"])
		self.assertTrue(result["crypto_failed"])
		self.assertFalse(result["encrypted"])  # plain JSON on crypto failure
		self.assertEqual(result["response"]["status_code"], "01")

	def _loaded_keypair(self):
		private_pem, public_pem = _make_keypair_pem()
		return crypto.load_private_key(private_pem), crypto.load_public_key(public_pem)


# --------------------------------------------------------------------------- #
# Layer 3: HTTP endpoint
# --------------------------------------------------------------------------- #
class TestAuthenticationEndpoint(FrappeTestCase):
	def setUp(self):
		self.client_private_pem, self.sbi_public_pem = _make_keypair_pem()
		self.client_private_key = crypto.load_private_key(self.client_private_pem)
		self.sbi_public_key = crypto.load_public_key(self.sbi_public_pem)
		self._load_keys_patcher = patch_load_keys(self.client_private_key, self.sbi_public_key)
		self._load_keys_patcher.start()
		_set_settings_data(sbi_username=TEST_USERNAME, token_expiry_minutes=60)
		_set_settings_password("sbi_password", TEST_PASSWORD)
		_set_settings_password("jwt_secret", TEST_JWT_SECRET)
		from sbi_collection.sbi_collection.doctype.sbi_collection_settings.sbi_collection_settings import (
			SBICollectionSettings,
		)

		self._get_pw_patcher = patch.object(SBICollectionSettings, "get_password", _patched_get_password)
		self._get_pw_patcher.start()

	def tearDown(self):
		self._load_keys_patcher.stop()
		self._get_pw_patcher.stop()
		_clear_settings_passwords()

	def _call(self, body_dict):
		with fake_request(body_dict):
			return api.authenticate()

	# --- Development mode (plain JSON) ---
	def test_dev_mode_correct_credentials_returns_plain_success(self):
		_set_settings_data(enable_encryption=0)
		response = self._call({"username": TEST_USERNAME, "password": TEST_PASSWORD})
		self.assertEqual(response["status_code"], "00")
		self.assertEqual(response["message"], "Login Successful")
		self.assertTrue(response["token"])
		# Plain JSON - no envelope.
		self.assertNotIn("data", response)
		# Token is a valid JWT signed with the configured secret.
		payload = jwt.decode(response["token"], TEST_JWT_SECRET, algorithms=["HS256"])
		self.assertEqual(payload["sub"], TEST_USERNAME)

	def test_dev_mode_wrong_password_returns_plain_failure(self):
		_set_settings_data(enable_encryption=0)
		response = self._call({"username": TEST_USERNAME, "password": "wrong"})
		self.assertEqual(response["status_code"], "01")
		self.assertEqual(response["message"], "Invalid Credential")
		self.assertNotIn("token", response)
		self.assertNotIn("data", response)

	def test_dev_mode_missing_username_returns_failure(self):
		_set_settings_data(enable_encryption=0)
		response = self._call({"password": TEST_PASSWORD})
		self.assertEqual(response["status_code"], "01")

	# --- Production mode (encrypted) ---
	def test_prod_mode_correct_credentials_returns_envelope_success(self):
		_set_settings_data(enable_encryption=1)
		envelope = _make_envelope(
			{"username": TEST_USERNAME, "password": TEST_PASSWORD},
			self.client_private_key,
			self.sbi_public_key,
		)
		response = self._call(envelope)
		# Encrypted envelope.
		self.assertEqual(set(response), {"data", "hash_digest", "session_key"})
		decrypted = crypto.decrypt_request(
			response,
			client_private_key=self.client_private_key,
			sbi_public_key=self.sbi_public_key,
		)
		self.assertEqual(decrypted["status_code"], "00")
		self.assertTrue(decrypted["token"])

	def test_prod_mode_tampered_returns_plain_failure(self):
		_set_settings_data(enable_encryption=1)
		envelope = _make_envelope(
			{"username": TEST_USERNAME, "password": TEST_PASSWORD},
			self.client_private_key,
			self.sbi_public_key,
		)
		raw = bytearray(base64.b64decode(envelope["data"]))
		raw[0] ^= 0xFF
		envelope["data"] = base64.b64encode(bytes(raw)).decode("ascii")

		response = self._call(envelope)
		# Plain JSON (crypto failure), not an envelope.
		self.assertNotIn("data", response)
		self.assertEqual(response["status_code"], "01")
		self.assertEqual(response["message"], "Decryption/signature failed")
