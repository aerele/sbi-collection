# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Tests for the Dealer Validation API.

Three layers:
  1. Service unit tests (no crypto, no HTTP) - the SBI business rules.
  2. Crypto round-trip - proves the full decrypt -> process -> encrypt pipeline.
  3. HTTP endpoint - exercises api.dealer_validation with a real encrypted
     request injected into frappe.local.request.

Keys are generated in-memory per test (no fixtures, no Attach files).
"""

import base64
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import frappe
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from frappe.tests.utils import FrappeTestCase

from sbi_collection import api, crypto
from sbi_collection.services import dealer_validation_service
from sbi_collection.services.dealer_validation_service import DealerValidationService

TEST_JWT_SECRET = "dealer-validation-test-secret"
_UNSET = object()  # sentinel: distinguishes "default valid token" from token=None/""


# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #
def _make_keypair_pem():
	"""Return (client_private_pem, sbi_public_pem) for a fresh 2048-bit RSA pair.

	Both pems are bytes so they can be fed to crypto.load_private_key / load_public_key
	directly, or written to disk for Attach-based tests.
	"""
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
	"""Wrap a plaintext dict in the SBI universal envelope (data/hash_digest/session_key)."""
	return crypto.encrypt_response(
		plaintext_payload,
		client_private_key=client_private_key,
		sbi_public_key=sbi_public_key,
	)


@contextmanager
def fake_request(body_dict, token=None):
	"""Inject `body_dict` (and optional `token` header) as the request for one block.

	The endpoint reads the body via _get_request_payload -> frappe.request.get_json()
	and the bearer token via frappe.get_request_header("token"). We patch
	frappe.request to a small stub carrying both.
	"""
	envelope_json = json.dumps(body_dict).encode("utf-8")
	headers = {"token": token} if token else {}
	fake_req = frappe._dict(
		data=envelope_json,
		method="POST",
		headers=headers,
		get_json=lambda: body_dict,
	)
	with patch.object(frappe.local, "request", fake_req, create=True):
		yield


def patch_load_keys(client_private_key, sbi_public_key):
	"""Patch SBI Collection Settings.load_keys to return the given key objects.

	The endpoint test verifies orchestration (logging, decrypt, service, encrypt,
	error handling) - not the Attach-file plumbing, which is covered by the
	crypto module's own tests. Patching load_keys lets us inject an in-memory
	keypair without creating real File attachments.
	"""
	from sbi_collection.sbi_collection.doctype.sbi_collection_settings.sbi_collection_settings import (
		SBICollectionSettings,
	)

	return patch.object(
		SBICollectionSettings,
		"load_keys",
		return_value=(client_private_key, sbi_public_key),
	)


def patch_get_password(jwt_secret):
	"""Patch SBICollectionSettings.get_password to return `jwt_secret` for jwt_secret.

	The token verifier reads the secret via settings.get_password("jwt_secret").
	Password-type fields can't be reliably written within a test transaction
	(__Auth rolls back), so we patch the read - same approach as test_authentication.
	"""
	from sbi_collection.sbi_collection.doctype.sbi_collection_settings.sbi_collection_settings import (
		SBICollectionSettings,
	)

	def _get_password(self, fieldname, raise_exception=True):
		if fieldname == "jwt_secret":
			return jwt_secret
		return None

	return patch.object(SBICollectionSettings, "get_password", _get_password)


def _set_jwt_secret(secret):
	"""No-op kept for symmetry; actual seeding happens via patch_get_password."""
	return None


def _make_customer(name, van):
	"""Create a Customer and set its collection_van directly."""
	customer_group = frappe.db.get_single_value("Selling Settings", "customer_group") or frappe.db.get_value(
		"Customer Group", {"is_group": 0}
	)
	territory = frappe.db.get_value("Territory", {"is_group": 0})
	doc = frappe.get_doc(
		{
			"doctype": "Customer",
			"customer_name": name,
			"customer_group": customer_group,
			"territory": territory,
		}
	)
	doc.insert(ignore_permissions=True)
	if doc.name != name:
		doc.rename(name)
	frappe.db.set_value("Customer", doc.name, "collection_van", van)
	return doc.name


# --------------------------------------------------------------------------- #
# Layer 1: Service unit tests
# --------------------------------------------------------------------------- #
class TestDealerValidationService(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		# Ensure the collection_van custom field column exists for lookups.
		from sbi_collection.install import make_custom_fields

		make_custom_fields()

	def setUp(self):
		self.service = DealerValidationService()
		self._customers = []

	def tearDown(self):
		for name in self._customers:
			frappe.delete_doc("Customer", name, force=1, ignore_permissions=True)

	def _seed_customer(self, name, van):
		cust = _make_customer(name, van)
		self._customers.append(cust)
		return cust

	# --- validate_request ---
	def test_validate_request_passes_with_all_mandatory_fields(self):
		self.service.validate_request(
			{"van": "NEDFER00000001", "amount": "300.00", "date_time": "12-05-2023"}
		)  # no exception

	def test_validate_request_raises_on_each_missing_field(self):
		for missing in ("van", "amount", "date_time"):
			with self.subTest(missing=missing):
				payload = {"van": "V", "amount": "1.00", "date_time": "01-01-2023"}
				payload.pop(missing)
				with self.assertRaises(frappe.ValidationError):
					self.service.validate_request(payload)

	def test_validate_request_rejects_blank_string_values(self):
		with self.assertRaises(frappe.ValidationError):
			self.service.validate_request({"van": "   ", "amount": "1.00", "date_time": "01-01-2023"})

	# --- extract_van ---
	def test_extract_van_strips_whitespace(self):
		self.assertEqual(self.service.extract_van({"van": "  NEDFER001  "}), "NEDFER001")

	# --- get_customer_by_van ---
	def test_get_customer_by_van_returns_docname_when_present(self):
		self._seed_customer("DV-CUST-FOUND", "NEDFER00000099")
		self.assertEqual(self.service.get_customer_by_van("NEDFER00000099"), "DV-CUST-FOUND")

	def test_get_customer_by_van_returns_none_when_absent(self):
		self.assertIsNone(self.service.get_customer_by_van("DOES-NOT-EXIST"))

	def test_get_customer_by_van_returns_none_for_empty_van(self):
		self.assertIsNone(self.service.get_customer_by_van(""))

	# --- response builders (exact SBI shape) ---
	def test_build_success_response_shape(self):
		self.assertEqual(
			self.service.build_success_response("DV-CUST-FOUND", "2026091113533000001"),
			{"status_code": "00", "message": "Success", "request_id": "2026091113533000001"},
		)

	def test_build_failure_response_shape(self):
		self.assertEqual(
			self.service.build_failure_response("Dealer not found", "2026091113533000002"),
			{"status_code": "01", "message": "Dealer not found", "request_id": "2026091113533000002"},
		)

	def test_generate_request_id_uses_timestamp_and_atomic_series(self):
		with (
			patch.object(
				frappe.utils,
				"now_datetime",
				return_value=datetime(2026, 9, 11, 13, 53, 30),
			),
			patch.object(
				dealer_validation_service,
				"make_autoname",
				return_value="2026091113533000001",
			) as make_autoname,
		):
			self.assertEqual(
				dealer_validation_service.generate_request_id(),
				"2026091113533000001",
			)
		make_autoname.assert_called_once_with("20260911135330.#####")

	# --- process (orchestration) ---
	def test_process_success_when_customer_exists(self):
		self._seed_customer("DV-CUST-OK", "NEDFER00000001")
		result = self.service.process(
			{"van": "NEDFER00000001", "amount": "300.00", "date_time": "12-05-2023"}
		)
		self.assertTrue(result["succeeded"])
		self.assertEqual(result["van"], "NEDFER00000001")
		self.assertEqual(result["customer"], "DV-CUST-OK")
		self.assertEqual(result["response"]["status_code"], "00")

	def test_process_failure_when_customer_not_found(self):
		result = self.service.process({"van": "UNKNOWN-VAN", "amount": "300.00", "date_time": "12-05-2023"})
		self.assertFalse(result["succeeded"])
		self.assertIsNone(result["customer"])
		self.assertEqual(result["response"]["status_code"], "01")
		self.assertEqual(result["response"]["message"], "Invalid Van")

	def test_process_failure_when_field_missing(self):
		result = self.service.process({"van": "NEDFER00000001"})  # amount/date_time missing
		self.assertFalse(result["succeeded"])
		self.assertEqual(result["response"]["status_code"], "01")


# --------------------------------------------------------------------------- #
# Layer 2: Crypto round-trip integration
# --------------------------------------------------------------------------- #
class TestDealerValidationCryptoRoundTrip(FrappeTestCase):
	def test_encrypt_decrypt_process_encrypt_decrypt(self):
		"""Full pipeline without HTTP: SBI envelope -> service -> SBI envelope."""
		client_private_key, sbi_public_key = self._loaded_keypair()

		sbi_request = {"van": "ROUNDTRIP-VAN", "amount": "150.00", "date_time": "03-04-2026"}
		# No customer seeded -> the service will return a (01) failure. That's
		# fine; we only care that the crypto round-trips through the service.
		envelope = _make_envelope(sbi_request, client_private_key, sbi_public_key)

		decrypted = crypto.decrypt_request(
			envelope,
			client_private_key=client_private_key,
			sbi_public_key=sbi_public_key,
		)
		self.assertEqual(decrypted, sbi_request)

		result = dealer_validation_service.process(decrypted)
		self.assertEqual(result["response"]["status_code"], "01")  # no such customer

		# Encrypt the service response and decrypt it back.
		response_envelope = crypto.encrypt_response(
			result["response"],
			client_private_key=client_private_key,
			sbi_public_key=sbi_public_key,
		)
		# Envelope shape per the SBI doc.
		self.assertEqual(set(response_envelope), {"data", "hash_digest", "session_key"})
		decrypted_response = crypto.decrypt_request(
			response_envelope,
			client_private_key=client_private_key,
			sbi_public_key=sbi_public_key,
		)
		self.assertEqual(decrypted_response, result["response"])

	def _loaded_keypair(self):
		private_pem, public_pem = _make_keypair_pem()
		return crypto.load_private_key(private_pem), crypto.load_public_key(public_pem)


# --------------------------------------------------------------------------- #
# Layer 3: HTTP endpoint
# --------------------------------------------------------------------------- #
class TestDealerValidationEndpoint(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		from sbi_collection.install import make_custom_fields

		make_custom_fields()

	def setUp(self):
		self._cleanup = []  # Customer names to delete
		# In-memory keypair loaded for crypto. We patch load_keys() so the
		# endpoint gets these objects without needing File attachments on disk.
		self.client_private_pem, self.sbi_public_pem = _make_keypair_pem()
		self.client_private_key = crypto.load_private_key(self.client_private_pem)
		self.sbi_public_key = crypto.load_public_key(self.sbi_public_pem)
		self._load_keys_patcher = patch_load_keys(self.client_private_key, self.sbi_public_key)
		self._load_keys_patcher.start()
		# Patch get_password so _verify_token can read the jwt_secret, and mint a
		# valid token that the endpoint will accept.
		self._get_pw_patcher = patch_get_password(TEST_JWT_SECRET)
		self._get_pw_patcher.start()
		self.valid_token = jwt.encode(
			{"sub": "SBI_USER", "exp": datetime.now(UTC) + timedelta(hours=1)},
			TEST_JWT_SECRET,
			algorithm="HS256",
		)

	def tearDown(self):
		self._load_keys_patcher.stop()
		self._get_pw_patcher.stop()
		for name in self._cleanup:
			try:
				frappe.delete_doc("Customer", name, force=1, ignore_permissions=True)
			except Exception:
				pass

	def _seed_customer(self, name, van):
		cust = _make_customer(name, van)
		self._cleanup.append(cust)
		return cust

	def _call_endpoint(self, body_dict, token=_UNSET):
		"""Invoke api.dealer_validation. token=_UNSET (default) -> valid token."""
		effective = self.valid_token if token is _UNSET else token
		with fake_request(body_dict, token=effective):
			return api.dealer_validation()

	def test_endpoint_success_returns_encrypted_envelope(self):
		"""Happy path: seeded customer, valid encrypted request -> 00 response."""
		van = "NEDFER00000077"
		self._seed_customer("DV-ENDPOINT-OK", van)

		envelope = _make_envelope(
			{"van": van, "amount": "300.00", "date_time": "12-05-2023"},
			self.client_private_key,
			self.sbi_public_key,
		)
		response = self._call_endpoint(envelope)

		# Response must be the SBI universal envelope.
		self.assertEqual(set(response), {"data", "hash_digest", "session_key"})
		decrypted = crypto.decrypt_request(
			response,
			client_private_key=self.client_private_key,
			sbi_public_key=self.sbi_public_key,
		)
		self.assertEqual(decrypted["status_code"], "00")
		self.assertEqual(decrypted["message"], "Success")

	def test_endpoint_unknown_van_returns_encrypted_failure(self):
		"""Unknown VAN -> business failure -> encrypted envelope with status 01."""
		envelope = _make_envelope(
			{"van": "NO-SUCH-VAN", "amount": "1.00", "date_time": "01-01-2026"},
			self.client_private_key,
			self.sbi_public_key,
		)
		response = self._call_endpoint(envelope)
		self.assertEqual(set(response), {"data", "hash_digest", "session_key"})
		decrypted = crypto.decrypt_request(
			response,
			client_private_key=self.client_private_key,
			sbi_public_key=self.sbi_public_key,
		)
		self.assertEqual(decrypted["status_code"], "01")

	def test_endpoint_crypto_failure_returns_plain_json(self):
		"""Tampered data -> crypto failure -> plain JSON (not an envelope)."""
		envelope = _make_envelope(
			{"van": "V", "amount": "1.00", "date_time": "01-01-2026"},
			self.client_private_key,
			self.sbi_public_key,
		)
		# Flip one byte of the ciphertext -> signature/tag verification fails.
		raw = bytearray(base64.b64decode(envelope["data"]))
		raw[0] ^= 0xFF
		envelope["data"] = base64.b64encode(bytes(raw)).decode("ascii")

		response = self._call_endpoint(envelope)
		# Plain JSON, not an envelope.
		self.assertNotIn("data", response)
		self.assertEqual(response["status_code"], "01")
		self.assertEqual(response["message"], "Decryption/signature failed")

	def test_endpoint_missing_field_returns_encrypted_failure(self):
		"""Decrypted OK but missing mandatory field -> encrypted 01 envelope."""
		envelope = _make_envelope(
			{"van": "NEDFER00000088"},  # amount/date_time missing
			self.client_private_key,
			self.sbi_public_key,
		)
		response = self._call_endpoint(envelope)
		self.assertEqual(set(response), {"data", "hash_digest", "session_key"})
		decrypted = crypto.decrypt_request(
			response,
			client_private_key=self.client_private_key,
			sbi_public_key=self.sbi_public_key,
		)
		self.assertEqual(decrypted["status_code"], "01")

	def test_endpoint_missing_token_returns_encrypted_failure(self):
		"""No `token` header -> rejected before processing, encrypted JSON 01."""
		envelope = _make_envelope(
			{"van": "NEDFER00000077", "amount": "300.00", "date_time": "12-05-2023"},
			self.client_private_key,
			self.sbi_public_key,
		)
		response = self._call_endpoint(envelope, token=None)
		self.assertEqual(set(response), {"data", "hash_digest", "session_key"})
		response = crypto.decrypt_request(
			response,
			client_private_key=self.client_private_key,
			sbi_public_key=self.sbi_public_key,
		)
		self.assertEqual(response["status_code"], "01")
		self.assertEqual(response["message"], "Invalid token")

	def test_endpoint_invalid_token_returns_encrypted_failure(self):
		"""Tampered token -> rejected, encrypted JSON 01."""
		envelope = _make_envelope(
			{"van": "NEDFER00000077", "amount": "300.00", "date_time": "12-05-2023"},
			self.client_private_key,
			self.sbi_public_key,
		)
		response = self._call_endpoint(envelope, token="not-a-valid-jwt")
		self.assertEqual(set(response), {"data", "hash_digest", "session_key"})
		response = crypto.decrypt_request(
			response,
			client_private_key=self.client_private_key,
			sbi_public_key=self.sbi_public_key,
		)
		self.assertEqual(response["status_code"], "01")
		self.assertEqual(response["message"], "Invalid token")
