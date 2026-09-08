# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Tests for the Transaction Post API.

Three layers:
  1. Service unit tests (no crypto, no HTTP) - SBI business rules + duplicate
     detection + Payment Entry creation against real accounting fixtures.
  2. Crypto round-trip - the full decrypt -> process -> encrypt pipeline.
  3. HTTP endpoint - api.transaction_post with a real encrypted request.

Uses the test site's "ABC (Demo)" company and its SBI Bank Account, so Payment
Entry validation (account types, currency, party account) passes for real.
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
from sbi_collection.services import transaction_post_service
from sbi_collection.services.transaction_post_service import (
	MANDATORY_FIELDS,
	TransactionPostService,
)

TEST_JWT_SECRET = "transaction-post-test-secret"
_UNSET = object()  # sentinel: distinguishes "default valid token" from token=None/""

# Real fixtures on the test site.
TEST_COMPANY = "ABC (Demo)"
TEST_BANK_ACCOUNT = "ABC test - State Bank of India"
TEST_BANK_LEDGER = "Demo Bank Account - AD"
TEST_RECEIVABLE = "Debtors - AD"


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
def fake_request(body_dict, token=None):
	envelope_json = json.dumps(body_dict).encode("utf-8")
	headers = {"token": token} if token else {}
	fake_req = frappe._dict(data=envelope_json, method="POST", headers=headers, get_json=lambda: body_dict)
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


def patch_get_password(jwt_secret):
	from sbi_collection.sbi_collection.doctype.sbi_collection_settings.sbi_collection_settings import (
		SBICollectionSettings,
	)

	def _get_password(self, fieldname, raise_exception=True):
		if fieldname == "jwt_secret":
			return jwt_secret
		return None

	return patch.object(SBICollectionSettings, "get_password", _get_password)


def _set_settings(**values):
	"""Write SBI Collection Settings fields directly, bypassing mandatory checks."""
	doc = frappe.get_doc("SBI Collection Settings", "SBI Collection Settings")
	for key, value in values.items():
		doc.db_set(key, value)
	frappe.clear_document_cache("SBI Collection Settings", "SBI Collection Settings")


def _make_customer(name, van, company=TEST_COMPANY, receivable=TEST_RECEIVABLE):
	"""Create a Customer with a VAN and a receivable Party Account row."""
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
			"accounts": [{"company": company, "account": receivable}],
		}
	)
	doc.insert(ignore_permissions=True)
	if doc.name != name:
		doc.rename(name)
	frappe.db.set_value("Customer", doc.name, "collection_van", van)
	return doc.name


def _make_valid_payload(utr, van="TPTESTVAN001"):
	"""A valid SBI Transaction Post payload (all mandatory fields present)."""
	return {
		"van": van,
		"amount": "100.00",
		"date_time": "12-05-2026",
		"request_id": "REQ-1",
		"trans_typ": "NEFT",
		"ref_id": "REF-1",
		"utr_no": utr,
	}


def _cancel_and_delete_payment_entry(utr):
	"""Clean up any Payment Entry created with `reference_no == utr`."""
	for name in frappe.get_all(
		"Payment Entry",
		filters={"reference_no": utr, "company": TEST_COMPANY},
		pluck="name",
	):
		try:
			pe = frappe.get_doc("Payment Entry", name)
			if pe.docstatus == 1:
				pe.cancel()
			frappe.delete_doc("Payment Entry", name, force=1, ignore_permissions=True)
		except Exception:
			pass


# --------------------------------------------------------------------------- #
# Layer 1: Service unit tests
# --------------------------------------------------------------------------- #
class TestTransactionPostService(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		from sbi_collection.install import make_custom_fields

		make_custom_fields()
		_set_settings(default_company=TEST_COMPANY, bank_account=TEST_BANK_ACCOUNT)

	def setUp(self):
		self.service = TransactionPostService()
		self._customers = []
		self._utrs = []

	def tearDown(self):
		for utr in self._utrs:
			_cancel_and_delete_payment_entry(utr)
		for cust in self._customers:
			try:
				frappe.delete_doc("Customer", cust, force=1, ignore_permissions=True)
			except Exception:
				pass

	def _next_utr(self):
		utr = f"UTR{frappe.utils.random_string(8).upper()}{len(self._utrs)}"
		self._utrs.append(utr)
		return utr

	def _seed_customer(self, van=None):
		van = van or f"TPVAN{frappe.utils.random_string(6).upper()}"
		cust = _make_customer(f"TP-CUST-{frappe.utils.random_string(4).upper()}", van)
		self._customers.append(cust)
		return cust, van

	# --- validate_request ---
	def test_validate_request_passes_with_all_mandatory_fields(self):
		self.service.validate_request(_make_valid_payload(self._next_utr()))

	def test_validate_request_raises_on_each_missing_field(self):
		for missing in MANDATORY_FIELDS:
			with self.subTest(missing=missing):
				payload = _make_valid_payload(self._next_utr())
				payload.pop(missing)
				with self.assertRaises(frappe.ValidationError):
					self.service.validate_request(payload)

	# --- get_customer_by_van ---
	def test_get_customer_by_van_finds_seeded_customer(self):
		cust, van = self._seed_customer()
		self.assertEqual(self.service.get_customer_by_van(van), cust)

	def test_get_customer_by_van_returns_none_for_unknown(self):
		self.assertIsNone(self.service.get_customer_by_van("NO-SUCH-TPVAN"))

	# --- check_duplicate_transaction ---
	def test_check_duplicate_returns_none_when_no_pe(self):
		utr = self._next_utr()
		self.assertIsNone(self.service.check_duplicate_transaction(utr, TEST_COMPANY))

	# --- response builders (exact SBI shape) ---
	def test_build_success_response_is_success(self):
		# SBI's latest UAT message overrides the PDF.
		self.assertEqual(
			self.service.build_success_response(),
			{"status_code": "00", "message": "Success"},
		)

	def test_build_failure_response_shape(self):
		self.assertEqual(
			self.service.build_failure_response("boom"),
			{"status_code": "01", "message": "boom"},
		)

	def test_build_duplicate_response_shape(self):
		resp = self.service.build_duplicate_response("ACC-PAY-2026-0001")
		self.assertEqual(resp["status_code"], "01")
		self.assertIn("ACC-PAY-2026-0001", resp["message"])

	# --- process: full flow ---
	def test_process_success_creates_draft_payment_entry(self):
		cust, van = self._seed_customer()
		utr = self._next_utr()
		result = self.service.process(_make_valid_payload(utr=utr, van=van))

		self.assertTrue(result["succeeded"], msg=f"result={result}")
		self.assertEqual(result["customer"], cust)
		self.assertEqual(result["transaction_reference"], utr)
		self.assertTrue(result["payment_entry"])
		# The PE must be a DRAFT (docstatus 0, not submitted) so it can be
		# verified + reconciled manually, and carry the UTR as reference_no.
		_, pe_ds, pe_ref = frappe.db.get_value(
			"Payment Entry", result["payment_entry"], ["name", "docstatus", "reference_no"]
		)
		self.assertEqual(pe_ds, 0)
		self.assertEqual(pe_ref, utr)

	def test_process_unknown_van_returns_failure_no_pe(self):
		utr = self._next_utr()
		result = self.service.process(_make_valid_payload(utr=utr, van="UNKNOWN-TPVAN"))
		self.assertFalse(result["succeeded"])
		self.assertEqual(result["response"]["status_code"], "01")
		self.assertIsNone(result["payment_entry"])

	def test_process_duplicate_does_not_create_second_pe(self):
		_, van = self._seed_customer()
		utr = self._next_utr()
		first = self.service.process(_make_valid_payload(utr=utr, van=van))
		self.assertTrue(first["succeeded"])
		pe1 = first["payment_entry"]

		# Same UTR again -> duplicate response, no new PE.
		second = self.service.process(_make_valid_payload(utr=utr, van=van))
		self.assertFalse(second["succeeded"])
		self.assertEqual(second["response"]["status_code"], "01")
		self.assertEqual(second["payment_entry"], pe1)
		self.assertEqual(frappe.db.count("Payment Entry", {"reference_no": utr, "company": TEST_COMPANY}), 1)

	def test_process_missing_field_returns_failure(self):
		_, van = self._seed_customer()
		utr = self._next_utr()
		payload = _make_valid_payload(utr=utr, van=van)
		payload.pop("utr_no")
		result = self.service.process(payload)
		self.assertFalse(result["succeeded"])
		self.assertEqual(result["response"]["status_code"], "01")


# --------------------------------------------------------------------------- #
# Layer 2: Crypto round-trip
# --------------------------------------------------------------------------- #
class TestTransactionPostCryptoRoundTrip(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		_set_settings(default_company=TEST_COMPANY, bank_account=TEST_BANK_ACCOUNT)

	def test_encrypt_decrypt_process_encrypt_decrypt(self):
		# Proves the crypto round-trips through the service. No customer is
		# seeded, so the service returns a (01) failure which we still
		# re-encrypt and re-decrypt.
		client_private_key, sbi_public_key = self._loaded_keypair()
		sbi_request = _make_valid_payload(utr="ROUNDTRIP-UTR-TP", van="ROUNDTRIP-TPVAN")

		envelope = _make_envelope(sbi_request, client_private_key, sbi_public_key)
		decrypted = crypto.decrypt_request(
			envelope,
			client_private_key=client_private_key,
			sbi_public_key=sbi_public_key,
		)
		self.assertEqual(decrypted, sbi_request)

		result = transaction_post_service.process(decrypted)
		self.assertEqual(result["response"]["status_code"], "01")  # no customer

		response_envelope = crypto.encrypt_response(
			result["response"],
			client_private_key=client_private_key,
			sbi_public_key=sbi_public_key,
		)
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
class TestTransactionPostEndpoint(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		from sbi_collection.install import make_custom_fields

		make_custom_fields()
		_set_settings(default_company=TEST_COMPANY, bank_account=TEST_BANK_ACCOUNT)

	def setUp(self):
		self._customers = []
		self._utrs = []
		self.client_private_pem, self.sbi_public_pem = _make_keypair_pem()
		self.client_private_key = crypto.load_private_key(self.client_private_pem)
		self.sbi_public_key = crypto.load_public_key(self.sbi_public_pem)
		self._load_keys_patcher = patch_load_keys(self.client_private_key, self.sbi_public_key)
		self._load_keys_patcher.start()
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
		for utr in self._utrs:
			_cancel_and_delete_payment_entry(utr)
		for cust in self._customers:
			try:
				frappe.delete_doc("Customer", cust, force=1, ignore_permissions=True)
			except Exception:
				pass

	def _next_utr(self):
		self._utrs.append(f"UTR{frappe.utils.random_string(8).upper()}")
		return self._utrs[-1]

	def _seed_customer(self, van=None):
		van = van or f"TPVAN{frappe.utils.random_string(6).upper()}"
		cust = _make_customer(f"TP-END-{frappe.utils.random_string(4).upper()}", van)
		self._customers.append(cust)
		return cust, van

	def _call_endpoint(self, body_dict, token=_UNSET):
		effective = self.valid_token if token is _UNSET else token
		with fake_request(body_dict, token=effective):
			return api.transaction_post()

	def test_endpoint_success_creates_pe_and_returns_encrypted_success(self):
		_, van = self._seed_customer()
		utr = self._next_utr()
		envelope = _make_envelope(
			_make_valid_payload(utr=utr, van=van),
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

		# A real DRAFT (docstatus 0, not submitted) Payment Entry must exist for
		# this UTR - left for manual verification + reconciliation.
		pe = frappe.db.get_value(
			"Payment Entry",
			{"reference_no": utr, "company": TEST_COMPANY},
			["name", "docstatus"],
			as_dict=True,
		)
		self.assertIsNotNone(pe, "Payment Entry was not created")
		self.assertEqual(pe.docstatus, 0)

	def test_endpoint_crypto_failure_returns_plain_json(self):
		_, van = self._seed_customer()
		utr = self._next_utr()
		envelope = _make_envelope(
			_make_valid_payload(utr=utr, van=van),
			self.client_private_key,
			self.sbi_public_key,
		)
		# Tamper -> signature/tag failure.
		raw = bytearray(base64.b64decode(envelope["data"]))
		raw[0] ^= 0xFF
		envelope["data"] = base64.b64encode(bytes(raw)).decode("ascii")

		response = self._call_endpoint(envelope)
		self.assertNotIn("data", response)  # plain JSON, not an envelope
		self.assertEqual(response["status_code"], "01")
		self.assertEqual(response["message"], "Decryption/signature failed")

		# No PE should have been created.
		self.assertFalse(frappe.db.exists("Payment Entry", {"reference_no": utr, "company": TEST_COMPANY}))

	def test_endpoint_missing_token_returns_encrypted_failure(self):
		"""No token header -> encrypted failure before business processing."""
		utr = self._next_utr()
		envelope = _make_envelope(
			_make_valid_payload(utr=utr),
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
		# No PE created.
		self.assertFalse(frappe.db.exists("Payment Entry", {"reference_no": utr, "company": TEST_COMPANY}))

	def test_endpoint_invalid_token_returns_encrypted_failure(self):
		"""Invalid token -> encrypted failure, no PE created."""
		utr = self._next_utr()
		envelope = _make_envelope(
			_make_valid_payload(utr=utr),
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
