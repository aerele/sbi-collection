"""Database-free UAT contract tests using real crypto and Frappe's HTTP dispatcher.

Run with the bench Python and unittest, without selecting or connecting to a site.
All settings, logging, accounting lookups and document persistence are mocked.
"""

import base64
import json
import logging
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import frappe
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from werkzeug.test import Client
from werkzeug.wrappers import Request, Response

# ERPNext imports initialise a PDF logger; keep standalone tests off the filesystem.
with patch.object(frappe, "logger", return_value=logging.getLogger(__name__)):
	import frappe.api
	import frappe.app
	import frappe.handler

	from sbi_collection import api, crypto
	from sbi_collection.services import authentication_service, dealer_validation_service, payment_service
	from sbi_collection.services.dealer_validation_service import DealerValidationService
	from sbi_collection.services.transaction_post_service import TransactionPostService
	from sbi_collection.utils import diagnostics


class TestUATContract(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		# Distinct SBI/client pairs prove the direction of signing and key wrapping.
		cls.client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		cls.bank_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	def setUp(self):
		self.passwords = {"sbi_password": "test-password", "jwt_secret": "uat-test-secret-at-least-32-bytes"}
		self.settings = frappe._dict(
			sbi_username="uat-user",
			enable_encryption=1,
			token_expiry_minutes=60,
			default_company="Test Company",
			bank_account="Test Bank",
			get_password=lambda field, **kwargs: self.passwords.get(field),
			load_keys=Mock(return_value=(self.client_key, self.bank_key.public_key())),
		)
		self.entries = {}
		self.documents = []
		self.diagnostic_records = []
		self.generated_request_ids = []
		self.enterContext(
			patch.object(
				dealer_validation_service,
				"generate_request_id",
				side_effect=self._next_request_id,
			)
		)
		self.enterContext(patch.object(diagnostics, "UAT_DIAGNOSTICS_ENABLED", True))
		self.db = Mock()
		self.db.get_value.side_effect = self._get_value
		self.db.exists.side_effect = self._exists
		self.logs = {}
		for name in ("create_api_log", "update_api_log", "mark_success", "mark_failed"):
			self.logs[name] = self.enterContext(patch.object(api, name))
		self.enterContext(patch.object(frappe, "get_doc", side_effect=self._get_settings))
		self.enterContext(patch.object(frappe, "get_cached_doc", side_effect=self._get_settings))
		self.enterContext(patch.object(frappe, "new_doc", side_effect=self._new_doc))
		self.enterContext(patch.object(frappe, "get_system_settings", return_value=False))
		self.enterContext(patch.object(frappe, "get_installed_apps", return_value=["sbi_collection"]))
		self.enterContext(patch.object(frappe, "override_whitelisted_method", side_effect=lambda cmd: cmd))
		self.enterContext(patch.object(frappe.handler, "get_server_script_map", return_value={}))
		self.enterContext(patch.object(frappe.api, "add_data_to_monitor"))
		self.enterContext(patch.object(frappe.api, "capture_app_heartbeat"))
		self.framework_log = self.enterContext(
			patch.object(frappe, "log_error", side_effect=self._record_error_log)
		)
		self.enterContext(patch.object(frappe, "logger", return_value=Mock()))
		self.enterContext(patch("frappe.translate.get_all_translations", return_value={}))
		self.enterContext(
			patch.object(payment_service, "_resolve_receivable_account", return_value="Receivable")
		)
		self.enterContext(
			patch.object(payment_service, "_resolve_bank_ledger_account", return_value="Bank Ledger")
		)
		self.enterContext(
			patch.object(payment_service, "_account_currency_and_type", return_value=("INR", "Bank"))
		)
		for name, value in {
			"db": self.db,
			"flags": frappe._dict(),
			"lang": "en",
			"session": frappe._dict(user="Guest"),
			"conf": frappe._dict(),
			"response": frappe._dict(),
			"request": None,
			"form_dict": frappe._dict(),
			"message_log": [],
			"error_log": [],
			"debug_log": [],
		}.items():
			self.enterContext(patch.object(frappe.local, name, value, create=True))
		self.valid_token = self._token()
		self.client = Client(self._application, Response)

	def _next_request_id(self):
		request_id = f"20260911135330{len(self.generated_request_ids) + 1:05d}"
		self.generated_request_ids.append(request_id)
		return request_id

	def assert_generated_request_id(self, response):
		self.assertRegex(response["request_id"], r"^\d{19}$")
		self.assertIn(response["request_id"], self.generated_request_ids)

	def _get_settings(self, doctype, *args, **kwargs):
		self.assertEqual(doctype, "SBI Collection Settings", "Unexpected document access")
		return self.settings

	def _record_error_log(self, *, title, message):
		self.assertEqual(frappe.local.form_dict, {"request": "<redacted>"})
		self.diagnostic_records.append({"method": title, "error": message})

	def _get_value(self, doctype, filters, *args, **kwargs):
		if doctype == "Customer":
			return "Test Customer" if filters == {"collection_van": "VALID-VAN"} else None
		if doctype == "Company":
			return "Test Cost Center"
		self.fail(f"Unexpected database read: {doctype}")

	def _exists(self, doctype, filters):
		self.assertEqual(doctype, "Payment Entry")
		self.assertEqual(filters["docstatus"], ["<", 2])
		self.assertEqual(filters["company"], "Test Company")
		return self.entries.get(filters["reference_no"])

	def _new_doc(self, doctype):
		self.assertEqual(doctype, "Payment Entry")
		doc = Mock(name=f"draft-{len(self.documents)}", docstatus=0, flags=frappe._dict())
		doc.name = f"draft-{len(self.documents)}"

		def insert(**kwargs):
			self.entries[doc.reference_no] = doc.name

		doc.insert.side_effect = insert
		self.documents.append(doc)
		return doc

	def _token(self, **claims):
		payload = {"sub": "uat-user", "exp": datetime.now(UTC) + timedelta(hours=1), **claims}
		return jwt.encode(payload, self.passwords["jwt_secret"], algorithm="HS256")

	@Request.application
	def _application(self, request):
		# Real request parser, route matching, whitelist dispatch and JSON serialization.
		# Site/session/DB middleware is deliberately excluded.
		frappe.local.request = request
		frappe.local.response = frappe._dict()
		frappe.local.form_dict = frappe._dict()
		frappe.local.message_log = []
		try:
			frappe.app.make_form_dict(request)
			response = frappe.api.handle(request)
		except frappe.ValidationError:
			response = Response('{"exception":"framework validation"}', status=417)
		api.normalize_parse_failure(request, response)
		return response

	def _envelope(self, payload):
		return crypto.encrypt_response(
			payload, client_private_key=self.bank_key, sbi_public_key=self.client_key.public_key()
		)

	def _call(
		self, endpoint, payload=None, *, token=True, encrypted=True, raw=None, content_type="application/json"
	):
		body = raw if raw is not None else json.dumps(self._envelope(payload) if encrypted else payload)
		headers = {}
		if token:
			headers["token"] = self.valid_token if token is True else token
		response = self.client.post(
			f"/api/method/sbi_collection.api.{endpoint}",
			data=body,
			content_type=content_type,
			headers=headers,
		)
		self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
		self.assertEqual(response.mimetype, "application/json")
		return response.get_json()

	def _decrypt(self, envelope):
		self.assertEqual(set(envelope), {"data", "hash_digest", "session_key"})
		return crypto.decrypt_request(
			envelope, client_private_key=self.bank_key, sbi_public_key=self.client_key.public_key()
		)

	def _business_payload(self, **values):
		return {
			"van": "VALID-VAN",
			"amount": "300.00",
			"date_time": "08-09-2026",
			"utr_no": "UAT-UTR",
			**values,
		}

	def test_encrypted_authentication_success_and_redacted_logs(self):
		response = self._decrypt(
			self._call("authenticate", {"username": "uat-user", "password": "test-password"})
		)
		self.assertEqual(set(response), {"status_code", "message", "token"})
		self.assertEqual(response["status_code"], "00")
		self.assertEqual(response["message"], "Login Successful")
		claims = jwt.decode(response["token"], self.passwords["jwt_secret"], algorithms=["HS256"])
		self.assertEqual(claims["sub"], "uat-user")
		logged = repr(
			[log.mock_calls for log in self.logs.values()]
			+ [self.framework_log.mock_calls, self.diagnostic_records]
		)
		for secret in ("test-password", "uat-user", response["token"], self.valid_token):
			self.assertNotIn(secret, logged)

	def test_encrypted_invalid_and_missing_credentials(self):
		for payload in (
			{},
			{"username": "uat-user"},
			{"password": "test-password"},
			{"username": "wrong", "password": "test-password"},
			{"username": "uat-user", "password": "wrong"},
			{"username": "", "password": ""},
			{"username": [], "password": {}},
			{"username": "非ASCII", "password": "test-password"},
		):
			with self.subTest(payload=payload):
				self.assertEqual(
					self._decrypt(self._call("authenticate", payload)),
					{"status_code": "01", "message": "Invalid Credential"},
				)

	def test_plain_authentication_requires_explicit_disabled_encryption(self):
		payload = {"username": "uat-user", "password": "test-password"}
		for setting in (1, "1", None, ""):
			with self.subTest(setting=setting):
				self.settings.enable_encryption = setting
				response = self._call("authenticate", payload, encrypted=False)
				self.assertEqual(response["status_code"], "01")
				self.assertNotIn("token", response)
		for setting in (0, "0", False):
			with self.subTest(setting=setting):
				self.settings.enable_encryption = setting
				response = self._call("authenticate", payload, encrypted=False)
				self.assertEqual(response["message"], "Login Successful")
				self.assertEqual(response["status_code"], "00")
				self.assertEqual(
					self._call("authenticate", {}, encrypted=False),
					{"status_code": "01", "message": "Invalid Credential"},
				)

	def test_encrypted_request_is_answered_encrypted_even_in_dev_mode(self):
		self.settings.enable_encryption = 0
		response = self._decrypt(self._call("authenticate", {}))
		self.assertEqual(response, {"status_code": "01", "message": "Invalid Credential"})

	def test_dealer_generates_request_id_for_success_and_failure(self):
		for request_id in (None, "", "65432789677"):
			for amount, van, code, message in (
				("300.00", "VALID-VAN", "00", "Success"),
				("0", "VALID-VAN", "00", "Success"),
				(0, "VALID-VAN", "00", "Success"),
				("-0.01", "VALID-VAN", "01", "Amount Cannot be Negative"),
				(-1, "VALID-VAN", "01", "Amount Cannot be Negative"),
				("300", "UNKNOWN", "01", "Invalid Van"),
			):
				with self.subTest(request_id=request_id, amount=amount, van=van):
					payload = self._business_payload(amount=amount, van=van)
					if request_id is not None:
						payload["request_id"] = request_id
					response = self._decrypt(self._call("dealer_validation", payload))
					self.assertEqual(response["status_code"], code)
					self.assertEqual(response["message"], message)
					self.assert_generated_request_id(response)
					self.assertNotEqual(response["request_id"], request_id)
		self.assertEqual(len(self.generated_request_ids), len(set(self.generated_request_ids)))
		self.assertFalse(self.documents)

	def test_invalid_tokens_are_encrypted_without_business_processing(self):
		tokens = (
			None,
			"bad-token",
			self._token(exp=datetime.now(UTC) - timedelta(seconds=1)),
			jwt.encode({"sub": "uat-user"}, "wrong-secret-with-at-least-32-bytes", algorithm="HS256"),
		)
		for endpoint in ("dealer_validation", "transaction_post"):
			for token in tokens:
				for request_id in (None, "REQ-TOKEN"):
					with self.subTest(endpoint=endpoint, token=token, request_id=request_id):
						payload = self._business_payload()
						if request_id is not None:
							payload["request_id"] = request_id
						expected = {"status_code": "01", "message": "Invalid token"}
						response = self._decrypt(self._call(endpoint, payload, token=token))
						if endpoint == "dealer_validation":
							self.assert_generated_request_id(response)
							response.pop("request_id")
						self.assertEqual(response, expected)
		self.db.get_value.assert_not_called()
		self.db.exists.assert_not_called()
		self.assertFalse(self.documents)

	def test_missing_jwt_secret_fails_closed(self):
		self.passwords["jwt_secret"] = ""
		response = self._decrypt(self._call("transaction_post", self._business_payload()))
		self.assertEqual(response, {"status_code": "01", "message": "Invalid token"})

	def test_mis_negative_zero_and_invalid_van(self):
		for amount, van, message in (
			("-1", "VALID-VAN", "Amount Cannot be Negative"),
			(-0.01, "VALID-VAN", "Amount Cannot be Negative"),
			("0.00", "VALID-VAN", "Amount Cannot be Zero"),
			(0, "VALID-VAN", "Amount Cannot be Zero"),
			("300", "UNKNOWN", "Invalid Van"),
		):
			with self.subTest(amount=amount, van=van):
				response = self._decrypt(
					self._call("transaction_post", self._business_payload(amount=amount, van=van))
				)
				self.assertEqual(response, {"status_code": "01", "message": message})
		self.assertFalse(self.documents)
		self.db.exists.assert_not_called()

	def test_mis_success_creates_draft_and_duplicate_utr_does_not_create_another(self):
		payload = self._business_payload(request_id="REQ-1", trans_typ="NEFT", ref_id="BANK-REF")
		response = self._decrypt(self._call("transaction_post", payload))
		self.assertEqual(response, {"status_code": "00", "message": "Success"})
		self.assertEqual(len(self.documents), 1)
		doc = self.documents[0]
		self.assertEqual(doc.docstatus, 0)
		self.assertEqual(doc.payment_type, "Receive")
		self.assertEqual(doc.paid_amount, 300)
		self.assertEqual(doc.reference_no, "UAT-UTR")
		doc.submit.assert_not_called()
		doc.insert.assert_called_once_with(ignore_permissions=True, ignore_mandatory=True)
		second = self._decrypt(self._call("transaction_post", payload))
		self.assertEqual(second["status_code"], "01")
		self.assertIn("Duplicate transaction", second["message"])
		self.assertEqual(len(self.documents), 1)
		doc.insert.assert_called_once()

	def test_invalid_amounts_are_encrypted_and_cannot_create_payments(self):
		for endpoint in ("dealer_validation", "transaction_post"):
			for amount in ("NaN", "Infinity", "-Infinity", "abc", True, {}, []):
				with self.subTest(endpoint=endpoint, amount=amount):
					response = self._decrypt(self._call(endpoint, self._business_payload(amount=amount)))
					self.assertEqual(response["status_code"], "01")
					self.assertEqual(response["message"], "Invalid Amount")
		self.assertFalse(self.documents)

	def test_service_validation_errors_cannot_escape_as_417(self):
		for endpoint, service in (
			("authenticate", authentication_service),
			("dealer_validation", api.dealer_validation_service),
			("transaction_post", api.transaction_post_service),
		):
			with self.subTest(endpoint=endpoint):
				with patch.object(service, "process", side_effect=frappe.ValidationError("internal details")):
					response = self._decrypt(self._call(endpoint, self._business_payload(request_id="REQ")))
				self.assertEqual(response["status_code"], "01")
				self.assertEqual(response["message"], "Request processing failed")
				if endpoint == "dealer_validation":
					self.assert_generated_request_id(response)

	def test_missing_business_fields_are_encrypted(self):
		for endpoint in ("dealer_validation", "transaction_post"):
			response = self._decrypt(self._call(endpoint, {"request_id": "REQ"}))
			self.assertEqual(response["status_code"], "01")
			if endpoint == "dealer_validation":
				self.assert_generated_request_id(response)

	def test_frappe_throw_does_not_leak_plaintext_server_messages(self):
		with patch.object(
			api.transaction_post_service,
			"process",
			side_effect=lambda payload: frappe.throw("internal detail"),
		):
			response = self._decrypt(self._call("transaction_post", self._business_payload()))
		self.assertEqual(response, {"status_code": "01", "message": "Request processing failed"})
		self.assertEqual(frappe.local.message_log, [])

	def test_malformed_and_unverifiable_envelopes_return_plain_200(self):
		valid = self._envelope(self._business_payload())
		tampered = dict(valid)
		data = bytearray(base64.b64decode(tampered["data"]))
		data[0] ^= 1
		tampered["data"] = base64.b64encode(data).decode("ascii")
		wrong_key = self._envelope({})
		wrong_key["session_key"] = crypto.rsa_oaep_encrypt(
			crypto.generate_aes_key(), self.bank_key.public_key()
		)
		for endpoint in api.ENDPOINTS:
			for envelope in ({}, {"data": "x"}, dict.fromkeys(api.ENVELOPE_FIELDS, ""), tampered, wrong_key):
				with self.subTest(endpoint=endpoint, envelope_fields=list(envelope)):
					response = self._call(endpoint, envelope, encrypted=False)
					self.assertEqual(response["status_code"], "01")
					self.assertEqual(response["message"], "Decryption/signature failed")
					self.assertNotIn("data", response)
					if endpoint == "dealer_validation":
						self.assert_generated_request_id(response)

	def test_raw_body_fallback_with_wrong_content_type(self):
		for endpoint in api.ENDPOINTS:
			for content_type in ("text/plain", "application/x-www-form-urlencoded", None):
				with self.subTest(endpoint=endpoint, content_type=content_type):
					payload = (
						{"username": "uat-user", "password": "test-password"}
						if endpoint == "authenticate"
						else self._business_payload(utr_no=f"UTR-{content_type}")
					)
					response = self._decrypt(self._call(endpoint, payload, content_type=content_type))
					self.assertEqual(response["status_code"], "00")

	def test_json_parser_failure_and_none_fall_back_to_raw_body(self):
		envelope = self._envelope({})
		for get_json in (Mock(side_effect=ValueError("client parsing issue")), Mock(return_value=None)):
			request = frappe._dict(data=json.dumps(envelope).encode(), get_json=get_json)
			with patch.object(frappe.local, "request", request):
				self.assertEqual(api._get_request_payload(), envelope)

	def test_empty_invalid_and_nonobject_raw_bodies(self):
		for endpoint in api.ENDPOINTS:
			for raw in (b"", b"{bad json", b"null", b"123", b"[]", b'"text"'):
				with self.subTest(endpoint=endpoint, raw=raw):
					response = self._call(endpoint, raw=raw)
					self.assertEqual(response["status_code"], "01")
					self.assertNotIn("data", response)

	def test_parse_failure_hook_does_not_rewrite_unrelated_errors(self):
		for path, method, status, body in (
			("/api/method/other.app", "POST", 417, "{"),
			("/api/method/sbi_collection.api.authenticate", "GET", 417, "{"),
			("/api/method/sbi_collection.api.authenticate", "POST", 403, "{"),
			("/api/method/sbi_collection.api.authenticate", "POST", 417, "{}"),
		):
			request = Request.from_values(
				path=path, method=method, data=body, content_type="application/json"
			)
			response = Response("original error", status=status)
			api.normalize_parse_failure(request, response)
			self.assertEqual(response.status_code, status)
			self.assertEqual(response.get_data(as_text=True), "original error")

	def test_logging_failures_do_not_change_business_response(self):
		for log in self.logs.values():
			log.side_effect = frappe.ValidationError("log unavailable")
		self.framework_log.side_effect = frappe.ValidationError("Error Log unavailable")
		response = self._decrypt(self._call("dealer_validation", self._business_payload()))
		self.assertEqual(response["status_code"], "00")
		self.assertEqual(response["message"], "Success")
		self.assert_generated_request_id(response)

	def test_uat_error_logs_retain_authentication_checks_and_processing_stages(self):
		self._call("authenticate", {"username": "uat-user", "password": "wrong"})
		details = [json.loads(record["error"]) for record in self.diagnostic_records]
		self.assertTrue(all(record["method"] == "SBI Auth Debug" for record in self.diagnostic_records))
		self.assertEqual(
			[item["event"] for item in details],
			["process_entry", "decrypt_success", "credential_check", "response_ready"],
		)
		check = next(item for item in details if item["event"] == "credential_check")
		self.assertTrue(check["username_match"])
		self.assertFalse(check["password_match"])
		self.assertEqual(details[-1]["status_code"], "01")
		self.assertTrue(details[-1]["encrypted"])
		self.assertEqual(self.framework_log.call_count, 4)

	def test_uat_error_logs_capture_token_parsing_and_crypto_failures(self):
		self._call("dealer_validation", self._business_payload(), token=None)
		self._call("authenticate", {}, content_type="text/plain")
		self._call("transaction_post", {}, encrypted=False)
		self._call("authenticate", raw=b"{bad json")
		events = {json.loads(record["error"])["event"] for record in self.diagnostic_records}
		self.assertTrue(
			{
				"token_rejected",
				"get_json_failed",
				"raw_json_fallback",
				"envelope_validation_failed",
				"framework_parse_failure_normalized",
			}.issubset(events)
		)

	def test_uat_error_logs_omit_exception_text_payloads_and_locals(self):
		secret = "sensitive-exception-credential-or-token"
		with patch.object(api.transaction_post_service, "process", side_effect=ValueError(secret)):
			self._call("transaction_post", self._business_payload())
		self.assertNotIn(secret, repr(self.diagnostic_records))
		self.assertNotIn(self.valid_token, repr(self.diagnostic_records))
		failure = next(
			json.loads(record["error"])
			for record in self.diagnostic_records
			if json.loads(record["error"])["event"] == "processing_failed"
		)
		self.assertEqual(failure["error_type"], "ValueError")
		self.assertTrue(failure["locations"])
		self.assertEqual(set(failure["locations"][0]), {"file", "function", "line"})
		self.assertTrue(all("metadata" not in record for record in self.diagnostic_records))

	def test_uat_diagnostics_can_be_disabled_for_production(self):
		with patch.object(diagnostics, "UAT_DIAGNOSTICS_ENABLED", False):
			response = self._decrypt(self._call("dealer_validation", self._business_payload()))
		self.assertEqual(response["status_code"], "00")
		self.assertEqual(self.diagnostic_records, [])

	def test_log_error_restores_request_fields_even_when_logging_fails(self):
		original = frappe._dict(username="uat-user", password="test-password", token=self.valid_token)
		frappe.local.form_dict = original
		diagnostics.log_diagnostic("authenticate", "process_entry")
		self.assertIs(frappe.local.form_dict, original)
		self.framework_log.side_effect = RuntimeError("log unavailable")
		diagnostics.log_diagnostic("authenticate", "process_entry")
		self.assertIs(frappe.local.form_dict, original)

	def test_key_loading_and_response_encryption_failures_return_plain_200(self):
		self.settings.load_keys.side_effect = frappe.ValidationError("key unavailable")
		response = self._call("authenticate", {})
		self.assertEqual(response["status_code"], "01")
		self.assertNotIn("data", response)
		self.settings.load_keys.side_effect = None
		body = json.dumps(self._envelope({}))
		with patch.object(crypto, "encrypt_response", side_effect=ValueError("encryption failed")):
			response = self._call("authenticate", raw=body)
		self.assertEqual(response, {"status_code": "01", "message": "Response encryption failed"})

	def test_service_response_builders_match_uat(self):
		dealer_response = DealerValidationService().build_success_response("Test Customer")
		self.assertEqual(dealer_response["status_code"], "00")
		self.assertEqual(dealer_response["message"], "Success")
		self.assert_generated_request_id(dealer_response)
		self.assertEqual(
			TransactionPostService().build_success_response(),
			{"status_code": "00", "message": "Success"},
		)
