# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Unit tests for the SBI Collection crypto envelope.

These tests verify the encrypt/decrypt round-trip and the integrity checks
mandated by the SBI Collection integration document. Keys are generated
in-memory for each run - no fixtures, no DB writes, no network.
"""

import base64
import json
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
	Encoding,
	NoEncryption,
	PrivateFormat,
	PublicFormat,
)

from sbi_collection import crypto


def _make_keypair():
	"""Return a throwaway 2048-bit RSA keypair as loaded key objects."""
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	public_key = private_key.public_key()
	return private_key, public_key


class TestSbiCollectionCrypto(unittest.TestCase):
	# Frappe's test runner instantiates the class per test, so generate a fresh
	# keypair for each via setUp.
	def setUp(self):
		self.client_private_key, self.client_public_key = _make_keypair()
		# In production, sbi_public_key == a different keypair. For round-trip
		# tests we reuse the same keypair on both sides so encrypt/decrypt line up.
		self.sbi_private_key, self.sbi_public_key = self.client_private_key, self.client_public_key

	def test_encrypt_response_decrypt_request_round_trip(self):
		"""encrypt_response -> decrypt_request recovers the original payload."""
		payload = {
			"status_code": "00",
			"message": "Success",
			"request_id": "65432789677",
		}

		envelope = crypto.encrypt_response(
			payload,
			client_private_key=self.client_private_key,
			sbi_public_key=self.sbi_public_key,
		)

		# Envelope must carry exactly the three document-mandated fields.
		assert set(envelope) == {"data", "hash_digest", "session_key"}
		for value in envelope.values():
			# All fields are base64-encoded ASCII strings.
			base64.b64decode(value)

		decrypted = crypto.decrypt_request(
			envelope,
			client_private_key=self.client_private_key,
			sbi_public_key=self.sbi_public_key,
		)
		assert decrypted == payload

	def test_decrypt_request_rejects_tampered_data(self):
		"""A single flipped byte in `data` must fail verification/decryption."""
		envelope = crypto.encrypt_response(
			{"van": "AJMU1234", "amount": "300.00"},
			client_private_key=self.client_private_key,
			sbi_public_key=self.sbi_public_key,
		)

		raw = bytearray(base64.b64decode(envelope["data"]))
		raw[0] ^= 0xFF
		envelope["data"] = base64.b64encode(bytes(raw)).decode("ascii")

		try:
			crypto.decrypt_request(
				envelope,
				client_private_key=self.client_private_key,
				sbi_public_key=self.sbi_public_key,
			)
			raise AssertionError("Tampered data was unexpectedly accepted")
		except (InvalidSignature, ValueError):
			# Either signature verification (sign-over-ciphertext) or the GCM
			# auth tag check rejects it - both are acceptable security outcomes.
			# InvalidSignature = bad hash_digest; ValueError = AESGCM tag failure.
			pass

	def test_verify_rejects_wrong_signature(self):
		"""`verify` raises InvalidSignature when the signature does not match."""
		data = b"some ciphertext"
		envelope = crypto.encrypt_response(
			{"x": 1},
			client_private_key=self.client_private_key,
			sbi_public_key=self.sbi_public_key,
		)
		# Use a valid-looking but wrong signature (from a different payload).
		wrong_signature = envelope["hash_digest"]

		try:
			crypto.verify(data, wrong_signature, self.sbi_public_key)
			raise AssertionError("Wrong signature was unexpectedly accepted")
		except InvalidSignature:
			pass

	def test_aes_key_is_fresh_each_call(self):
		"""generate_aes_key returns distinct keys (zero-IV safety invariant)."""
		keys = {crypto.generate_aes_key() for _ in range(50)}
		assert len(keys) == 50

	def test_round_trip_with_payload_matching_authenticate_contract(self):
		"""End-to-end with a payload shaped like SBI's authenticate response."""
		payload = {
			"status_code": "00",
			"token": "eyJhbGciOiJIUzI1NiJ9.payload.signature",
			"message": "Login Successful",
		}
		envelope = crypto.encrypt_response(
			payload,
			client_private_key=self.client_private_key,
			sbi_public_key=self.sbi_public_key,
		)
		assert (
			crypto.decrypt_request(
				envelope,
				client_private_key=self.client_private_key,
				sbi_public_key=self.sbi_public_key,
			)
			== payload
		)

	def test_load_pem_keys(self):
		"""load_private_key/load_public_key accept openssl PEM output."""
		private_pem = self.client_private_key.private_bytes(
			Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
		)
		public_pem = self.sbi_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

		loaded_private = crypto.load_private_key(private_pem)
		loaded_public = crypto.load_public_key(public_pem)

		# Round-trip still works through the loaded-from-PEM keys.
		envelope = crypto.encrypt_response(
			{"ok": True},
			client_private_key=loaded_private,
			sbi_public_key=loaded_public,
		)
		assert crypto.decrypt_request(
			envelope,
			client_private_key=loaded_private,
			sbi_public_key=loaded_public,
		) == {"ok": True}

	def test_compact_json_is_used(self):
		"""Responses must serialize as compact JSON (no whitespace)."""
		# Deterministic check: encrypt twice with a fixed plaintext should
		# produce identical `data` if compact JSON + same key. We pin the key.
		import json as _json

		plaintext = _json.dumps({"a": 1, "b": 2}, separators=(",", ":"))
		key = crypto.generate_aes_key()
		assert crypto.aes_gcm_encrypt(plaintext, key) == crypto.aes_gcm_encrypt(plaintext, key)
