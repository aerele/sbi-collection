# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Tests for the local dev/test helpers in sbi_collection.dev_tools.

These prove the dev helpers are exact mirrors of the production crypto pair:
  - encrypt_request  produces envelopes the production decrypt_request accepts
  - decrypt_response decrypts envelopes the production encrypt_response emits
and that tampering / wrong keys fail loudly. No DB, no HTTP - pure crypto.
"""

import base64
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sbi_collection import crypto, dev_tools


def _make_keypair():
	"""Return (private_key_obj, public_key_obj) for a fresh 2048-bit RSA pair."""
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	return private_key, private_key.public_key()


def _b64mutate(value_b64):
	"""Flip the first byte of a base64 string's decoded bytes, re-encode."""
	raw = bytearray(base64.b64decode(value_b64))
	raw[0] ^= 0xFF
	return base64.b64encode(bytes(raw)).decode("ascii")


class TestDevTools(unittest.TestCase):
	def setUp(self):
		# Two distinct keypairs: ERPNext holds one, SBI holds the other.
		self.erp_private_key, self.erp_public_key = _make_keypair()
		self.sbi_private_key, self.sbi_public_key = _make_keypair()
		# A throwaway third keypair for the "wrong key" cases.
		self.other_private_key, self.other_public_key = _make_keypair()

	# -------------------------------------------------------------- #
	# Round-trips against the PRODUCTION crypto pair
	# -------------------------------------------------------------- #
	def test_encrypt_request_then_production_decrypt_request_round_trips(self):
		"""dev encrypt_request -> production decrypt_request = original payload."""
		payload = {"username": "SBI_USER", "password": "password", "n": [1, 2, 3]}
		envelope = dev_tools.encrypt_request(payload, self.erp_public_key, self.sbi_private_key)
		# Production decryptor uses ERPNext's private key + SBI's public key.
		decrypted = crypto.decrypt_request(
			envelope,
			client_private_key=self.erp_private_key,
			sbi_public_key=self.sbi_public_key,
		)
		self.assertEqual(decrypted, payload)

	def test_production_encrypt_response_then_decrypt_response_round_trips(self):
		"""production encrypt_response -> dev decrypt_response = original dict."""
		response = {"status": "SUCCESS", "message": "ok", "token": "abc.def.ghi"}
		envelope = crypto.encrypt_response(
			response,
			client_private_key=self.erp_private_key,
			sbi_public_key=self.sbi_public_key,
		)
		decrypted = dev_tools.decrypt_response(envelope, self.sbi_private_key, self.erp_public_key)
		self.assertEqual(decrypted, response)

	# -------------------------------------------------------------- #
	# Tamper detection
	# -------------------------------------------------------------- #
	def test_tampering_data_fails(self):
		envelope = dev_tools.encrypt_request(
			{"username": "u", "password": "p"}, self.erp_public_key, self.sbi_private_key
		)
		envelope["data"] = _b64mutate(envelope["data"])
		with self.assertRaises((InvalidSignature, ValueError)):
			dev_tools.decrypt_response(envelope, self.sbi_private_key, self.erp_public_key)

	def test_tampering_session_key_fails(self):
		envelope = dev_tools.encrypt_request(
			{"username": "u", "password": "p"}, self.erp_public_key, self.sbi_private_key
		)
		envelope["session_key"] = _b64mutate(envelope["session_key"])
		# Signature is over `data` (still valid), so failure happens at RSA or
		# AES-GCM decrypt, not at verify.
		with self.assertRaises((InvalidSignature, ValueError)):
			dev_tools.decrypt_response(envelope, self.sbi_private_key, self.erp_public_key)

	def test_tampering_hash_digest_fails(self):
		envelope = dev_tools.encrypt_request(
			{"username": "u", "password": "p"}, self.erp_public_key, self.sbi_private_key
		)
		envelope["hash_digest"] = _b64mutate(envelope["hash_digest"])
		with self.assertRaises(InvalidSignature):
			dev_tools.decrypt_response(envelope, self.sbi_private_key, self.erp_public_key)

	# -------------------------------------------------------------- #
	# Wrong keys
	# -------------------------------------------------------------- #
	def test_wrong_private_key_fails(self):
		"""SBI decrypts the session_key with its private key; a wrong one fails."""
		envelope = dev_tools.encrypt_request(
			{"username": "u", "password": "p"}, self.erp_public_key, self.sbi_private_key
		)
		with self.assertRaises((InvalidSignature, ValueError)):
			dev_tools.decrypt_response(envelope, self.other_private_key, self.erp_public_key)

	def test_wrong_public_key_fails(self):
		"""Signature verification uses ERPNext's public key; a wrong one fails."""
		envelope = dev_tools.encrypt_request(
			{"username": "u", "password": "p"}, self.erp_public_key, self.sbi_private_key
		)
		with self.assertRaises(InvalidSignature):
			dev_tools.decrypt_response(envelope, self.sbi_private_key, self.other_public_key)


class TestDevToolsKeyLoaders(unittest.TestCase):
	"""Cover the file-based key loaders without committing fixture PEMs."""

	def test_load_private_and_public_key_from_file_round_trip(self):
		# Write a throwaway keypair to temp PEM files and load them back.
		private_key, public_key = _make_keypair()
		with (
			tempfile.NamedTemporaryFile(suffix=".pem") as priv_file,
			tempfile.NamedTemporaryFile(suffix=".pem") as pub_file,
		):
			priv_file.write(
				private_key.private_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.NoEncryption(),
				)
			)
			priv_file.flush()
			pub_file.write(
				public_key.public_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PublicFormat.SubjectPublicKeyInfo,
				)
			)
			pub_file.flush()

			loaded_priv = dev_tools.load_private_key_from_file(priv_file.name)
			loaded_pub = dev_tools.load_public_key_from_file(pub_file.name)

		# Prove the loaded keys are usable end-to-end through encrypt_request.
		envelope = dev_tools.encrypt_request({"x": 1}, loaded_pub, loaded_priv)
		decrypted = crypto.decrypt_request(
			envelope,
			client_private_key=loaded_priv,
			sbi_public_key=loaded_pub,
		)
		self.assertEqual(decrypted, {"x": 1})

	def test_load_local_keys_returns_all_four(self):
		"""The one-call helper returns the documented key dict shape."""
		erp_priv, erp_pub = _make_keypair()
		sbi_priv, sbi_pub = _make_keypair()
		with (
			tempfile.NamedTemporaryFile(suffix=".pem") as erp_priv_f,
			tempfile.NamedTemporaryFile(suffix=".pem") as erp_pub_f,
			tempfile.NamedTemporaryFile(suffix=".pem") as sbi_priv_f,
			tempfile.NamedTemporaryFile(suffix=".pem") as sbi_pub_f,
		):
			for key, file in (
				(erp_priv, erp_priv_f),
				(sbi_priv, sbi_priv_f),
			):
				file.write(
					key.private_bytes(
						encoding=serialization.Encoding.PEM,
						format=serialization.PrivateFormat.TraditionalOpenSSL,
						encryption_algorithm=serialization.NoEncryption(),
					)
				)
				file.flush()
			for key, file in (
				(erp_pub, erp_pub_f),
				(sbi_pub, sbi_pub_f),
			):
				file.write(
					key.public_bytes(
						encoding=serialization.Encoding.PEM,
						format=serialization.PublicFormat.SubjectPublicKeyInfo,
					)
				)
				file.flush()

			keys = dev_tools.load_local_keys(erp_priv_f.name, erp_pub_f.name, sbi_priv_f.name, sbi_pub_f.name)

		self.assertEqual(
			set(keys), {"erp_private_key", "erp_public_key", "sbi_private_key", "sbi_public_key"}
		)
		# Full workflow: encrypt_request -> production decrypt_request.
		envelope = dev_tools.encrypt_request(
			{"hello": "world"}, keys["erp_public_key"], keys["sbi_private_key"]
		)
		decrypted = crypto.decrypt_request(
			envelope,
			client_private_key=keys["erp_private_key"],
			sbi_public_key=keys["sbi_public_key"],
		)
		self.assertEqual(decrypted, {"hello": "world"})


if __name__ == "__main__":
	unittest.main()
