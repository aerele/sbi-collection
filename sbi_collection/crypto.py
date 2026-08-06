# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""
SBI Collection API crypto envelope.

Implements the encryption/decryption contract described in SBI's
"API Integration Document for VAN based Collection". The wire format is a
fixed three-field envelope used by every request and response:

    {
        "data":        "<base64 AES-256-GCM of the JSON payload>",
        "hash_digest": "<base64 SHA256withRSA signature>",
        "session_key": "<base64 RSA-OAEP-SHA1 of the AES session key>"
    }

Primitives (all matching SBI's Java reference):
    - AES-256-GCM, NoPadding, with a fixed 16-byte zero IV.
    - RSA / None / OAEPWithSHA1AndMGF1Padding for the session key.
    - SHA256withRSA (RSASSA-PKCS1-v1_5) for the signature.

This module adapts the proven primitives of the india_banking_connector SBI
EIS payout connector, with three deliberate corrections required by the
Collection document (the schemes look alike but are not identical):

    1. IV  - fixed 16-byte all-zero IV (NOT the EIS `key[:12]` nonce).
    2. Sign- the signature is over the CIPHERTEXT `data` (NOT the plaintext).
    3. Envelope - `data` / `hash_digest` / `session_key` JSON body fields
       (NOT the EIS `REQUEST` / `DIGI_SIGN` + `AccessToken` header).

Security note on the zero IV: reusing a static IV under GCM is only safe
because a fresh random AES key is generated for every message in
`generate_aes_key()`. Never reuse a key across messages - GCM is
catastrophically broken by (key, nonce) reuse. The document explicitly blesses
this "random key + fixed zero IV" design.
"""

import base64
import json
import secrets

import frappe
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
	load_pem_private_key,
	load_pem_public_key,
)

# Fixed 16-byte zero IV mandated by the Collection document (AES GCM IV Length).
# Safe ONLY because each message uses a fresh random AES key (see module note).
IV = b"\x00" * 16


def load_private_key(pem_bytes, password=None):
	"""Load a PEM-encoded RSA private key (optionally passphrase-protected)."""
	return load_pem_private_key(pem_bytes, password=password)


def load_public_key(pem_bytes):
	"""Load a PEM-encoded RSA public key (openssl `rsa -pubout` output)."""
	return load_pem_public_key(pem_bytes)


def generate_aes_key():
	"""Return a fresh random 256-bit AES session key (32 random bytes).

	Step 1 of the document's Encryption Logic. Per-message generation is what
	makes the fixed zero IV safe - do not reuse this key.
	"""
	return secrets.token_bytes(32)


def aes_gcm_encrypt(plaintext, key):
	"""AES-256-GCM encrypt `plaintext` (str) with the fixed zero IV.

	Returns base64 of `ciphertext || 16-byte auth tag` (the layout the document
	calls "cipher text includes the auth tag"). Step 3-4 of Encryption Logic.
	"""
	encrypted = AESGCM(key).encrypt(IV, plaintext.encode("utf-8"), None)
	return base64.b64encode(encrypted).decode("ascii")


def aes_gcm_decrypt(ciphertext_b64, key):
	"""Reverse of `aes_gcm_encrypt`. Step 4 of Decryption Logic."""
	decrypted = AESGCM(key).decrypt(IV, base64.b64decode(ciphertext_b64), None)
	return decrypted.decode("utf-8")


def rsa_oaep_encrypt(data, public_key):
	"""RSA-OAEP (SHA1 / MGF1-SHA1) encrypt `data` (bytes) with a public key.

	Step 2/3 of Encryption Logic - wraps the AES session key with the
	recipient's RSA public key (`RSA/None/OAEPWithSHA1AndMGF1Padding`).
	"""
	encrypted = public_key.encrypt(
		data,
		asym_padding.OAEP(
			mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None,
		),
	)
	return base64.b64encode(encrypted).decode("ascii")


def rsa_oaep_decrypt(ciphertext_b64, private_key):
	"""Reverse of `rsa_oaep_encrypt`. Step 2 of Decryption Logic."""
	decrypted = private_key.decrypt(
		base64.b64decode(ciphertext_b64),
		asym_padding.OAEP(
			mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None,
		),
	)
	return decrypted


def sign(data, private_key):
	"""SHA256withRSA (RSASSA-PKCS1-v1_5 + SHA-256) sign `data` (bytes).

	Step 5 of Encryption Logic. Per the document the signature is computed over
	the encrypted `data` field (correction #2 - NOT the plaintext).
	"""
	signature = private_key.sign(data, asym_padding.PKCS1v15(), hashes.SHA256())
	return base64.b64encode(signature).decode("ascii")


def verify(data, signature_b64, public_key):
	"""Verify a SHA256withRSA signature. Raises `InvalidSignature` on mismatch.

	Step 1 of Decryption Logic - authenticates SBI by verifying `hash_digest`
	over the ciphertext `data` with SBI's public key.
	"""
	public_key.verify(
		base64.b64decode(signature_b64),
		data,
		asym_padding.PKCS1v15(),
		hashes.SHA256(),
	)


def decrypt_request(envelope, *, client_private_key, sbi_public_key):
	"""Decrypt an incoming SBI request envelope -> dict.

	Follows the document's Decryption Logic in order:
	  1. Verify `hash_digest` over the ciphertext `data` with SBI's public key.
	  2. Decrypt `session_key` with our RSA private key -> AES key.
	  3. AES-GCM decrypt `data` with the fixed zero IV -> plaintext JSON.
	"""
	data_b64 = envelope["data"]
	session_b64 = envelope["session_key"]
	hash_b64 = envelope["hash_digest"]

	verify(base64.b64decode(data_b64), hash_b64, sbi_public_key)

	aes_key = rsa_oaep_decrypt(session_b64, client_private_key)
	plaintext = aes_gcm_decrypt(data_b64, aes_key)

	return frappe.parse_json(plaintext)


def encrypt_response(payload, *, client_private_key, sbi_public_key):
	"""Encrypt an outgoing response payload -> three-field envelope dict.

	Follows the document's Encryption Logic:
	  1. Generate a fresh 256-bit AES session key.
	  2. AES-256-GCM encrypt the JSON payload -> `data` (with auth tag).
	  3. RSA-OAEP encrypt the AES key with SBI's public key -> `session_key`.
	  4. SHA256withRSA sign the ciphertext `data` with our private key ->
	     `hash_digest`.
	All values are base64-encoded ASCII strings.
	"""
	plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

	aes_key = generate_aes_key()
	data_b64 = aes_gcm_encrypt(plaintext, aes_key)
	hash_b64 = sign(base64.b64decode(data_b64), client_private_key)
	session_b64 = rsa_oaep_encrypt(aes_key, sbi_public_key)

	return {
		"data": data_b64,
		"hash_digest": hash_b64,
		"session_key": session_b64,
	}


# Re-export so callers can catch it without importing cryptography directly.
__all__ = [
	"IV",
	"InvalidSignature",
	"aes_gcm_decrypt",
	"aes_gcm_encrypt",
	"decrypt_request",
	"encrypt_response",
	"generate_aes_key",
	"load_private_key",
	"load_public_key",
	"rsa_oaep_decrypt",
	"rsa_oaep_encrypt",
	"sign",
	"verify",
]
