# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""LOCAL TESTING HELPERS for the SBI Collection integration.

⚠️  DEVELOPMENT / TESTING ONLY.  ⚠️
This module simulates SBI's side of the wire so you can exercise the production
endpoints (authenticate / dealer_validation / transaction_post) from Postman or
bench console against a local site. It MUST NOT be imported by any production
code path, endpoint, or service. Nothing here is whitelisted; it is import-only.

It reuses the production crypto primitives in `sbi_collection.crypto` - there is
no duplicated encryption logic. The two envelope helpers are the *mirror* of the
production pair:
    encrypt_request   mirrors production decrypt_request   (SBI -> ERPNext)
    decrypt_response  mirrors production encrypt_response  (ERPNext -> SBI)

Bench-console workflow:

    from sbi_collection.dev_tools import (
        load_local_keys, encrypt_request, decrypt_response,
    )
    keys = load_local_keys(
        "erp_priv.pem", "erp_pub.pem", "sbi_priv.pem", "sbi_pub.pem",
    )
    envelope = encrypt_request(
        {"username": "SBI_USER", "password": "password"},
        keys["erp_public_key"], keys["sbi_private_key"],
    )
    # paste `envelope` into Postman as the raw JSON body to an endpoint.
    # copy the encrypted response back:
    plaintext = decrypt_response(
        response, keys["sbi_private_key"], keys["erp_public_key"],
    )
    print(plaintext)
"""

import base64
import json

from sbi_collection import crypto

__all__ = [
	"decrypt_response",
	"encrypt_request",
	"load_keypair_from_files",
	"load_local_keys",
	"load_private_key_from_file",
	"load_public_key_from_file",
]


# --------------------------------------------------------------------------- #
# Envelope helpers (SBI side of the wire)
# --------------------------------------------------------------------------- #
def encrypt_request(payload, erp_public_key, sbi_private_key):
	"""Simulate SBI sending an encrypted request to ERPNext.

		Performs the exact sender steps from the integration document:
		  1. Generate a random 256-bit AES key.
		  2. AES-256-GCM encrypt the JSON payload (fixed zero IV) -> `data`.
		  3. RSA-OAEP (SHA1) encrypt the AES key with ERPNext's public key ->
		     `session_key`.
		  4. SHA256withRSA sign the *ciphertext* `data` with SBI's private key ->
		     `hash_digest`.

		Returns the standard SBI envelope `{"data", "session_key", "hash_digest"}`,
	which the production `crypto.decrypt_request` consumes unchanged.

		Args:
			payload: a JSON-serialisable dict (e.g. {"username": ..., "password": ...}).
			erp_public_key: ERPNext's RSA public key (loaded key object).
			sbi_private_key: SBI's RSA private key (loaded key object).
	"""
	plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

	aes_key = crypto.generate_aes_key()
	data_b64 = crypto.aes_gcm_encrypt(plaintext, aes_key)
	session_key_b64 = crypto.rsa_oaep_encrypt(aes_key, erp_public_key)
	# Sign the ciphertext `data` (matches the doc's "Sign the Encrypted data"
	# and the production verify-over-ciphertext in decrypt_request).
	hash_digest_b64 = crypto.sign(base64.b64decode(data_b64), sbi_private_key)

	return {"data": data_b64, "session_key": session_key_b64, "hash_digest": hash_digest_b64}


def decrypt_response(envelope, sbi_private_key, erp_public_key):
	"""Simulate SBI receiving and decrypting ERPNext's encrypted response.

	Performs the exact receiver steps:
	  1. Verify the response signature over the ciphertext `data` with ERPNext's
	     public key (raises InvalidSignature on mismatch).
	  2. RSA-OAEP decrypt `session_key` with SBI's private key -> AES key.
	  3. AES-256-GCM decrypt `data` with the fixed zero IV -> plaintext JSON.

	Returns the original response dict.

	Args:
		envelope: {"data", "session_key", "hash_digest"} from ERPNext.
		sbi_private_key: SBI's RSA private key (loaded key object).
		erp_public_key: ERPNext's RSA public key (loaded key object).
	"""
	data_b64 = envelope["data"]
	session_key_b64 = envelope["session_key"]
	hash_digest_b64 = envelope["hash_digest"]

	# Step 1: authenticate the sender (ERPNext) via its signature over data.
	crypto.verify(base64.b64decode(data_b64), hash_digest_b64, erp_public_key)

	# Step 2: recover the AES key.
	aes_key = crypto.rsa_oaep_decrypt(session_key_b64, sbi_private_key)

	# Step 3: decrypt the payload.
	plaintext = crypto.aes_gcm_decrypt(data_b64, aes_key)
	return json.loads(plaintext)


# --------------------------------------------------------------------------- #
# Local key-loading helpers (defer to crypto.load_private_key / load_public_key)
# --------------------------------------------------------------------------- #
def load_private_key_from_file(path, password=None):
	"""Load an RSA private key from a PEM file on disk."""
	with open(path, "rb") as file:
		return crypto.load_private_key(file.read(), password=password)


def load_public_key_from_file(path):
	"""Load an RSA public key from a PEM file on disk (openssl `rsa -pubout`)."""
	with open(path, "rb") as file:
		return crypto.load_public_key(file.read())


def load_keypair_from_files(private_key_path, public_key_path, password=None):
	"""Load both halves of one party's keypair from PEM files.

	Returns ``(private_key, public_key)``.
	"""
	return (
		load_private_key_from_file(private_key_path, password=password),
		load_public_key_from_file(public_key_path),
	)


def load_local_keys(
	erp_private_key_path,
	erp_public_key_path,
	sbi_private_key_path,
	sbi_public_key_path,
	private_key_password=None,
):
	"""Load all four local RSA keys (ERPNext + SBI) for the dev workflow.

	Returns a dict:
	    {
	        "erp_private_key": ..., "erp_public_key": ...,
	        "sbi_private_key": ..., "sbi_public_key": ...,
	    }
	`private_key_password` (if given) is applied to BOTH private keys.
	"""
	erp_private_key, erp_public_key = load_keypair_from_files(
		erp_private_key_path, erp_public_key_path, password=private_key_password
	)
	sbi_private_key, sbi_public_key = load_keypair_from_files(
		sbi_private_key_path, sbi_public_key_path, password=private_key_password
	)
	return {
		"erp_private_key": erp_private_key,
		"erp_public_key": erp_public_key,
		"sbi_private_key": sbi_private_key,
		"sbi_public_key": sbi_public_key,
	}
