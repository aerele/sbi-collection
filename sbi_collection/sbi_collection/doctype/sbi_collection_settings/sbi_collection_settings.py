# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document
from frappe.utils.password import get_decrypted_password

from sbi_collection.crypto import load_private_key, load_public_key


class SBICollectionSettings(Document):
	# -------------------------------------------------------------- #
	# Key loading - the single bridge between this DocType and crypto.py
	# -------------------------------------------------------------- #
	def load_keys(self):
		"""Return loaded key objects for the crypto envelope.

		Returns a tuple ``(client_private_key, sbi_public_key)``. The keys are
		read from the attached PEM files and (for the private key) decrypted
		using the stored passphrase when present.
		"""
		password = self.get_password("client_private_key_password", raise_exception=False)
		password = password.encode("utf-8") if password else None

		with open(self._file_path(self.client_private_key), "rb") as file:
			client_private_key = load_private_key(file.read(), password=password)

		with open(self._file_path(self.sbi_public_key), "rb") as file:
			sbi_public_key = load_public_key(file.read())

		return client_private_key, sbi_public_key

	def get_password(self, fieldname, raise_exception=True):
		"""Return the decrypted value of a Password-type field."""
		return get_decrypted_password(self.doctype, self.name, fieldname, raise_exception=raise_exception)

	@staticmethod
	def _file_path(file_url):
		"""Resolve an Attach field's file_url to an absolute filesystem path."""
		return frappe.get_doc("File", {"file_url": file_url}).get_full_path()


@frappe.whitelist()
def get_settings():
	"""Return the cached SBI Collection Settings singleton document."""
	return frappe.get_cached_doc("SBI Collection Settings")
