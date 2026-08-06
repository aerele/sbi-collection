# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Tests for VAN generation.

These exercise the full server flow: custom field, Settings, the
`generate_van` method (success, idempotency, prefix validation, uniqueness,
prefix-stripping). Uses real Customer documents in the test DB.
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from sbi_collection.van import build_van, generate_van


def _set_settings(**values):
	"""Set SBI Collection Settings fields directly, bypassing mandatory checks.

	`change_settings` does a full `.save()`, which fails because the crypto/auth
	fields on the Settings singleton are mandatory - and the VAN tests don't
	care about them. We write directly and invalidate the cache so
	`get_cached_doc` inside `generate_van` re-reads the row.
	"""
	doc = frappe.get_doc("SBI Collection Settings", "SBI Collection Settings")
	for key, value in values.items():
		doc.db_set(key, value)
	frappe.clear_cache(doctype="SBI Collection Settings")
	frappe.clear_document_cache("SBI Collection Settings", "SBI Collection Settings")


class TestVanGeneration(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		# Ensure the custom field exists for this test run.
		from sbi_collection.install import make_custom_fields

		make_custom_fields()

	def setUp(self):
		# A unique prefix per test avoids cross-test collisions on Settings.
		self.prefix = "TEST" + frappe.generate_hash(length=2).upper()
		# Patch the prefix-validation regex to accept this 6-char prefix
		# (it's already alphanumeric, so no patching needed).
		self.customer = self._make_customer(self.prefix + "00000001")

	def tearDown(self):
		frappe.delete_doc("Customer", self.customer, force=1)
		# Clear any VAN set on Settings so tests don't bleed into each other.
		# Use db_set to avoid mandatory-field validation on the crypto/auth
		# fields (they're empty in these tests).
		frappe.get_doc("SBI Collection Settings", "SBI Collection Settings").db_set(
			"van_prefix", None
		)

	# -------------------------------------------------------------- #
	# build_van unit tests (pure function, no DB)
	# -------------------------------------------------------------- #
	def test_build_van_strips_leading_prefix(self):
		"""When the docname starts with the prefix, it is stripped once."""
		self.assertEqual(build_van("NEDFER", "NEDFER00000001"), "NEDFER00000001")

	def test_build_van_no_strip_when_prefix_absent(self):
		"""If the docname doesn't start with the prefix, use it whole."""
		self.assertEqual(build_van("NEDFER", "OTHER00000001"), "NEDFEROTHER00000001")

	def test_build_van_case_insensitive_strip(self):
		"""Prefix match is case-insensitive; remainder keeps its case."""
		self.assertEqual(build_van("nedfer", "NEDFER00000001"), "nedfer00000001")

	# -------------------------------------------------------------- #
	# generate_van integration tests
	# -------------------------------------------------------------- #
	def test_generate_van_success(self):
		"""Happy path: prefix stripped from docname, VAN persisted and returned."""
		_set_settings(van_prefix=self.prefix)
		van = generate_van(self.customer)
		self.assertEqual(van, self.prefix + "00000001")
		self.assertEqual(
			frappe.db.get_value("Customer", self.customer, "collection_van"),
			van,
		)

	def test_generate_van_is_idempotent(self):
		"""Second call on the same customer is rejected, not regenerated."""
		_set_settings(van_prefix=self.prefix)
		first = generate_van(self.customer)
		with self.assertRaises(frappe.exceptions.ValidationError):
			generate_van(self.customer)
		# Value unchanged after the rejected attempt.
		self.assertEqual(
			frappe.db.get_value("Customer", self.customer, "collection_van"),
			first,
		)

	def test_generate_van_rejects_bad_prefix(self):
		"""Prefixes that aren't exactly 6 alphanumeric chars are rejected."""
		cases = ["", "ABC", "ABCDEFG", "ABC!@#", "ABC DE"]
		for bad in cases:
			with self.subTest(prefix=bad):
				_set_settings(van_prefix=bad)
				with self.assertRaises(frappe.exceptions.ValidationError):
					generate_van(self.customer)

	def test_generate_van_rejects_duplicate_globally(self):
		"""Two customers cannot end up with the same VAN."""
		other = self._make_customer(self.prefix + "00000002")
		try:
			_set_settings(van_prefix=self.prefix)
			# Force both customers to resolve to the same VAN by pre-setting the
			# second customer's VAN to the value the first one will generate.
			first_van = self.prefix + "00000001"
			frappe.db.set_value("Customer", other, "collection_van", first_van)
			# Now generating for `self.customer` (which would produce the
			# same VAN) must be rejected.
			with self.assertRaises(frappe.exceptions.ValidationError):
				generate_van(self.customer)
		finally:
			frappe.delete_doc("Customer", other, force=1)

	def test_generate_van_respects_max_length(self):
		"""A VAN exceeding the configured max length is rejected."""
		long_prefix = "ABCDEF"  # 6 chars - valid prefix
		# Customer with a very long docname (manual rename).
		long_customer = self._make_customer("ABCDEF" + "X" * 30)
		try:
			_set_settings(van_prefix=long_prefix, van_max_length=20)
			with self.assertRaises(frappe.exceptions.ValidationError):
				generate_van(long_customer)
		finally:
			frappe.delete_doc("Customer", long_customer, force=1)

	# -------------------------------------------------------------- #
	# helpers
	# -------------------------------------------------------------- #
	def _make_customer(self, name):
		"""Create a Customer with an explicit docname (to control the VAN).

		Resolves a real Customer Group and Territory from the DB instead of
		relying on ERPNext's `_Test *` fixtures (which may not be installed).
		"""
		doc = frappe.get_doc(
			{
				"doctype": "Customer",
				"customer_name": name,
				"customer_group": frappe.db.get_single_value("Selling Settings", "customer_group")
				or frappe.db.get_value("Customer Group", {"is_group": 0}),
				"territory": frappe.db.get_value("Territory", {"is_group": 0}),
			}
		)
		doc.insert(ignore_permissions=True)
		# Force the docname to the value our VAN logic expects.
		if doc.name != name:
			doc.rename(name)
		return doc.name
