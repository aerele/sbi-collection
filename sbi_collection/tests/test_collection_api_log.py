# Copyright (c) 2025, aerele.in and contributors
# For license information, please see license.txt

"""Tests for the Collection API Log DocType and its logger utility.

Covers: create_api_log (Pending + auto-filled transport fields), update_api_log,
mark_success (with processing_time), mark_failed (with error_message), the
defensive behaviour (non-existent name does not raise), and an end-to-end call
through the `authenticate` endpoint asserting a log row is created and finalised.
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from sbi_collection import api
from sbi_collection.utils.logger import (
	LOG_DOCTYPE,
	create_api_log,
	mark_failed,
	mark_success,
	update_api_log,
)


class TestCollectionApiLog(FrappeTestCase):
	def setUp(self):
		# Track log rows created by each test so they're cleaned up afterwards.
		self._created = []

	def tearDown(self):
		for name in self._created:
			frappe.delete_doc(LOG_DOCTYPE, name, force=1, ignore_permissions=True)

	# -------------------------------------------------------------- #
	# create_api_log
	# -------------------------------------------------------------- #
	def test_create_api_log_returns_name_and_pending_status(self):
		name = create_api_log(api_name="authenticate", request_payload={"a": 1})
		self._created.append(name)
		self.assertTrue(name)

		doc = frappe.get_doc(LOG_DOCTYPE, name)
		self.assertEqual(doc.api_name, "authenticate")
		self.assertEqual(doc.status, "Pending")
		self.assertTrue(doc.started_at)
		# Request payload is pretty-printed JSON.
		self.assertIn('"a"', doc.request_payload)

	def test_create_api_log_records_explicit_transport_fields(self):
		# Transport fields can be supplied explicitly (auto-fill from the live
		# request is best-effort and request-context dependent, so we assert on
		# the explicit path here).
		name = create_api_log(
			api_name="dealer_validation",
			http_method="POST",
			endpoint="/api/method/sbi_collection.api.dealer_validation",
			remote_ip="203.0.113.7",
		)
		self._created.append(name)
		doc = frappe.get_doc(LOG_DOCTYPE, name)
		self.assertEqual(doc.http_method, "POST")
		self.assertEqual(doc.endpoint, "/api/method/sbi_collection.api.dealer_validation")
		self.assertEqual(doc.remote_ip, "203.0.113.7")

	# -------------------------------------------------------------- #
	# update_api_log
	# -------------------------------------------------------------- #
	def test_update_api_log_patches_fields(self):
		name = create_api_log(api_name="transaction_post")
		self._created.append(name)
		update_api_log(name, van="NEDFER00000001", amount="300.00")

		values = frappe.db.get_value(LOG_DOCTYPE, name, ["van", "amount"], as_dict=True)
		self.assertEqual(values.van, "NEDFER00000001")
		self.assertEqual(values.amount, 300.0)

	# -------------------------------------------------------------- #
	# mark_success
	# -------------------------------------------------------------- #
	def test_mark_success_sets_status_response_and_processing_time(self):
		name = create_api_log(api_name="authenticate")
		self._created.append(name)
		mark_success(name, response_payload={"status": "success"})

		values = frappe.db.get_value(
			LOG_DOCTYPE,
			name,
			["status", "response_payload", "processing_time"],
			as_dict=True,
		)
		self.assertEqual(values.status, "Success")
		self.assertIn('"success"', values.response_payload)
		# started_at was set moments ago, so processing_time should be >= 0.
		self.assertIsNotNone(values.processing_time)
		self.assertGreaterEqual(values.processing_time, 0)

	# -------------------------------------------------------------- #
	# mark_failed
	# -------------------------------------------------------------- #
	def test_mark_failed_sets_status_and_error_message(self):
		name = create_api_log(api_name="authenticate")
		self._created.append(name)
		mark_failed(name, error="boom: bad signature")

		values = frappe.db.get_value(LOG_DOCTYPE, name, ["status", "error_message"], as_dict=True)
		self.assertEqual(values.status, "Failed")
		self.assertEqual(values.error_message, "boom: bad signature")

	# -------------------------------------------------------------- #
	# defensive behaviour
	# -------------------------------------------------------------- #
	def test_mark_success_on_nonexistent_name_does_not_raise(self):
		# A bad name should be a no-op (logged to Error Log), never an exception.
		before = frappe.db.count(LOG_DOCTYPE)
		mark_success("NONEXISTENT-LOG-NAME", response_payload={"x": 1})
		after = frappe.db.count(LOG_DOCTYPE)
		self.assertEqual(before, after)

	def test_update_api_log_ignores_none_values(self):
		name = create_api_log(api_name="authenticate")
		self._created.append(name)
		# Passing None for van should NOT overwrite (no value written).
		update_api_log(name, van=None, customer="CUST-1")
		values = frappe.db.get_value(LOG_DOCTYPE, name, ["van", "customer"], as_dict=True)
		self.assertIsNone(values.van)
		self.assertEqual(values.customer, "CUST-1")

	# -------------------------------------------------------------- #
	# end-to-end through the endpoint
	# -------------------------------------------------------------- #
	def test_authenticate_creates_and_finalises_log(self):
		# Call the whitelisted endpoint directly. With the real authentication
		# implementation in place, calling authenticate() with no body and no
		# configured credentials returns status_code 01 and the log is marked Failed.
		# This test just verifies the log lifecycle (create -> finalise) is
		# exercised end-to-end by the endpoint.
		result = api.authenticate()
		self.assertEqual(result["status_code"], "01")

		# The most recent log row should be our authenticate call, now finalised.
		name = frappe.db.get_value(
			LOG_DOCTYPE,
			{"api_name": "authenticate"},
			order_by="creation desc",
		)
		self.assertTrue(name, "authenticate did not create a log row")
		self._created.append(name)
		status = frappe.db.get_value(LOG_DOCTYPE, name, "status")
		# Auth failure (no creds configured) -> the log is marked Failed.
		self.assertEqual(status, "Failed")
