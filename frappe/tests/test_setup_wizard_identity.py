# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE
from unittest.mock import patch

import frappe
from frappe.desk.page.setup_wizard import setup_wizard
from frappe.desk.page.setup_wizard.setup_wizard import bind_identity_to_session
from frappe.tests import UnitTestCase

SESSION_USER = "wizard-session-user@example.com"
OTHER_USER = "wizard-other-user@example.com"


class TestSetupWizardIdentity(UnitTestCase):
	def tearDown(self):
		frappe.set_user("Administrator")

	def test_administrator_may_name_the_first_user(self):
		frappe.set_user("Administrator")
		self.assertEqual(bind_identity_to_session({"email": OTHER_USER}).email, OTHER_USER)

	def test_any_other_user_is_bound_to_their_session(self):
		frappe.set_user(SESSION_USER)
		bound = bind_identity_to_session({"email": OTHER_USER, "full_name": "Someone Else"})
		self.assertEqual(bound.email, SESSION_USER)
		self.assertEqual(bound.full_name, "Someone Else")

	def test_missing_email_stays_missing(self):
		frappe.set_user(SESSION_USER)
		self.assertIsNone(bind_identity_to_session({}).get("email"))

	def test_setup_complete_submits_the_session_user(self):
		submitted = {}

		def capture(stages, kwargs):
			submitted.update(kwargs)
			return {"status": "ok"}

		frappe.set_user(SESSION_USER)
		with (
			patch.object(frappe, "is_setup_complete", return_value=False),
			patch.object(setup_wizard, "get_setup_stages", return_value=[]),
			patch.object(setup_wizard, "process_setup_stages", side_effect=capture),
		):
			setup_wizard.setup_complete({"email": OTHER_USER, "full_name": "Someone Else"})

		self.assertEqual(submitted["email"], SESSION_USER)

	def test_initialize_never_updates_another_user(self):
		frappe.set_user(SESSION_USER)
		with (
			patch.object(frappe, "get_single") as system_settings,
			patch.object(setup_wizard, "create_or_update_user") as create_or_update_user,
		):
			system_settings.return_value.setup_complete = 0
			setup_wizard.initialize_system_settings_and_user(
				{}, {"email": OTHER_USER, "full_name": "Someone Else"}
			)

		self.assertEqual(create_or_update_user.call_args.args[0].email, SESSION_USER)
