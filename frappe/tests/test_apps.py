from unittest.mock import patch

import frappe
from frappe.apps import get_default_app, get_desk_landing_route
from frappe.tests import IntegrationTestCase

DEFAULT_APP = "landing_route_test_app"
SYSTEM_MANAGER_WORKSPACE = "/desk/users"
SYSTEM_MANAGER_PAGE = "/desk/permission-manager"
OPEN_WORKSPACE = "/desk/build"
EMPTY_FOR_MEMBERS_WORKSPACE = "/desk/website"
MEMBER_ROLE = "Landing Route Test Member"
MEMBER = "landing-route-member@example.com"


def apps_screen(route: str) -> list[dict]:
	return [{"name": DEFAULT_APP, "route": route}]


def make_member() -> str:
	"""A desk user with a role that grants nothing, so no role-gated workspace or page is theirs."""
	frappe.get_doc({"doctype": "Role", "role_name": MEMBER_ROLE, "desk_access": 1}).insert()
	frappe.get_doc(
		{
			"doctype": "User",
			"email": MEMBER,
			"first_name": "Landing",
			"send_welcome_email": 0,
			"roles": [{"role": MEMBER_ROLE}],
		}
	).insert()
	return MEMBER


class TestDeskLandingRoute(IntegrationTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.member = make_member()

	def setUp(self):
		self.enterContext(patch("frappe.apps.get_default_app", return_value=DEFAULT_APP))
		self.enterContext(patch("frappe.is_setup_complete", return_value=True))

	def landing_route(self, user: str, app_route: str | None = SYSTEM_MANAGER_WORKSPACE) -> str | None:
		apps = apps_screen(app_route) if app_route else []
		with patch("frappe.apps.get_apps", return_value=apps), self.set_user(user):
			frappe.local.request_cache.clear()
			return get_desk_landing_route()

	def test_permitted_user_lands_on_the_default_app(self):
		self.assertEqual(self.landing_route("Administrator"), SYSTEM_MANAGER_WORKSPACE)
		self.assertEqual(
			self.landing_route("Administrator", SYSTEM_MANAGER_PAGE),
			SYSTEM_MANAGER_PAGE,
		)

	def test_user_who_cannot_open_the_route_keeps_the_apps_screen(self):
		self.assertIsNone(self.landing_route(self.member))
		self.assertIsNone(self.landing_route(self.member, SYSTEM_MANAGER_PAGE))
		self.assertEqual(self.landing_route(self.member, OPEN_WORKSPACE), OPEN_WORKSPACE)

	def test_workspace_with_nothing_on_it_for_the_user_keeps_the_apps_screen(self):
		self.assertIsNone(self.landing_route(self.member, EMPTY_FOR_MEMBERS_WORKSPACE))
		self.assertEqual(
			self.landing_route("Administrator", EMPTY_FOR_MEMBERS_WORKSPACE), EMPTY_FOR_MEMBERS_WORKSPACE
		)

	def test_app_hidden_by_its_permission_hook_keeps_the_apps_screen(self):
		self.assertIsNone(self.landing_route("Administrator", app_route=None))

	def test_no_default_app_keeps_the_apps_screen(self):
		with patch("frappe.apps.get_default_app", return_value=None):
			self.assertIsNone(self.landing_route("Administrator"))

	def test_incomplete_setup_keeps_the_apps_screen(self):
		with patch("frappe.is_setup_complete", return_value=False):
			self.assertIsNone(self.landing_route("Administrator"))

	def test_route_that_is_not_one_desk_page_keeps_the_apps_screen(self):
		for route in ("/desk", "/desk/", "/apps", "/crm", "/desk/users/user", "/desk/no-such-page"):
			with self.subTest(route=route):
				self.assertIsNone(self.landing_route("Administrator", route))


class TestDefaultApp(IntegrationTestCase):
	def default_app(self, user_app: str | None, system_app: str | None) -> str | None:
		with (
			patch("frappe.get_cached_value", return_value=user_app),
			patch("frappe.get_system_settings", return_value=system_app),
		):
			return get_default_app()

	def test_user_default_wins_over_the_site_default(self):
		self.assertEqual(self.default_app("hrms", "erpnext"), "hrms")

	def test_site_default_applies_without_a_user_default(self):
		self.assertEqual(self.default_app(None, "erpnext"), "erpnext")
		self.assertEqual(self.default_app("", "erpnext"), "erpnext")

	def test_no_default_without_either(self):
		self.assertFalse(self.default_app(None, None))
