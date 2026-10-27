from unittest.mock import patch

import frappe
from frappe.apps import get_default_app, get_desk_landing_route
from frappe.desk.utils import slug
from frappe.permissions import add_permission
from frappe.tests import IntegrationTestCase

DEFAULT_APP = "landing_route_test_app"
MEMBER_ROLE = "Landing Route Test Member"
MEMBER = "landing-route-member@example.com"
READABLE_DOCTYPE = "Module Profile"
UNREADABLE_DOCTYPE = "Role Profile"
OPEN_WORKSPACE = "Landing Route Readable"
EMPTY_FOR_MEMBERS_WORKSPACE = "Landing Route Unreadable"
SYSTEM_MANAGER_WORKSPACE = "Landing Route System Manager"
SYSTEM_MANAGER_PAGE = "/desk/permission-manager"


def apps_screen(route: str) -> list[dict]:
	return [{"name": DEFAULT_APP, "route": route}]


def desk_route(workspace: str) -> str:
	return "/desk/" + slug(workspace)


def make_member() -> str:
	"""A desk user whose role reads one doctype and nothing role-gated."""
	frappe.get_doc({"doctype": "Role", "role_name": MEMBER_ROLE, "desk_access": 1}).insert()
	add_permission(READABLE_DOCTYPE, MEMBER_ROLE)
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


def make_workspace(title: str, doctype: str, roles: tuple[str, ...] = ()) -> None:
	frappe.get_doc(
		{
			"doctype": "Workspace",
			"title": title,
			"label": title,
			"public": 1,
			"module": "Desk",
			"content": "[]",
			"shortcuts": [{"type": "DocType", "link_to": doctype, "label": doctype}],
			"roles": [{"role": role} for role in roles],
		}
	).insert()


def forget_test_permissions() -> None:
	"""Rolled back rows can outlive the test in the cached permissions of their doctypes."""
	frappe.db.rollback()
	frappe.clear_cache(doctype=READABLE_DOCTYPE)
	frappe.clear_cache(doctype=UNREADABLE_DOCTYPE)


class TestDeskLandingRoute(IntegrationTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.addClassCleanup(forget_test_permissions)
		cls.member = make_member()
		make_workspace(OPEN_WORKSPACE, READABLE_DOCTYPE)
		make_workspace(EMPTY_FOR_MEMBERS_WORKSPACE, UNREADABLE_DOCTYPE)
		make_workspace(SYSTEM_MANAGER_WORKSPACE, READABLE_DOCTYPE, roles=("System Manager",))

	def setUp(self):
		self.enterContext(patch("frappe.apps.get_default_app", return_value=DEFAULT_APP))
		self.enterContext(patch("frappe.is_setup_complete", return_value=True))

	def landing_route(self, user: str, app_route: str | None) -> str | None:
		apps = apps_screen(app_route) if app_route else []
		with patch("frappe.apps.get_apps", return_value=apps), self.set_user(user):
			frappe.local.request_cache.clear()
			return get_desk_landing_route()

	def test_permitted_user_lands_on_the_default_app(self):
		route = desk_route(SYSTEM_MANAGER_WORKSPACE)
		self.assertEqual(self.landing_route("Administrator", route), route)
		self.assertEqual(self.landing_route("Administrator", SYSTEM_MANAGER_PAGE), SYSTEM_MANAGER_PAGE)

	def test_user_who_cannot_open_the_route_keeps_the_apps_screen(self):
		self.assertIsNone(self.landing_route(self.member, desk_route(SYSTEM_MANAGER_WORKSPACE)))
		self.assertIsNone(self.landing_route(self.member, SYSTEM_MANAGER_PAGE))

		route = desk_route(OPEN_WORKSPACE)
		self.assertEqual(self.landing_route(self.member, route), route)

	def test_workspace_with_nothing_on_it_for_the_user_keeps_the_apps_screen(self):
		route = desk_route(EMPTY_FOR_MEMBERS_WORKSPACE)
		self.assertIsNone(self.landing_route(self.member, route))
		self.assertEqual(self.landing_route("Administrator", route), route)

	def test_app_hidden_by_its_permission_hook_keeps_the_apps_screen(self):
		self.assertIsNone(self.landing_route("Administrator", None))

	def test_no_default_app_keeps_the_apps_screen(self):
		with patch("frappe.apps.get_default_app", return_value=None):
			self.assertIsNone(self.landing_route("Administrator", desk_route(SYSTEM_MANAGER_WORKSPACE)))

	def test_incomplete_setup_keeps_the_apps_screen(self):
		with patch("frappe.is_setup_complete", return_value=False):
			self.assertIsNone(self.landing_route("Administrator", desk_route(SYSTEM_MANAGER_WORKSPACE)))

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
