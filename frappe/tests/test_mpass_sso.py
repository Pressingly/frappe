# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE
import base64
import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import frappe
from frappe.auth import CookieManager, LoginManager
from frappe.mpass_sso import (
	ACCESS_TOKEN_HEADER,
	EDGE_SECRET_HEADER,
	EMAIL_HEADER,
	MEMBER_ROLE,
	MpassRefusalError,
	MpassSettings,
	Outcome,
	admissible_role,
	apply_proxy_identity,
	asserted_identity,
	corporate_ok,
	decide,
	decode_jwt_payload,
	from_edge,
	inspects_request,
	is_email_shaped,
	normalise,
	portal_url,
	resolve_email,
)
from frappe.tests import IntegrationTestCase, UnitTestCase
from frappe.tests.test_api import FrappeAPITestCase, make_request
from frappe.utils import get_test_client, set_request

CORPORATE_ID = "corp-123"
EDGE_SECRET = "s" * 40
PORTAL_URL = "https://portal.example.com/"
SSO_ENV = {
	"AUTH_TYPE": "SSO",
	"DEFAULT_EMAIL_DOMAIN": "foss.local",
	"SMB_CORPORATE_ID": CORPORATE_ID,
	"LOGOUT_REDIRECT_URL": PORTAL_URL,
}


def jwt(claims: dict) -> str:
	payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
	return f"header.{payload}.signature"


def corporate_token(corporate_id: str = CORPORATE_ID) -> str:
	return jwt({"custom:is_corporate": "true", "custom:corporate_id": corporate_id})


def raw_jwt(payload: bytes) -> str:
	return f"header.{base64.urlsafe_b64encode(payload).rstrip(b'=').decode()}.signature"


def purge_test_users(*emails: str) -> None:
	"""SSO logins commit, so test users, their sessions and the member role outlive rollbacks."""
	frappe.set_user("Administrator")
	for email in emails:
		frappe.db.delete("Sessions", {"user": email})
		frappe.delete_doc_if_exists("User", email, force=True)
	if not frappe.db.exists("Has Role", {"role": MEMBER_ROLE}):
		frappe.delete_doc_if_exists("Role", MEMBER_ROLE, force=True)
	frappe.db.commit()


class TestMpassIdentityHelpers(UnitTestCase):
	def test_settings_from_env(self):
		settings = MpassSettings.from_env(
			{"AUTH_TYPE": "SSO", "DEFAULT_EMAIL_DOMAIN": " Foss.Local ", "SMB_CORPORATE_ID": " c1 "}
		)
		self.assertTrue(settings.sso_enabled)
		self.assertEqual(settings.default_email_domain, "foss.local")
		self.assertEqual(settings.corporate_id, "c1")
		self.assertFalse(MpassSettings.from_env({}).sso_enabled)
		self.assertFalse(MpassSettings.from_env({"AUTH_TYPE": "sso"}).sso_enabled)

	def test_normalise(self):
		self.assertEqual(normalise("  Jane@Example.COM "), "jane@example.com")
		self.assertEqual(normalise(None), "")

	def test_email_shape(self):
		for value, expected in (
			("a@b.co", True),
			("a@b.c", True),
			("@b.co", False),
			("a@b", False),
			("a@.co", False),
			("1020010000019120", False),
		):
			with self.subTest(value=value):
				self.assertEqual(is_email_shaped(value), expected)

	def test_resolve_email(self):
		self.assertEqual(resolve_email("jane@example.com", ""), "jane@example.com")
		self.assertEqual(resolve_email("1020010000019120", "foss.local"), "1020010000019120@foss.local")
		self.assertIsNone(resolve_email("1020010000019120", ""))
		self.assertIsNone(resolve_email("@example.com", "foss.local"))
		self.assertIsNone(resolve_email("", "foss.local"))
		self.assertIsNone(resolve_email("a" * 140 + "@example.com", ""))

	def test_from_edge(self):
		self.assertTrue(from_edge(None, ""))
		self.assertTrue(from_edge(EDGE_SECRET, EDGE_SECRET))
		self.assertFalse(from_edge(None, EDGE_SECRET))
		self.assertFalse(from_edge("wrong", EDGE_SECRET))
		self.assertFalse(from_edge("short", "short"))

	def test_asserted_identity(self):
		open_settings = MpassSettings(auth_type="SSO")
		gated_settings = MpassSettings(auth_type="SSO", edge_secret=EDGE_SECRET)
		headers = {EMAIL_HEADER: " Jane@Example.com "}

		self.assertEqual(asserted_identity(headers, open_settings), "jane@example.com")
		self.assertEqual(asserted_identity(headers, gated_settings), "")
		self.assertEqual(
			asserted_identity({**headers, EDGE_SECRET_HEADER: EDGE_SECRET}, gated_settings),
			"jane@example.com",
		)
		self.assertEqual(asserted_identity({}, open_settings), "")

	def test_decode_jwt_payload(self):
		self.assertEqual(decode_jwt_payload(jwt({"a": "b"})), {"a": "b"})
		self.assertIsNone(decode_jwt_payload(None))
		self.assertIsNone(decode_jwt_payload("not-a-jwt"))
		self.assertIsNone(decode_jwt_payload("a..c"))
		self.assertIsNone(decode_jwt_payload("a.!!!.c"))
		self.assertIsNone(decode_jwt_payload(jwt(["a"])))
		self.assertIsNone(decode_jwt_payload(jwt({"pad": "x" * 9000})))
		self.assertIsNone(decode_jwt_payload(raw_jwt(b"[" * 5000)))

	def test_corporate_ok(self):
		bound = MpassSettings(corporate_id=CORPORATE_ID)
		self.assertTrue(corporate_ok(corporate_token(), bound))
		self.assertFalse(corporate_ok(corporate_token("other"), bound))
		self.assertFalse(
			corporate_ok(jwt({"custom:is_corporate": True, "custom:corporate_id": CORPORATE_ID}), bound)
		)
		self.assertFalse(corporate_ok(jwt({"custom:corporate_id": CORPORATE_ID}), bound))
		self.assertFalse(corporate_ok(None, bound))
		self.assertFalse(corporate_ok(corporate_token(), MpassSettings()))
		self.assertTrue(corporate_ok(None, MpassSettings(allow_any_tenant="1")))

	def test_portal_url(self):
		self.assertEqual(portal_url(" https://portal.example.com/ "), "https://portal.example.com/")
		self.assertEqual(portal_url("http://portal.example.com"), "http://portal.example.com")
		self.assertIsNone(portal_url("/relative"))
		self.assertIsNone(portal_url("javascript:alert(1)"))
		self.assertIsNone(portal_url("https://"))
		self.assertIsNone(portal_url(None))

	def test_decision_table(self):
		jane = "jane@example.com"
		for email, session_user, impersonated_by, admitted, expected in (
			(None, "Guest", None, True, Outcome.UNRESOLVABLE),
			(None, jane, None, True, Outcome.UNRESOLVABLE),
			(jane, "Guest", None, False, Outcome.CORPORATE),
			(jane, jane, None, False, Outcome.CORPORATE),
			(jane, jane, None, True, Outcome.KEEP),
			(jane, "Jane@Example.com", None, True, Outcome.KEEP),
			(jane, "bob@example.com", jane, True, Outcome.KEEP),
			(jane, "Guest", None, True, Outcome.LOGIN),
			(jane, "bob@example.com", None, True, Outcome.LOGIN),
			(jane, "bob@example.com", "carol@example.com", True, Outcome.LOGIN),
			(jane, "Administrator", None, True, Outcome.LOGIN),
			(jane, "Administrator", None, False, Outcome.CORPORATE),
			(None, "Administrator", None, True, Outcome.UNRESOLVABLE),
		):
			with self.subTest(email=email, session_user=session_user, impersonated_by=impersonated_by):
				self.assertEqual(decide(email, session_user, impersonated_by, admitted), expected)

	def test_admissible_role(self):
		member = {"name": MEMBER_ROLE, "disabled": 0, "desk_access": 1}
		self.assertTrue(admissible_role(member))
		self.assertFalse(admissible_role(None))
		self.assertFalse(admissible_role({**member, "disabled": 1}))
		self.assertFalse(admissible_role({**member, "desk_access": 0}))
		for privileged in ("System Manager", "Administrator", "All", "Guest", "Desk User"):
			with self.subTest(role=privileged):
				self.assertFalse(admissible_role({**member, "name": privileged}))

	def test_inspects_request(self):
		def request(method="GET", **headers):
			return SimpleNamespace(method=method, headers=headers)

		self.assertTrue(inspects_request(request(), "Guest"))
		self.assertTrue(inspects_request(request(), "jane@example.com"))
		self.assertFalse(inspects_request(request("OPTIONS"), "Guest"))
		self.assertFalse(inspects_request(request(Authorization="token a:b"), "Guest"))
		self.assertTrue(inspects_request(request(Authorization="x"), "jane@example.com"))
		self.assertFalse(inspects_request(None, "Guest"))


class TestMpassProxyLogin(IntegrationTestCase):
	jane = "mpass-jane@example.com"
	bob = "mpass-bob@example.com"
	settings = MpassSettings(auth_type="SSO", default_email_domain="foss.local", corporate_id=CORPORATE_ID)

	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		for user in (self.jane, self.bob, "1020010000019120@foss.local"):
			frappe.delete_doc_if_exists("User", user, force=True)
		frappe.set_user("Guest")

	def tearDown(self):
		frappe.db.rollback()
		frappe.set_user("Administrator")
		super().tearDown()

	@classmethod
	def tearDownClass(cls):
		purge_test_users(cls.jane, cls.bob, "1020010000019120@foss.local")
		super().tearDownClass()

	def start_request(self, email: str | None = None, token: str | None = None, **extra_headers):
		headers = {ACCESS_TOKEN_HEADER: token or corporate_token(), **extra_headers}
		if email is not None:
			headers[EMAIL_HEADER] = email
		set_request(method="GET", path="/desk", headers=headers)
		frappe.local.cookie_manager = CookieManager()
		frappe.local.login_manager = LoginManager()
		return frappe.local.login_manager

	def apply(self, login_manager, settings: MpassSettings | None = None):
		apply_proxy_identity(login_manager, settings or self.settings)

	def test_guest_is_provisioned_as_member(self):
		self.apply(self.start_request(" MPASS-Jane@Example.com "))

		self.assertEqual(frappe.session.user, self.jane)
		user = frappe.get_doc("User", self.jane)
		self.assertEqual(user.user_type, "System User")
		self.assertEqual(user.send_welcome_email, 0)
		self.assertEqual([r.role for r in user.roles], [MEMBER_ROLE])
		self.assertNotIn("message", frappe.local.response)
		self.assertTrue(frappe.session.data.csrf_token)

	def test_bare_mpass_id_uses_default_domain(self):
		self.apply(self.start_request("1020010000019120"))
		self.assertEqual(frappe.session.user, "1020010000019120@foss.local")

	def test_same_user_keeps_session(self):
		login_manager = self.start_request(self.jane)
		self.apply(login_manager)
		sid = frappe.session.sid

		self.apply(login_manager)
		self.assertEqual(frappe.session.sid, sid)

	def test_different_user_replaces_session(self):
		self.apply(self.start_request(self.jane))
		login_manager = self.start_request(self.bob)
		login_manager.login_as(self.jane)
		old_sid = frappe.session.sid

		self.apply(login_manager)

		self.assertEqual(frappe.session.user, self.bob)
		self.assertNotEqual(frappe.session.sid, old_sid)
		self.assertFalse(frappe.db.exists("Sessions", {"sid": old_sid}))
		self.assertNotIn("sid", frappe.local.cookie_manager.to_delete)

	def test_administrator_session_is_replaced_by_the_asserted_user(self):
		login_manager = self.start_request(self.jane)
		login_manager.login_as("Administrator")
		admin_sid = frappe.session.sid

		self.apply(login_manager)

		self.assertEqual(frappe.session.user, self.jane)
		self.assertFalse(frappe.db.exists("Sessions", {"sid": admin_sid}))

	def test_impersonation_by_asserted_user_is_kept(self):
		self.apply(self.start_request(self.bob))
		login_manager = self.start_request(self.jane)
		login_manager.login_as(self.bob)
		frappe.local.session_obj.set_impersonated(self.jane)

		self.apply(login_manager)
		self.assertEqual(frappe.session.user, self.bob)

	def test_existing_user_is_not_re_roled(self):
		frappe.get_doc(
			doctype="User", email=self.jane, first_name="Jane", roles=[{"role": "System Manager"}]
		).insert(ignore_permissions=True)

		self.apply(self.start_request(self.jane))

		self.assertEqual(frappe.session.user, self.jane)
		self.assertEqual([r.role for r in frappe.get_doc("User", self.jane).roles], ["System Manager"])

	def test_refusals(self):
		frappe.db.set_value("User", "Administrator", "email", "mpass-admin@example.com")
		frappe.get_doc(doctype="User", email=self.bob, first_name="Bob", enabled=0).insert(
			ignore_permissions=True
		)
		unbound = MpassSettings(auth_type="SSO", corporate_id=CORPORATE_ID)
		cases = (
			("unbound tenant", self.jane, corporate_token("other"), self.settings, Outcome.CORPORATE),
			("no corporate id", self.jane, None, MpassSettings(auth_type="SSO"), Outcome.CORPORATE),
			("bare id without domain", "1020010000019120", None, unbound, Outcome.UNRESOLVABLE),
			("administrator email", "mpass-admin@example.com", None, self.settings, Outcome.RESERVED),
			("disabled user", self.bob, None, self.settings, Outcome.DISABLED),
			(
				"admin default role",
				self.jane,
				None,
				MpassSettings(auth_type="SSO", corporate_id=CORPORATE_ID, default_role="System Manager"),
				Outcome.ROLE,
			),
		)
		for label, email, token, settings, reason in cases:
			with self.subTest(label):
				login_manager = self.start_request(email, token=token)
				with self.assertRaises(MpassRefusalError) as refusal:
					self.apply(login_manager, settings)
				self.assertEqual(refusal.exception.reason, reason)
				self.assertEqual(frappe.session.user, "Guest")
				self.assertFalse(frappe.db.exists("User", self.jane))

	def test_refusal_ends_existing_session(self):
		self.apply(self.start_request(self.jane))
		login_manager = self.start_request(self.jane, token=corporate_token("other"))
		login_manager.login_as(self.jane)
		sid = frappe.session.sid

		frappe.local.message_log = []
		with self.assertRaises(MpassRefusalError) as refusal:
			self.apply(login_manager)

		self.assertEqual(frappe.session.user, "Guest")
		self.assertFalse(frappe.db.exists("Sessions", {"sid": sid}))
		for key in ("message", "home_page", "full_name"):
			self.assertNotIn(key, frappe.local.response)
		self.assertIn(
			refusal.exception.page_message, [entry.get("message") for entry in frappe.local.message_log]
		)

	def test_authorization_header_does_not_shield_a_cookie_session(self):
		self.apply(self.start_request(self.jane))
		login_manager = self.start_request(self.jane, token=corporate_token("other"), Authorization="x")
		login_manager.login_as(self.jane)

		with self.assertRaises(MpassRefusalError) as refusal:
			self.apply(login_manager)

		self.assertEqual(refusal.exception.reason, Outcome.CORPORATE)
		self.assertEqual(frappe.session.user, "Guest")

	def test_requests_left_alone(self):
		edge_gated = MpassSettings(auth_type="SSO", corporate_id=CORPORATE_ID, edge_secret=EDGE_SECRET)
		cases = (
			("sso off", self.jane, {}, MpassSettings()),
			("no identity header", None, {}, self.settings),
			("blank identity header", "  ", {}, self.settings),
			("token auth", self.jane, {"Authorization": "token a:b"}, self.settings),
			("edge secret missing", self.jane, {}, edge_gated),
			("edge secret wrong", self.jane, {EDGE_SECRET_HEADER: "x" * 40}, edge_gated),
		)
		for label, email, headers, settings in cases:
			with self.subTest(label):
				self.apply(self.start_request(email, **headers), settings)
				self.assertEqual(frappe.session.user, "Guest")
				self.assertFalse(frappe.db.exists("User", self.jane))

	def test_edge_secret_admits_matching_request(self):
		settings = MpassSettings(auth_type="SSO", corporate_id=CORPORATE_ID, edge_secret=EDGE_SECRET)
		self.apply(self.start_request(self.jane, **{EDGE_SECRET_HEADER: EDGE_SECRET}), settings)
		self.assertEqual(frappe.session.user, self.jane)


class ReachedAuthenticate(Exception):
	pass


class ReachedPastGuard(Exception):
	pass


class TestMpassPasswordLogin(IntegrationTestCase):
	def attempt_password_login(self, usr: str, auth_type: str, password_login_disabled: int):
		system_setting = frappe.get_system_settings

		def settings(key):
			return password_login_disabled if key == "disable_user_pass_login" else system_setting(key)

		set_request(method="POST", path="/api/method/login")
		frappe.local.form_dict = frappe._dict(usr=usr, pwd="irrelevant")
		login_manager = LoginManager.__new__(LoginManager)
		with (
			patch.dict(os.environ, {"AUTH_TYPE": auth_type}),
			patch.object(frappe, "get_system_settings", side_effect=settings),
			patch.object(LoginManager, "authenticate", side_effect=ReachedAuthenticate),
		):
			login_manager.login()

	def test_every_password_login_is_refused_under_sso(self):
		for usr in ("Administrator", "administrator", "jane@example.com"):
			for password_login_disabled in (0, 1):
				with (
					self.subTest(usr=usr, password_login_disabled=password_login_disabled),
					self.assertRaises(frappe.AuthenticationError),
				):
					self.attempt_password_login(usr, "SSO", password_login_disabled)

	def test_password_login_is_upstream_without_sso(self):
		for usr in ("Administrator", "jane@example.com"):
			with self.subTest(usr=usr):
				with self.assertRaises(ReachedAuthenticate):
					self.attempt_password_login(usr, "", 0)
				with self.assertRaises(frappe.AuthenticationError):
					self.attempt_password_login(usr, "", 1)

	def assert_refused_only_under_sso(self, call, past_the_guard: str):
		with patch(past_the_guard, side_effect=ReachedPastGuard):
			with patch.dict(os.environ, {"AUTH_TYPE": "SSO"}), self.assertRaises(frappe.PermissionError):
				call()
			with patch.dict(os.environ, {"AUTH_TYPE": ""}), self.assertRaises(ReachedPastGuard):
				call()

	def test_ldap_login_is_refused_only_under_sso(self):
		from frappe.integrations.doctype.ldap_settings.ldap_settings import login

		frappe.local.form_dict = frappe._dict(usr="jane", pwd="irrelevant")
		self.assert_refused_only_under_sso(
			login, "frappe.integrations.doctype.ldap_settings.ldap_settings.LDAPSettings.authenticate"
		)

	def test_social_login_is_refused_only_under_sso(self):
		from frappe.utils.oauth import login_oauth_user

		self.assert_refused_only_under_sso(
			lambda: login_oauth_user({"email": "jane@example.com"}, provider="google", state="x"),
			"frappe.utils.oauth.consume_oauth_state",
		)

	def test_invitation_acceptance_is_refused_only_under_sso(self):
		from frappe.core.api.user_invitation import accept_invitation

		self.assert_refused_only_under_sso(
			lambda: accept_invitation("x"), "frappe.core.api.user_invitation._accept_invitation"
		)

	def test_system_settings_accept_disabled_password_login_under_sso(self):
		settings = frappe.get_doc("System Settings")
		settings.disable_user_pass_login = 1
		settings.login_with_email_link = 0

		with patch.dict(os.environ, {"AUTH_TYPE": "SSO"}):
			settings.validate_user_pass_login()

		has_other_login = frappe.db.exists(
			"Social Login Key", {"enable_social_login": 1}
		) or frappe.db.get_single_value("LDAP Settings", "enabled")
		if has_other_login:
			return
		with patch.dict(os.environ, {"AUTH_TYPE": ""}), self.assertRaises(frappe.ValidationError):
			settings.validate_user_pass_login()


class TestMpassHTTPRequest(FrappeAPITestCase):
	user = "mpass-http@example.com"

	def setUp(self):
		super().setUp()
		sso = patch.dict(os.environ, SSO_ENV)
		sso.start()
		self.addCleanup(sso.stop)
		self.client = get_test_client()

	@classmethod
	def tearDownClass(cls):
		purge_test_users(cls.user)
		super().tearDownClass()

	def send(self, method: str, path: str, headers: dict | None = None, **kwargs):
		target = getattr(self.client, method)
		return make_request(target=target, args=(path,), kwargs={"headers": headers or {}, **kwargs})

	def identity(self, corporate_id: str = CORPORATE_ID) -> dict:
		return {EMAIL_HEADER: self.user, ACCESS_TOKEN_HEADER: corporate_token(corporate_id)}

	def test_get_creates_a_session_with_a_csrf_token(self):
		response = self.send("get", "/api/method/frappe.auth.get_logged_user", self.identity())

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json["message"], self.user)
		sid = self.client.get_cookie("sid").value
		frappe.db.rollback()
		session_data = json.loads(frappe.db.get_value("Sessions", {"sid": sid}, "sessiondata", order_by=None))
		self.assertTrue(session_data.get("csrf_token"))

	def test_unsafe_request_that_creates_the_session_fails_csrf(self):
		if frappe.conf.ignore_csrf:
			self.skipTest("ignore_csrf is set for this site")

		response = self.send("post", "/api/method/frappe.auth.get_logged_user", self.identity())

		self.assertEqual(response.status_code, 400)
		self.assertEqual(response.json["exc_type"], "CSRFTokenError")

	def test_refusal_page_explains_the_mpass_refusal(self):
		response = self.send("get", "/desk", {**self.identity("other"), "Accept": "text/html"})

		self.assertEqual(response.status_code, 403)
		self.assertIn("Your mPass identity is not allowed", response.get_data(as_text=True))

	def test_web_logout_redirects_to_the_portal(self):
		response = self.send("post", "/api/method/web_logout")

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.headers["Location"], PORTAL_URL)

	def test_guest_login_page_redirects_to_the_portal(self):
		response = self.send("get", "/login")

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.headers["Location"], PORTAL_URL)

	def test_local_credential_endpoints_are_refused(self):
		for method, path, payload in (
			("post", "/api/method/frappe.core.doctype.user.user.reset_password", {"user": self.user}),
			("post", "/api/method/frappe.core.doctype.user.user.update_password", {"new_password": "x"}),
			("post", "/api/method/frappe.www.login.send_login_link", {"email": self.user}),
			("get", "/api/method/frappe.www.login.login_via_key?key=x", None),
			("get", "/api/method/frappe.core.api.user_invitation.accept_invitation?key=x", None),
			("get", "/update-password", None),
		):
			with self.subTest(path=path):
				frappe.cache.delete_keys("rl:")
				response = self.send(method, path, json=payload)
				self.assertEqual(response.status_code, 403)
