# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE
"""mPass SSO through oauth2-proxy ForwardAuth identity headers.

The contract (env, headers, gated routes) is in doc/mpass_sso.md.
"""

import base64
import binascii
import hmac
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn
from urllib.parse import urlparse

import frappe
from frappe import _
from frappe.permissions import AUTOMATIC_ROLES
from frappe.sessions import delete_session

EMAIL_HEADER = "X-Auth-Request-Email"
ACCESS_TOKEN_HEADER = "X-Auth-Request-Access-Token"
EDGE_SECRET_HEADER = "X-Mpass-Edge-Secret"

MEMBER_ROLE = "mPass Member"
PRIVILEGED_ROLES = frozenset(("System Manager", *AUTOMATIC_ROLES))
MIN_EDGE_SECRET_LENGTH = 32
MAX_EMAIL_LENGTH = 140
BREAK_GLASS_USER = "Administrator"
LOGIN_RESPONSE_KEYS = ("message", "home_page", "full_name", "redirect_to", "session_expired")


class Outcome(StrEnum):
	KEEP = "keep"
	LOGIN = "login"
	UNRESOLVABLE = "unresolvable"
	CORPORATE = "corporate"
	RESERVED = "reserved"
	DISABLED = "disabled"
	ROLE = "role"
	CONFLICT = "conflict"


class MpassRefusalError(frappe.PermissionError):
	def __init__(self, reason: Outcome):
		super().__init__(_("Your mPass identity is not allowed to sign in to this site."))
		self.reason = reason


@dataclass(frozen=True)
class MpassSettings:
	auth_type: str = ""
	default_email_domain: str = ""
	corporate_id: str = ""
	allow_any_tenant: str = ""
	edge_secret: str = ""
	default_role: str = ""
	logout_redirect_url: str = ""

	@classmethod
	def from_env(cls, env: Mapping[str, str] | None = None) -> "MpassSettings":
		env = os.environ if env is None else env
		return cls(
			auth_type=env.get("AUTH_TYPE", "").strip(),
			default_email_domain=normalise(env.get("DEFAULT_EMAIL_DOMAIN")),
			corporate_id=env.get("SMB_CORPORATE_ID", "").strip(),
			allow_any_tenant=env.get("MPASS_ALLOW_ANY_TENANT", "").strip(),
			edge_secret=env.get("MPASS_EDGE_SECRET", "").strip(),
			default_role=env.get("MPASS_SSO_DEFAULT_ROLE", "").strip(),
			logout_redirect_url=env.get("LOGOUT_REDIRECT_URL", "").strip(),
		)

	@property
	def sso_enabled(self) -> bool:
		return self.auth_type == "SSO"


def sso_enabled(env: Mapping[str, str] | None = None) -> bool:
	return MpassSettings.from_env(env).sso_enabled


def normalise(value: str | None) -> str:
	return (value or "").strip().lower()


def is_email_shaped(value: str) -> bool:
	"""O(n) shape check, deliberately not a regex: a non-leading `@` and a `.` at least one
	character after it."""
	at = value.find("@")
	if at <= 0:
		return False
	return value.find(".", at + 2) != -1


def resolve_email(asserted: str, default_email_domain: str) -> str | None:
	"""The email an asserted identity stands for, or None when it cannot be resolved.
	A bare mPass id becomes `<id>@<DEFAULT_EMAIL_DOMAIN>`; the domain is never guessed."""
	if not asserted:
		return None

	if "@" in asserted:
		email = asserted if is_email_shaped(asserted) else None
	else:
		email = f"{asserted}@{default_email_domain}" if default_email_domain else None

	return email if email and len(email) <= MAX_EMAIL_LENGTH else None


def from_edge(presented: str | None, configured: str) -> bool:
	"""Whether the request came through the protected Traefik router. Without a configured secret
	that is assumed (topology trust); a configured secret shorter than the minimum trusts nothing."""
	if not configured:
		return True

	return len(configured) >= MIN_EDGE_SECRET_LENGTH and hmac.compare_digest(
		configured.encode(), (presented or "").encode()
	)


def asserted_identity(headers: Mapping[str, str], settings: MpassSettings) -> str:
	"""The normalised `X-Auth-Request-Email`, or "" when absent or not from the edge.
	Absence is never a logout signal."""
	if not from_edge(headers.get(EDGE_SECRET_HEADER), settings.edge_secret):
		return ""
	return normalise(headers.get(EMAIL_HEADER))


def decode_jwt_payload(token: str | None) -> dict | None:
	"""The access token's claims, decoded WITHOUT verification: oauth2-proxy has already
	validated the token it forwards."""
	parts = (token or "").strip().split(".")
	if len(parts) != 3 or not parts[1]:
		return None

	segment = parts[1] + "=" * (-len(parts[1]) % 4)
	try:
		claims = json.loads(base64.b64decode(segment, altchars=b"-_", validate=True))
	except (ValueError, binascii.Error):
		return None

	return claims if isinstance(claims, dict) else None


def corporate_ok(access_token: str | None, settings: MpassSettings) -> bool:
	"""Tenant binding. Fails closed: with SMB_CORPORATE_ID unset nobody is admitted unless the
	deployment opts in with MPASS_ALLOW_ANY_TENANT=1."""
	if not settings.corporate_id:
		return settings.allow_any_tenant == "1"

	claims = decode_jwt_payload(access_token) or {}
	return (
		claims.get("custom:is_corporate") == "true"
		and claims.get("custom:corporate_id") == settings.corporate_id
	)


def portal_url(value: str | None) -> str | None:
	value = (value or "").strip()
	parsed = urlparse(value)
	return value if parsed.scheme.lower() in ("http", "https") and parsed.hostname else None


def decide(
	email: str | None, session_user: str | None, impersonated_by: str | None, corporate_admitted: bool
) -> Outcome:
	"""The identity decision for one request that carries an asserted identity."""
	if email is None:
		return Outcome.UNRESOLVABLE
	if not corporate_admitted:
		return Outcome.CORPORATE
	if email in (normalise(session_user), normalise(impersonated_by)):
		return Outcome.KEEP
	return Outcome.LOGIN


def admissible_role(role: Mapping | None) -> bool:
	return bool(
		role
		and not role.get("disabled")
		and role.get("desk_access")
		and role.get("name") not in PRIVILEGED_ROLES
	)


def inspects_request(request) -> bool:
	"""Token-authenticated calls and CORS preflights are left to Frappe's own auth."""
	return bool(request) and request.method != "OPTIONS" and not request.headers.get("Authorization")


def logout_redirect_url(settings: MpassSettings | None = None) -> str | None:
	"""Where Logout sends the browser under SSO, or None to keep Frappe's behaviour."""
	settings = settings or MpassSettings.from_env()
	if not settings.sso_enabled:
		return None

	url = portal_url(settings.logout_redirect_url)
	if not url:
		frappe.logger("mpass_sso").warning("LOGOUT_REDIRECT_URL is not an absolute http(s) URL")
	return url


def allows_password_login(login_id: str | None, settings: MpassSettings | None = None) -> bool:
	"""Under SSO, `disable_user_pass_login` still admits the Administrator password: the
	break-glass account when mPass or the corporate binding is broken."""
	settings = settings or MpassSettings.from_env()
	return settings.sso_enabled and normalise(login_id) == normalise(BREAK_GLASS_USER)


def guard_local_credentials() -> None:
	"""Refuse a local-credential flow (password reset, email link, signup) under SSO."""
	if sso_enabled():
		frappe.throw(_("Sign-in to this site is managed by mPass."), frappe.PermissionError)


def apply_proxy_identity(login_manager, settings: MpassSettings | None = None) -> None:
	"""Bind the Frappe session to the identity oauth2-proxy asserts for this request."""
	settings = settings or MpassSettings.from_env()
	if not settings.sso_enabled or not inspects_request(frappe.request):
		return

	headers = frappe.request.headers
	asserted = asserted_identity(headers, settings)
	if not asserted:
		return

	email = resolve_email(asserted, settings.default_email_domain)
	outcome = decide(
		email,
		frappe.session.user,
		frappe.session.data.get("impersonated_by"),
		corporate_ok(headers.get(ACCESS_TOKEN_HEADER), settings),
	)
	if outcome is Outcome.KEEP:
		return
	if outcome is not Outcome.LOGIN:
		refuse(login_manager, outcome)

	try:
		user = resolve_or_provision_user(email, settings.default_role)
	except MpassRefusalError as refusal:
		refuse(login_manager, refusal.reason)

	switch_session(login_manager, user)


def resolve_or_provision_user(email: str, default_role: str = "") -> str:
	"""The enabled, non-standard user for `email`, created with the default role when absent.
	Existing users are never re-roled."""
	user = find_user(email) or provision_user(email, default_role)
	if user.name in frappe.STANDARD_USERS:
		raise MpassRefusalError(Outcome.RESERVED)
	if not user.enabled:
		raise MpassRefusalError(Outcome.DISABLED)
	return user.name


def find_user(email: str):
	"""Looked up by the `email` column, not the name, so the Administrator's address is found
	(and refused) instead of colliding on insert."""
	return frappe.db.get_value("User", {"email": email}, ["name", "enabled"], as_dict=True)


def provision_user(email: str, default_role: str):
	user = frappe.new_doc("User")
	user.update(
		{
			"email": email,
			"first_name": email.split("@", 1)[0],
			"enabled": 1,
			"send_welcome_email": 0,
		}
	)
	user.append("roles", {"role": member_role(default_role)})
	user.flags.ignore_permissions = True
	user.flags.no_welcome_mail = True

	try:
		user.insert()
	except (frappe.DuplicateEntryError, frappe.UniqueValidationError):
		frappe.db.rollback()
		existing = find_user(email)
		if not existing:
			raise MpassRefusalError(Outcome.CONFLICT)
		return existing

	return frappe._dict(name=user.name, enabled=user.enabled)


def member_role(configured: str) -> str:
	name = configured or MEMBER_ROLE
	if name == MEMBER_ROLE:
		ensure_member_role()

	role = frappe.db.get_value("Role", name, ["name", "disabled", "desk_access"], as_dict=True)
	if not admissible_role(role):
		raise MpassRefusalError(Outcome.ROLE)
	return role.name


def ensure_member_role() -> None:
	"""A desk-access role with no permissions: new users see the desk and nothing else until an
	admin grants them roles."""
	if frappe.db.exists("Role", MEMBER_ROLE):
		return

	frappe.get_doc({"doctype": "Role", "role_name": MEMBER_ROLE, "desk_access": 1, "is_custom": 1}).insert(
		ignore_permissions=True, ignore_if_duplicate=True
	)


def switch_session(login_manager, user: str) -> None:
	"""Log `user` in, ending a different user's session first. Upstream login_as callers always
	redirect afterwards; this request continues, so the login response keys are dropped."""
	if user == frappe.session.user:
		return
	if frappe.session.user != "Guest":
		end_session(login_manager, reason="mPass identity changed")

	login_manager.login_as(user)
	frappe.db.commit()

	for key in LOGIN_RESPONSE_KEYS:
		frappe.local.response.pop(key, None)


def end_session(login_manager, reason: str) -> None:
	"""Delete the session without `LoginManager.logout`, whose cookie deletions are flushed after
	the new session's cookies and would log the browser straight out again."""
	login_manager.run_trigger("on_logout")
	delete_session(frappe.session.sid, user=frappe.session.user, reason=reason)


def refuse(login_manager, reason: Outcome) -> NoReturn:
	frappe.logger("mpass_sso").warning(f"mPass SSO refused a request: {reason}")
	if frappe.session.user != "Guest":
		login_manager.logout()
		frappe.db.commit()

	frappe.flags.disable_traceback = True
	raise MpassRefusalError(reason)
