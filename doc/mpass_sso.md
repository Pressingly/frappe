# mPass SSO (oauth2-proxy ForwardAuth)

How this fork authenticates on the Moneta FOSS platform, what a deployment has to provide,
and what Layer 2 needs to wire it into the bundle. Applies to every Frappe app on the site
(ERPNext included), since the integration lives in the framework.

Activated by `AUTH_TYPE=SSO`. Unset, every path below is inert and Frappe behaves like
upstream: password login, password reset, login links and signup work as shipped.

## How it works

Frappe never talks to the identity provider. Traefik asks oauth2-proxy (`mpass-auth`) whether
each request carries a valid mPass session; if not, the browser goes through the mPass QR login
and comes back. Requests that reach Frappe carry the user's identity in `X-Auth-Request-*`
headers.

```text
browser ──> traefik ──(ForwardAuth)──> oauth2-proxy ──> mpass-auth-proxy ──> Cognito
               │
               └─ request + X-Auth-Request-* ──> frappe (frappe/mpass_sso.py, from HTTPRequest)
```

`frappe.mpass_sso.apply_proxy_identity` runs on every request in `HTTPRequest.__init__`, right
after the session is resumed and before the language and CSRF checks.

## Decision table

Evaluated per request, in this order:

| Request | Result |
|---|---|
| `AUTH_TYPE` is not `SSO` | Nothing (upstream behaviour) |
| Session belongs to `Administrator` | Nothing: a break-glass session (see below) is never displaced by the browser's mPass identity |
| `OPTIONS`, or an `Authorization` header is present | Nothing: API key/secret, bearer and basic auth stay with Frappe's own `validate_auth` |
| `MPASS_EDGE_SECRET` is set and the request does not carry it | Nothing: the identity header is ignored and the current session is kept |
| `X-Auth-Request-Email` absent or blank | Nothing: absence is not a logout signal (internal traffic, the socket.io server's calls) |
| Identity cannot be resolved (see Provisioning) | `403`, any non-Guest session ended |
| Corporate check fails (see Configuration) | `403`, any non-Guest session ended. Checked on every request, so a revoked binding takes effect without waiting for the session to expire |
| Identity equals the session user | Nothing |
| Identity equals the session's `impersonated_by` | Nothing: an admin impersonating someone keeps that session |
| Session is Guest | User resolved or created, then logged in (`LoginManager.login_as`) and committed |
| Session belongs to someone else | That session is deleted (`on_logout` hooks run), then the new user is logged in |
| Resolved user is `Administrator` or `Guest`, or is disabled | `403`, any non-Guest session ended, no user created |

A refusal is a `frappe.PermissionError` subclass (`MpassRefusalError`, with a `reason`), so the
browser gets Frappe's `403` page and JSON callers a `403` body. The reason is logged to the
`mpass_sso` logger.

## Configuration

Read from the process environment on every request, never from `site_config.json`. The
variables must reach the gunicorn web workers.

| Variable | Required | Meaning |
|---|---|---|
| `AUTH_TYPE` | yes | `SSO` turns the integration on |
| `DEFAULT_EMAIL_DOMAIN` | yes | Domain for a bare mPass id (`<id>@<domain>`). Unset, every bare-id login is refused. Must match the other bundle apps. It marks an unverified synthetic address; never derive roles or tenancy from it |
| `LOGOUT_REDIRECT_URL` | yes | The portal Logout navigates to. Must be an absolute `http(s)` URL; otherwise it is logged and Logout falls back to `/login` |
| `SMB_CORPORATE_ID` | one of these two | Only principals whose access token has `custom:is_corporate` equal to the string `"true"` and this `custom:corporate_id` are admitted |
| `MPASS_ALLOW_ANY_TENANT` | | `1` admits every mPass principal when `SMB_CORPORATE_ID` is unset. See Trade-offs |
| `MPASS_SSO_DEFAULT_ROLE` | no | Role new SSO users get. Unset: `mPass Member`, created on first use. Must exist, be enabled, have desk access, and not be `System Manager` or an automatic role (`Administrator`, `All`, `Guest`, `Desk User`); otherwise the login is refused with `403` and no user is created |
| `MPASS_EDGE_SECRET` | no | Optional edge secret, at least 32 characters; see Header trust |

The access token (`X-Auth-Request-Access-Token`) is decoded without verification: oauth2-proxy
has already validated the token it forwards.

## Header trust

Header trust is topology-based, the same as every bundle app:

1. Frappe's port is never published; Traefik is the only way in.
2. Every Frappe router runs `strip-auth-headers` first, so a client cannot inject
   `X-Auth-Request-*`; on the protected router `mpass-auth` then sets the verified values.
3. oauth2-proxy validates the upstream session on every ForwardAuth call.

**Optional edge secret.** Topology trust does not cover another container on the same Docker
networks, which can reach gunicorn directly with any header. Setting `MPASS_EDGE_SECRET` closes
that: the protected router adds `X-Mpass-Edge-Secret` with the value, every other router strips a
client copy, and Frappe then reads identity headers only on a request carrying it (constant-time
compare). Unlike Mautic, a request without it is not refused: it simply carries no identity, and
whatever session cookie it has applies. A configured secret shorter than 32 characters trusts no
request. Frappe has no `phpinfo()`, but a System Manager can read the process environment through
the System Console, so the secret is only as private as admin access.

## Provisioning

- Identity is `X-Auth-Request-Email` only (`X-Auth-Request-User` is the Cognito `sub` and is never
  read), trimmed and lowercased. A value with an `@` (not first) and a `.` at least one character
  after it is used as is; a bare value becomes `<value>@${DEFAULT_EMAIL_DOMAIN}`. The check is
  `find`-based, never a regex. Longer than 140 characters is refused.
- Lookup is an exact match on the `User.email` column, not the user name. The Administrator's
  name is `Administrator` but its email is a real address; matching on email means an mPass
  identity equal to that address is refused, never logged in as Administrator.
- A new user is a System User with first name = the part of the email before `@` (the mPass id
  for a bare value), no password, `send_welcome_email = 0`, and the default role only. Names are
  set only at creation; users edit them in their settings.
- An existing user is never re-roled. Admins grant roles in the desk as usual.
- Concurrent first logins: a duplicate-entry failure rolls back and falls back to a read.
- Disabled users are refused.

## Local-credential surfaces under SSO

Refused with `403` ("Sign-in to this site is managed by mPass"):

- password reset (`frappe.core.doctype.user.user.reset_password`);
- password update (`frappe.core.doctype.user.user.update_password`) and the `/update-password`
  page;
- login by email link (`frappe.www.login.send_login_link`, `frappe.www.login.login_via_key`);
- signup (`frappe.website.utils.is_signup_disabled` is true under SSO, which also hides the
  signup form and blocks social-login signup).

`/login` never shows a form under SSO: a logged-in user is sent on as upstream does, and a Guest
(a request that reached `/login` without an identity header) is redirected to
`LOGOUT_REDIRECT_URL`, or gets a `403` when that is not set.

**Password login and the Administrator break-glass.** The provisioning step sets System Settings
`disable_user_pass_login = 1` (bundle side). Upstream, that setting can only be saved when a
Social Login Key, LDAP or login-by-email-link is enabled; under SSO that validation is skipped,
so the Setup Wizard and later admin edits of System Settings still save.

With the setting on, `/api/method/login` refuses every password login except one: under SSO the
login id `Administrator` (case-insensitive, not the Administrator's email) is still admitted, so
the Administrator password stays a break-glass for when mPass or the corporate binding is
broken. The `/login` form is never shown under SSO, so the break-glass is a direct
`POST /api/method/login` (`usr=Administrator`, `pwd=...`), through the public host (which needs an
mPass session) or the internal network. The resulting Administrator session is kept even when
the browser carries a different mPass identity, until it logs out or expires. Keep the
Administrator password strong and out of day-to-day use.

Not covered: a System Manager can still set another user's password from the User form
(`change_password`); with password login disabled that password cannot be used.

## Logout

Logout deletes the Frappe session and navigates to `LOGOUT_REDIRECT_URL`:

- desk: the boot carries `mpass_logout_url`, and `frappe.app.redirect_to_login` uses it after
  Logout (the session-expired dialog still goes to `/login`, which re-establishes the session from
  the header);
- website pages (`/logout`): `frappe.logout` uses the web boot's `mpass_logout_url`;
- `POST /api/method/web_logout` redirects there.

It does not end the mPass session: the next request with an identity header logs the user back
in. Ending everything is the portal's "Log out of all apps". A missing or non-`http(s)` URL is
logged and Logout falls back to `/login`.

## ForwardAuth bypass list

Recommended for the bundle routers. Everything not listed stays behind `mpass-auth`, including
`/api/*` and `/private/files/*`.

| Path | Why public |
|---|---|
| `/assets/*` | Static bundles, served before any session logic |
| `/socket.io/*` | Realtime websocket; the socket.io server authenticates by the `sid` cookie through Frappe, so a stale or missing session is simply anonymous |
| `/files/*` | Frappe's public files, public by upstream design (email images, print logos). Private files are `/private/files/*` and stay protected |
| `/favicon.ico`, `/robots.txt` | Static |

Keep `strip-auth-headers` on every router, bypass routers included.

## REST API

Under SSO the API is internal-only on the public host, the platform standard: `/api/*` is behind
`mpass-auth`. Token callers (an MCP server, integrations) use the internal network with an API
key and secret, which Frappe authenticates itself (the SSO hook skips any request with an
`Authorization` header). Frappe resolves the site from the `Host` header, so internal calls send
`Host: <site name>` or `X-Frappe-Site-Name: <site name>`:

```bash
curl http://erpnext-backend:8000/api/resource/Customer \
  -H 'X-Frappe-Site-Name: erp.example.com' -H 'Authorization: token <api_key>:<api_secret>'
```

## Trade-offs

- **Tenant binding fails closed.** With `SMB_CORPORATE_ID` unset every login is refused unless
  `MPASS_ALLOW_ANY_TENANT=1`, the same as Mautic. An empty variable silently admitting the whole
  Cognito pool is the easy mistake.
- **User creation is throttled.** Frappe refuses to create more than `throttle_user_limit` users
  per hour (default 60, `site_config.json`). A first-day rollout to a larger team must raise it,
  or the 61st first login gets an error page until the hour rolls over.
- **Administrator's email is locked out of SSO.** An mPass identity equal to the Administrator's
  email is refused rather than logged in as Administrator. Give Administrator an address no mPass
  user has.
- **No idle timeout of its own.** Frappe's session expiry still applies; once it lapses, the next
  request with an identity header starts a new session.

## Tests

`frappe/tests/test_mpass_sso.py`:

- `TestMpassIdentityHelpers`: the pure helpers (settings, normalisation, email shape, bare-id
  resolution, edge secret, JWT payload decode, corporate check, portal URL, role admissibility)
  and the decision table.
- `TestMpassProxyLogin`: `apply_proxy_identity` against a site database (provisioning, session
  switch, impersonation, refusals, edge secret). Needs a bench site:
  `bench --site <site> run-tests --module frappe.tests.test_mpass_sso`.
