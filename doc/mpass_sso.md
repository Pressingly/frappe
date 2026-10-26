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
| `OPTIONS` | Nothing |
| An `Authorization` header and no resumed session (Guest) | Nothing: API key/secret, bearer and basic auth stay with Frappe's own `validate_auth` |
| An `Authorization` header on a request that resumed a cookie session | Evaluated like any other request: Frappe ignores a malformed header (`Authorization: x`) and keeps the cookie session, so the header must not shield that session from the checks below |
| `MPASS_EDGE_SECRET` is set and the request does not carry it | Nothing: the identity header is ignored and the current session is kept |
| `X-Auth-Request-Email` absent or blank | Nothing: absence is not a logout signal (internal traffic, and the socket.io server's calls, which never pass through the gate; see the bypass list) |
| Identity cannot be resolved (see Provisioning) | `403`, any non-Guest session ended |
| Corporate check fails (see Configuration) | `403`, any non-Guest session ended. Checked on every request, so a revoked binding takes effect without waiting for the session to expire |
| Identity equals the session user | Nothing |
| Identity equals the session's `impersonated_by` | Nothing: an admin impersonating someone keeps that session |
| Session is Guest | User resolved or created, then logged in (`LoginManager.login_as`), given a CSRF token and committed |
| Session belongs to someone else | That session is deleted (`on_logout` hooks run), then the new user is logged in as above |
| Resolved user is `Administrator` or `Guest`, or is disabled | `403`, any non-Guest session ended, no user created |

A refusal is a `frappe.PermissionError` subclass (`MpassRefusalError`, with a `reason`). The
browser gets Frappe's `403` page with "Your mPass identity is not allowed to sign in to this site."
(`handle_exception` shows the exception's `page_message`), and JSON callers a `403` body carrying
the same text in `_server_messages`. The reason is logged to the `mpass_sso` logger.

**CSRF on the request that creates the session.** Frappe skips its CSRF check while a session has
no token. A session this hook creates belongs to the request that triggered it, so it is given a
token at once: an unsafe request (`POST`, `PUT`, `PATCH`, `DELETE`) that arrives with only the
mPass cookie, for example a form posted from another subdomain of the platform domain where the
`SameSite=Lax` oauth2-proxy cookie is still sent, fails with `CSRFTokenError` instead of running.
The cost: a desk tab whose Frappe session expired gets a CSRF error on its next save and must
reload, rather than saving into the new session.

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
broken. Keep that password strong and out of day-to-day use.

The mPass header always wins: an Administrator session in a browser that carries an mPass
identity is logged out and replaced by that identity on the next request, like any other
session. The break-glass is therefore used without an identity header, in one of two ways:

- **Internal host.** From a container on the backend network, log in and reuse the `sid`
  cookie. Frappe resolves the site from the `Host` header, so send the site name in `Host` or
  `X-Frappe-Site-Name`:

  ```bash
  curl -c /tmp/admin.jar http://erpnext-backend:8000/api/method/login \
    -H 'X-Frappe-Site-Name: erp.example.com' \
    --data-urlencode usr=Administrator --data-urlencode pwd="$ADMIN_PASSWORD"
  curl -b /tmp/admin.jar http://erpnext-backend:8000/api/method/frappe.auth.get_logged_user \
    -H 'X-Frappe-Site-Name: erp.example.com'
  ```

- **bench console.** No HTTP and no password: `bench --site <site> console` on the backend
  container runs as Administrator, e.g. to grant a role
  (`frappe.get_doc("User", "<email>").add_roles("System Manager")`) or switch password login
  back on (`frappe.db.set_single_value("System Settings", "disable_user_pass_login", 0)`).

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
| `/socket.io/*` | Realtime websocket. The socket.io server authenticates by the `sid` cookie only, by calling Frappe over the internal network without identity headers, so realtime never passes the mPass gate or the corporate check. It relies on the Frappe session and its expiry: a refused or logged-out session blocks new realtime connections and subscriptions, but a socket that is already open keeps receiving events for the rooms it joined until it disconnects, and a user removed from the tenant keeps connecting until their Frappe session is next refused on a gated request or expires. See the session-expiry recommendation under Trade-offs |
| `/files/*` | Frappe's public files, public by upstream design (email images, print logos). Private files are `/private/files/*` and stay protected |
| `/favicon.ico`, `/robots.txt` | Static |

Keep `strip-auth-headers` on every router, bypass routers included.

## REST API

Under SSO the API is internal-only on the public host, the platform standard: `/api/*` is behind
`mpass-auth`. Token callers (an MCP server, integrations) use the internal network with an API
key and secret, which Frappe authenticates itself (the SSO hook leaves a request with an
`Authorization` header and no cookie session to Frappe's token auth). Frappe resolves the site from the `Host` header, so internal calls send
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
  in any 60-minute window (default 60, set in `site_config.json`). SSO provisions a user on each
  first login, so a first-day rollout to a larger team must raise it (for example
  `bench --site <site> set-config throttle_user_limit 500`), or every first login past the limit
  gets an error page until the window rolls over.
- **Administrator's email is locked out of SSO.** An mPass identity equal to the Administrator's
  email is refused rather than logged in as Administrator. Give Administrator an address no mPass
  user has.
- **No idle timeout of its own.** Frappe's session expiry still applies; once it lapses, the next
  request with an identity header starts a new session. Because realtime (`/socket.io`) is gated
  only by that session, keep System Settings `session_expiry` short under SSO (for example
  `06:00`, against the upstream default of `240:00` hours of inactivity). The next gated request
  creates a new session from the identity header, so the cost is small: an open desk tab whose
  session lapsed reloads once (see CSRF above).

## Tests

`frappe/tests/test_mpass_sso.py`:

- `TestMpassIdentityHelpers`: the pure helpers (settings, normalisation, email shape, bare-id
  resolution, edge secret, JWT payload decode, corporate check, portal URL, role admissibility)
  and the decision table.
- `TestMpassProxyLogin`: `apply_proxy_identity` against a site database (provisioning, CSRF token
  on new sessions, session switch, impersonation, refusals, `Authorization` with a cookie
  session, edge secret).
- `TestMpassBreakGlass`: the Administrator password exemption and the System Settings validation.
- `TestMpassHTTPRequest`: whole requests through `frappe.app.application` (session creation with a
  CSRF token, CSRF failure on the creating `POST`, the refusal page, `web_logout`, `/login` as
  Guest, the gated credential endpoints).

The database and HTTP classes need a bench site and clean up the users, sessions and role they
commit: `bench --site <site> run-tests --module frappe.tests.test_mpass_sso`.
