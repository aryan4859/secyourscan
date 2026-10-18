# Security Model

What SecYourScan defends against, how, and what it does not defend against.

## Threat model

A SecYourScan instance holds breach material that mentions your organisation —
credentials, internal hostnames, personal data of your staff and customers —
with the unmasked originals in object storage. The assets worth protecting, in
order:

1. **The raw evidence.** It is a concentrated copy of what an attacker would
   otherwise have to assemble.
2. **Tenant isolation.** One tenant reaching another's leaks or watchlist.
3. **The audit trail.** If it can be altered silently, nothing else it says is
   evidence.
4. **The outbound connections.** Tor, Telegram, GitHub, HIBP, mempool.space,
   ThreatFox, Shodan InternetDB, bulk-ingest URLs, the SOAR webhook and the
   model server all reach the network from inside your perimeter.

Assumed adversaries:

- an authenticated analyst or tenant admin escalating beyond their tenant or role;
- an unauthenticated caller who can reach the web port;
- a holder of a leaked API key;
- hostile ingested content: prompt injection aimed at the Co-Analyst,
  spreadsheet formulas aimed at whoever opens an export, markup aimed at the UI.

Explicitly **not** in the model: a compromised host, a malicious
administrator, and denial of service by volume.

Scope is part of the security model too. SecYourScan has no identity hub, no
person profiling and no identity correlation. It holds data about people only
incidentally, inside leaks that matched your assets, and offers no feature for
pivoting from one person to everything about them.

## Authentication

Three credentials are accepted (`backend/app/deps.py`), checked in this order:

1. `Authorization: Bearer <jwt>` — API clients.
2. `Authorization: Bearer sys_…` or `X-API-Key: sys_…` — an API key.
3. The `sys_access_token` cookie — the browser.

### JWTs

Ed25519-signed (`EdDSA`), minted by `security.create_access_token`, verified by
the single function `security.decode_access_token`. Claims:

| Claim | Value |
|---|---|
| `iss` | `JWT_ISSUER` |
| `aud` | `JWT_AUDIENCE` |
| `sub` | user id |
| `tid` | tenant id |
| `role` | `admin` or `analyst` |
| `iat`, `nbf` | issue time |
| `exp` | issue time + `ACCESS_TOKEN_EXPIRE_MINUTES` |
| `jti` | random UUID |

On decode, only `EdDSA` is accepted; `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`
and `jti` are **required**; `iss` and `aud` must match the configured values;
and `JWT_LEEWAY_SECONDS` (30) absorbs clock skew.

**Role and tenant come from the database, not the token.** After verifying the
signature, the user row is loaded; a disabled user is rejected, and the
principal takes `role` and `tenant_id` from the row. The `tid` and `role`
claims are informational. A demotion or deactivation therefore takes effect on
the next request, not when the token expires.

**Revocation.** `POST /auth/logout` writes the token's `jti` to
`revoked_tokens` with the token's expiry; every authenticated request checks
it. Beat purges expired entries hourly. Logout does not revoke a user's
*other* tokens; disabling the user does.

**Keys.** `JWT_PRIVATE_KEY` is required when `ENV=production`, and must be an
Ed25519 key. In development an ephemeral key is generated with a warning. Each
process generates its own, so an unkeyed development setup with several
uvicorn workers will reject tokens minted by a sibling.

### Cookies and CSRF

Login sets two cookies, both `SameSite=Strict`, `Path=/`, `Secure` when
`COOKIE_SECURE=true`, with `max-age` equal to the token lifetime:

| Cookie | `httpOnly` | Content |
|---|---|---|
| `sys_access_token` | yes | the JWT |
| `sys_csrf` | **no**, deliberately | a random 32-byte token |

This is the **double-submit cookie** pattern. The SPA reads `sys_csrf` and
echoes it in an `X-SYS-CSRF` header on every request that is not `GET`, `HEAD`
or `OPTIONS`; the API compares header and cookie with `hmac.compare_digest`
and answers `403 CSRF token missing or invalid` on a mismatch. An attacker's
page can cause a cross-site request but cannot read the victim's cookies to
learn the token.

The check applies only to cookie-authenticated requests. A request with an
`Authorization` or `X-API-Key` header supplies its credential explicitly and
has no browser-CSRF exposure, so it is not checked — and if both a header and
the cookie are present, the header wins. Verified by
`test_cookie_session_needs_csrf_for_writes`.

`SameSite=Strict` is a second, independent layer: the browser does not send the
session cookie on any cross-site request, including top-level navigation. The
bundled nginx serves SPA and API from one origin, which is what makes `Strict`
workable.

### API keys and scopes

`sys_` followed by 32 random bytes, URL-safe base64. Only the SHA-256 is stored;
the plaintext is returned once at creation. A key belongs to one tenant, acts
with role `analyst`, and holds a subset of four scopes:

| Scope | Grants |
|---|---|
| `ingest` | the webhook and bulk ingestion |
| `read` | reading leaks, watchlist, sources, runs, rules, notifications, plans, stats, exports, audit |
| `write` | triage, watchlist, sources, rules, notification ack, plans, AI chat |
| `recon` | `/recon/*` probes and running a source |

Regardless of scopes, an API key **cannot**: use any admin route
(`require_admin` rejects `via == "api_key"`), download raw evidence, or read or
change `/users/me`. JWT sessions hold all four scopes. Verified by
`test_api_key_is_limited_to_its_scopes`.

Keys are compared by looking up the SHA-256 of the presented value, an indexed
equality match rather than a constant-time comparison of secrets; with 256 bits
of randomness behind the hash there is nothing useful to learn from timing.

### Passwords

bcrypt with cost 12 (`security.hash_password`). bcrypt reads at most **72
bytes** and ignores the rest, which would make the tail of a long passphrase
meaningless. So a password whose UTF-8 encoding exceeds 72 bytes is first
replaced by the 64-character hex SHA-256 of the whole thing, and that is
bcrypted; shorter passwords are bcrypted as they are. Verification applies the
same rule.

Passwords set through the API must be 12–256 characters; `ADMIN_PASSWORD` must
be at least 12 or the API refuses to start on an empty database. There is no
default password.

A login for an unknown email runs a bcrypt check against a dummy hash, so it
costs the same as a wrong password and the response time does not reveal
whether the account exists. Both outcomes return the same `401 Incorrect email
or password` and are audited as `LOGIN_FAILED`. Verified by
`test_login_success_and_failure_are_audited`.

### Rate limiting

`slowapi`, keyed by client IP, **in memory, per process**: `POST /auth/login`
10 per minute, `POST /leaks/ingest/webhook` 60 per minute. No other route is
limited. Exceeding a limit answers `429`.

## Authorization and tenancy

Two roles, plus one flag:

| Who | Can |
|---|---|
| `analyst` | every route that is not admin-only, within their tenant |
| `admin` | additionally manage users and API keys **of their own tenant** |
| platform admin (`is_platform_admin`) | additionally list, create and delete tenants |

`is_platform_admin` is a column on `users`. It is set only on the admin that
bootstrap creates from `ADMIN_EMAIL`; there is no API to grant it, so a second
platform admin needs a database update. Tenant routes go through
`require_platform_admin`, which first requires a non-API-key admin session and
then the flag; a tenant admin gets `403 Platform admin only`. `/users/me` and
the user objects returned by `/users` include `is_platform_admin`, and the web
app shows its Tenants tab only when it is true. Verified by
`test_only_the_platform_admin_manages_tenants`. Admin routes reject API keys.

Every row that holds monitoring data carries `tenant_id`, and every query
filters on the **caller's** tenant, taken from the database user (or the API
key's row), never from anything in the request. A record of another tenant is
answered with `404`, not `403`, so its existence is not disclosed. Elasticsearch
queries carry a tenant `term` filter and their hits are re-checked against
PostgreSQL. Object storage uses a bucket per tenant. YARA results are filtered
by namespace. The Co-Analyst's tools and the MCP server go through the same
scoping.

Verified by `test_tenants_cannot_see_each_others_data` (leak by id, list,
search, watchlist, status change), `test_custom_yara_rule_applies_only_to_its_tenant`
and `test_every_route_requires_auth_except_the_open_ones`.

::: info History
Tenant administration used to require only `role == admin`, so the admin of
any tenant could list every tenant and delete any tenant but their own. The
platform-admin flag closed that.
:::

The platform admin is, by design, the one account that crosses tenants: it can
see every tenant's name and delete any tenant other than its own. It does not
read other tenants' leaks through the API — data routes are still scoped to its
own tenant.

## Data handling

- **Masking before storage.** Passwords in credential lines and `key=value`
  pairs, Luhn-valid card numbers and PEM private keys are masked in everything
  stored in PostgreSQL, indexed in Elasticsearch, returned by the API, put in
  exports, sent to the model or posted to the SOAR webhook. See
  [Masking](/guide/pipeline#masking) for exactly what is recognised.
- **Raw evidence** exists only in MinIO. `GET /leaks/{id}/evidence` returns it
  as `text/plain` with `Content-Disposition: attachment`, `nosniff` and
  `Cache-Control: no-store`, only to a user session (not an API key), and every
  download is audited as `VIEW_EVIDENCE`.
- **Serializers are explicit.** `routers/serializers.py` lists every field
  returned; a new column is not exposed by accident. Password hashes and key
  hashes are never serialised.
- **Error bodies do not echo input.** Webhook validation errors omit the input;
  `/system/health` omits hostnames and exception text.

## HTTP hardening

The API sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer` and `Content-Security-Policy: default-src
'none'; frame-ancestors 'none'` on its responses. `TrustedHostMiddleware`
enforces `ALLOWED_HOSTS`. In production the OpenAPI schema and interactive
docs are not served. The bundled nginx adds its own CSP for the SPA
(`default-src 'self'`, no inline scripts).

## Container hardening

From `docker-compose.yml` and the Dockerfiles:

| Control | api, workers, beat | web | Tor | Datastores |
|---|---|---|---|---|
| Non-root user | uid 10001 | nginx-unprivileged | `tor` | image default |
| `cap_drop: ALL` | yes | — | — | — |
| `no-new-privileges` | yes | — | — | — |
| Read-only root filesystem | yes, `tmpfs` on `/tmp` | — | — | — |
| Published ports | none | `127.0.0.1:8080` | none | RabbitMQ UI on `127.0.0.1:15672` only |

The datastores, web and Tor containers do not have the `cap_drop` and
read-only settings the application containers have.

## AI-specific risk

The Co-Analyst and the per-leak triage both read attacker-supplied text.
Mitigations: a fixed tool allow-list with no destructive operation, tenant
scoping in the dispatcher, fenced tool results, a system prompt naming them as
hostile, and triage that can only raise a score and cannot trigger anything by
itself. The full account, and what remains, is on
[AI Co-Analyst](/guide/ai-coanalyst). Treat model output as a lead, not a
finding.

## Known gaps

Stated plainly, because a security page that lists only strengths is marketing.

### Tenancy and authorization

- **One platform admin, granted by the database.** Only the bootstrap admin has
  `is_platform_admin`, and there is no API to grant or revoke it. Losing that
  account means editing the `users` table.
- **Email addresses are unique across all tenants**, so creating a user whose
  email exists in another tenant answers `409` and discloses that it exists.
- **Global YARA rules are visible to every tenant**, including their source,
  and cannot be created or deleted through the API.

### Server-side requests

- **The URL check is made at resolution time.** `recon.ensure_public_url`
  resolves the host and refuses non-global addresses, and the fetch then
  resolves it again. A hostname whose DNS answer changes between the two (DNS
  rebinding) can still reach an internal address. Restricting the workers'
  egress at the network level closes this; the code does not.

### Integrity and availability

- **No migrations.** The schema is created with `Base.metadata.create_all`,
  which never alters an existing table. Upgrades that change the schema need
  manual SQL.
- **Rate limiting is per process and in memory.** Behind several API replicas
  the effective limit multiplies; a restart resets it. Put a shared limit at
  the reverse proxy.
- **The SimHash near-duplicate check is O(n) per tenant.** Every new leak loads
  every fingerprint in its tenant. Fine for thousands, slow for millions.
- **A near-duplicate re-match is partial.** It adds watch matches and can raise
  severity, but runs no AI triage, fires no SOAR webhook and keeps the first
  version's snippet and evidence. See
  [Deduplication](/guide/pipeline#_2-deduplication).
- **Deleting the newest audit rows is not detectable** by the chain, which
  proves order, not count. See [The chain](/guide/reporting#the-chain).
- **The tenant-less audit chain cannot be verified through the API.** Failed
  logins for unknown emails and `DELETE_TENANT_COMPLETED` have no tenant, and
  `/system/audit/verify` checks only the caller's.
- **Audit writes are serialised only on PostgreSQL.** On SQLite (development and
  tests) concurrent writes can still produce a spurious `link` break.
- **Not everything is audited.** The Co-Analyst's read tools and `create_task`,
  plan and task changes, and notification acknowledgements leave no audit
  entry.
- **The audit chain detects tampering; it does not prevent it.** Anyone with
  database write access can rewrite it wholesale.
- **The SOAR webhook is synchronous, unsigned and not retried.** The worker
  waits up to three seconds per qualifying leak, sends no signature, and drops
  the alert if the receiver is down.
- **uvicorn trusts `X-Forwarded-For` from any peer** (`--forwarded-allow-ips *`).
  Safe only while nothing but the bundled nginx can reach the API port;
  otherwise client IPs in the audit log and the per-IP rate limits are
  spoofable.

### Data residency and third parties

- **`AI_ENDPOINT` can point at a hosted API.** It is a URL; nothing stops it.
  If it does, masked leak text leaves your infrastructure on every triage and
  every chat.
- **ThreatFox needs a key**, and without `THREATFOX_AUTH_KEY` IP enrichment
  silently does nothing.
- **CTI lookups disclose values** — wallet addresses to mempool.space, IPs to
  ThreatFox and InternetDB — over the clearnet. The mempool.space lookup has no
  switch.
- **Ahmia falls back to the clearnet** when `TOR_PROXY` is unset, rather than
  refusing.

### Correctness and loose ends

- **`GET /leaks/?watch_item_id=` is approximate.** It filters the newest
  `limit × 4` leaks (at most 2,000) in Python, and `total` ignores the filter.
  See [Watchlist](/guide/watchlist#listing-leaks-for-one-item).
- **`MAX_CONTENT_BYTES` slices characters, not bytes**, despite its name.
- **The Elasticsearch severity facet is hard-coded** at 80 / 60 / 30 and does
  not follow `CRITICAL_THRESHOLD`.
- **Unused declarations:** the `JWT_PUBLIC_KEY` and `PROJECT_NAME` settings are
  never read, and the `info` notification level is never written.

### Not present

- **No 2FA or SSO.** Password plus JWT is the whole of authentication.
- **No field-level encryption.** Data at rest is protected only by whatever
  encrypts the volumes.
- **No screenshots.** naso captures page screenshots of crawled sites and its
  docs show the UI; SecYourScan stores page text only, and these docs have no
  screenshots.
- **No notification delivery** beyond the SOAR webhook: no email, no chat.

## Server-side request protection

A bulk-ingest `url` and a `feed` source's target are fetched by a worker, so
they are checked by `recon.ensure_public_url` before anything is fetched:

- the scheme must be `http` or `https` and there must be a host;
- the host is resolved, and **every** address it resolves to must be global —
  loopback, RFC 1918, link-local (including the `169.254.169.254` metadata
  address), CGNAT, reserved and multicast addresses are refused;
- `.onion` hosts are allowed without resolution, since they resolve only
  through Tor.

A refused URL answers `422` — when creating a feed source, when submitting a
bulk `url`, and again when the worker fetches it. Feed and bulk fetches do not
follow redirects, so a public URL cannot bounce the worker to an internal one.
Verified by `test_internal_urls_are_refused`.

::: info History
Earlier, both were fetched with no destination check and with redirects
followed: an `ingest`-scoped key could make a worker request
`http://elasticsearch:9200/…` or `http://minio:9000/…` and read the result
back as leaks.
:::

The remaining weakness, DNS rebinding, is listed under
[Known gaps](#server-side-requests).

## YARA rule compilation

Rules are compiled with `includes=False` everywhere — the static set, saved
rules and `POST /yara/test` — so a rule that uses `include "<path>"` fails to
compile and is refused with `422`. Before this, a rule author could make the API
process open arbitrary files while compiling. Verified by
`test_yara_include_is_rejected`.

## Operator checklist

Before pointing SecYourScan at real data:

1. Secrets from `scripts/gen_secrets.py`; `.env` and `secrets/` out of version
   control.
2. TLS in front of `web`, and `COOKIE_SECURE=true`.
3. `ALLOWED_HOSTS` and `CORS_ORIGINS` set to the real hostname and origin.
4. `ENV=production`.
5. The bootstrap admin (the only platform admin) kept for platform
   administration; day-to-day admins created per tenant.
6. API keys with the narrowest scopes; `ingest` only for scrapers.
7. `AI_ENDPOINT` pointing at a server you run.
8. The RabbitMQ management UI kept off untrusted networks.
9. Egress from the worker containers restricted to what the collectors need,
   if you can, as a second layer behind the URL check.
10. The legal note on [Dark Web Recon](/guide/dark-recon#legal-and-ethical-use)
    read and acted on. The database contains personal data, and that has
    consequences independent of how well it is secured.
