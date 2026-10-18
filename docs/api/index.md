# API Reference

The SecYourScan API is FastAPI, JSON in and out, version `0.2.0`. The tables
below are generated from `openapi.json` at the repository root — 59 operations
under ten tags — with the authorisation requirement of each read from the
code, since the schema does not record scopes.

**Base URL.** With the bundled Compose stack the API is reached through the web
container: `http://localhost:8080`, with every route at the root (`/leaks/…`,
not `/api/leaks/…`). Running uvicorn directly, it is `http://localhost:8000`.

**Interactive docs.** `/api/docs` (Swagger UI), `/api/redoc` and
`/api/openapi.json` are served only when `ENV` is not `production`.

## Authentication

Four routes answer without credentials, and no others:

| Route | Why it is open |
|---|---|
| `POST /auth/login` | how a client gets a session; rate-limited to 10 per minute per IP |
| `POST /auth/logout` | revokes the presented token if there is one and clears the cookies either way; an anonymous caller gets `200` and nothing else |
| `GET /system/status` | for orchestrators and load balancers, which hold no credentials; reveals only "operational" or "degraded" and a latency |
| `GET /system/health` | the same; component states without hostnames or errors |

The other 55 operations require authentication. This is tested, not claimed
from inspection: `test_every_route_requires_auth_except_the_open_ones` walks the
OpenAPI schema and calls every operation anonymously, failing if anything
outside this table answers with anything but `401` or `403` — so a route that
validated its input before authorising (`422`) would fail it too.

### Signing in

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=you@yourcompany.com&password=$PASSWORD"
```

```json
{"access_token": "eyJhbGciOiJFZERTQSIs…", "token_type": "bearer", "expires_in": 3600}
```

The response also sets the `sys_access_token` (httpOnly) and `sys_csrf`
cookies for the browser.

### Presenting credentials

| How | For | Extra requirement |
|---|---|---|
| `Authorization: Bearer <jwt>` | API clients | none |
| `Authorization: Bearer sys_…` or `X-API-Key: sys_…` | scrapers, the MCP server, automation | the key's scopes |
| `sys_access_token` cookie | the browser | non-`GET` requests must send `X-SYS-CSRF` equal to the `sys_csrf` cookie |

Details: [Security Model](/guide/security#authentication).

### Reading the "Auth" column

| Value | Meaning |
|---|---|
| open | no credentials |
| any | any valid JWT, cookie session or API key |
| session | a user (JWT or cookie); **API keys are refused** with `403` |
| admin | a user with role `admin`, acting on their own tenant; API keys refused |
| platform | an admin with `is_platform_admin` (the bootstrap admin); tenant admins get `403` |
| `ingest`, `read`, `write`, `recon` | that scope. User sessions hold all four; API keys hold what they were created with |

Errors: `401` missing, invalid, expired or revoked credentials; `403` wrong
role, missing scope, or failed CSRF check; `404` for a record in another tenant
(never `403`, so existence is not disclosed); `422` validation; `429` rate
limit.

## auth

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/login` | open | Form fields `username` (email), `password`. Returns the token and sets cookies. Audited `LOGIN` / `LOGIN_FAILED`. 10/min per IP |
| `POST` | `/auth/logout` | open | Revokes the bearer or cookie token's `jti`, clears cookies. Audited `LOGOUT` when a token was revoked |

## users

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/users/me` | session | Own profile, including `is_platform_admin`, plus `tenant_name` |
| `PUT` | `/users/me` | session | `{full_name?, current_password?, new_password?}`; a new password (12–256) requires the current one. Audited `UPDATE_PROFILE` |
| `GET` | `/users` | admin | Users of the caller's tenant |
| `POST` | `/users` | admin | `{email, password, full_name?, role: admin \| analyst}` → `201`; `409` if the email exists in any tenant. Audited `CREATE_USER` |
| `PATCH` | `/users/{user_id}` | admin | `{role?, is_active?}`; you cannot demote or disable yourself. Audited `UPDATE_USER` |
| `GET` | `/tenants` | platform | All tenants, with `is_current` |
| `POST` | `/tenants` | platform | `{name, admin_email, admin_password}` → `201`, creates the tenant and its first (tenant) admin. Audited `CREATE_TENANT` |
| `DELETE` | `/tenants/{tenant_id}` | platform | Any tenant except your own → `202`, runs the deletion saga. Audited `DELETE_TENANT_TRIGGERED` |
| `GET` | `/api-keys` | admin | Keys of the caller's tenant (never the plaintext) |
| `POST` | `/api-keys` | admin | `{name, scopes: [ingest \| read \| write \| recon]}` (default `["ingest"]`) → `201` with the plaintext `key`, shown once. Audited `CREATE_API_KEY` |
| `DELETE` | `/api-keys/{key_id}` | admin | Revokes the key. Audited `REVOKE_API_KEY` |

## leaks

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/leaks/ingest/webhook` | `ingest` | `{content, source?, source_url?, title?, metadata?}`, ≤ 5 MiB → `202`. 60/min per IP. See [Ingestion](/guide/ingestion#webhook-post-leaks-ingest-webhook) |
| `POST` | `/leaks/ingest/bulk` | `ingest` | Multipart: exactly one of `file` or `url`, plus `source?` → `202` with `job_id`; `422` if `url` resolves to a non-public address. Audited `BULK_INGEST` |
| `GET` | `/leaks/` | `read` | Filters `source`, `status`, `min_severity`, `max_severity`, `watch_item_id`; `limit` ≤ 500, `offset`. Newest first |
| `GET` | `/leaks/search` | `read` | Full-text search: `q`, severity range, repeatable `source` and `status`, `category`, `limit` ≤ 100, `offset` ≤ 10,000. See [Search](/guide/search) |
| `GET` | `/leaks/stats` | `read` | `total`, `critical_open`, `by_source`, `by_status`, `by_category`, 30-day `timeline` |
| `GET` | `/leaks/export/dossier` | `read` | Signed PDF, `min_severity` (default 0), ≤ 5,000 rows; `404` if empty. Audited `GENERATE_DOSSIER` |
| `GET` | `/leaks/export/public-key` | any | The dossier verification key, PEM |
| `GET` | `/leaks/export/csv` | `read` | CSV, ≤ 50,000 rows, formulas neutralised. Audited `EXPORT_CSV` |
| `GET` | `/leaks/{leak_id}` | `read` | Full detail: masked snippet, entities, YARA matches, AI verdict, CTI, metadata |
| `GET` | `/leaks/{leak_id}/evidence` | session | The **unmasked** original as a text attachment; `404` if none stored. Audited `VIEW_EVIDENCE` |
| `PATCH` | `/leaks/{leak_id}/status` | `write` | `{status: new \| reviewing \| escalated \| resolved \| false_positive}`. Audited `UPDATE_LEAK_STATUS` |
| `POST` | `/leaks/{leak_id}/ack` | `write` | Sets `acknowledged_at`. Audited `ACKNOWLEDGE_LEAK` |
| `POST` | `/leaks/ack-all` | `write` | `?min_severity=80` → `{acknowledged: n}`. Audited `ACKNOWLEDGE_ALL_CRITICAL` |

## watchlist

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/watchlist` | `read` | All watch items, by type then value |
| `POST` | `/watchlist` | `write` | `{type: domain \| email \| keyword \| ip \| wallet, value, is_vip?}` → `201`; `409` if present. Audited `CREATE_WATCH_ITEM` |
| `PATCH` | `/watchlist/{item_id}` | `write` | `{is_vip?, is_active?}`. Audited `UPDATE_WATCH_ITEM` |
| `DELETE` | `/watchlist/{item_id}` | `write` | → `204`. Audited `DELETE_WATCH_ITEM` |

Matching rules: [Watchlist & Alerting](/guide/watchlist#matching-rules).

## sources

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/sources` | `read` | The tenant's sources |
| `POST` | `/sources` | `write` | `{kind: ahmia \| onion \| telegram \| feed \| github \| hibp, target?, interval_minutes? (15–10080), max_pages? (1–50)}` → `201`; `422` for a `feed` target that resolves to a non-public address. Audited `CREATE_SOURCE` |
| `PATCH` | `/sources/{source_id}` | `write` | `{is_active?, interval_minutes?, max_pages?}`. Audited `UPDATE_SOURCE` |
| `DELETE` | `/sources/{source_id}` | `write` | → `204`. Audited `DELETE_SOURCE` |
| `POST` | `/sources/{source_id}/run` | `recon` | Queue the source now → `202`. Audited `RUN_SOURCE` |
| `GET` | `/sources/runs` | `read` | Runs, newest first; `source_id?`, `limit` ≤ 200 |
| `GET` | `/sources/runs/{run_id}` | `read` | One run, including its `report` |

Source kinds and provenance: [Dark Web Recon](/guide/dark-recon#sources-and-scheduling).

## recon

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/recon/darkweb` | `recon` | `?q=` (2–128) → `202`, queues an Ahmia query. Audited `DARK_WEB_RECON` on queueing |
| `GET` | `/recon/telegram` | `recon` | `?channel=` (4–64) → `202`, queues a public-channel read. Audited `TELEGRAM_RECON` on queueing |
| `GET` | `/recon/shodan` | `recon` | `?ip=` public IPv4 → InternetDB result, synchronous; `422` for private/reserved, `502` if InternetDB fails. Audited `SHODAN_RECON` |

## yara

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/yara/rules` | `read` | The tenant's custom rules plus global ones, with source |
| `POST` | `/yara/rules` | `write` | `{name (identifier, ≤ 64), content (10–50,000)}` → `201`; `422` if it does not compile; `409` on a duplicate name. Audited `CREATE_YARA_RULE` |
| `DELETE` | `/yara/rules/{rule_id}` | `write` | Own tenant's rules only → `204`. Audited `DELETE_YARA_RULE` |
| `POST` | `/yara/test` | `read` | `{content, sample}` → `{valid, error, matches}`; compiles and runs without saving. Not audited |

The static rules shipped in `backend/app/rules/` are not listed by this API.

## notifications

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/notifications` | `read` | `?unacknowledged=true`, `limit` ≤ 200; newest first |
| `POST` | `/notifications/{notification_id}/ack` | `write` | Sets `acknowledged_at`. Not audited |

## ai

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/ai/health` | any | Probes the model server's `/models`: `online`, `offline` or `disabled` |
| `POST` | `/ai/chat` | `write` | `{messages: [{role: user \| assistant, content ≤ 8000}]}` (1–40) → `text/event-stream`. Audited `AI_CHAT`. See [AI Co-Analyst](/guide/ai-coanalyst#sse-events) |
| `GET` | `/ai/plans` | `read` | Plans with their tasks |
| `POST` | `/ai/plans` | `write` | `{title, description?}` → `201` |
| `PATCH` | `/ai/plans/{plan_id}` | `write` | `{title?, description?, status?: active \| closed}` |
| `DELETE` | `/ai/plans/{plan_id}` | `write` | → `204`, deletes the plan and its tasks |
| `POST` | `/ai/plans/{plan_id}/tasks` | `write` | `{title}` → `201`, returns the plan |
| `PATCH` | `/ai/plans/{plan_id}/tasks/{task_id}` | `write` | `{status: todo \| doing \| done}` |

Plan and task changes are not audited.

## system

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/system/status` | open | Database reachability; always `200`, read `status` |
| `GET` | `/system/health` | open | Component states; `503` if anything configured is down |
| `GET` | `/system/audit` | `read` | The tenant's audit rows, newest first; `limit` ≤ 200, `offset`, `action?` |
| `GET` | `/system/audit/verify` | `read` | Recomputes the tenant's hash chain → `{valid, checked, broken_at, reason}` |
| `GET` | `/system/audit/export.csv` | `read` | Whole chain as CSV, oldest first, with hashes |

Response shapes: [Reporting & Audit](/guide/reporting#health-endpoints).

## Common objects

### Leak (summary)

Returned by `/leaks/`, `/leaks/search` (with `score` and `highlights`) and the
triage endpoints:

```json
{
  "id": "…", "source": "paste", "source_url": "…", "title": "…",
  "snippet": "first 300 masked characters",
  "severity": 100, "category": "CREDENTIALS", "status": "new",
  "watch_matches": [{"id": "…", "type": "domain", "value": "acme.example.com", "vip": true, "hits": ["…"]}],
  "yara_rules": ["combo_list"],
  "email_count": 6, "credential_count": 6, "seen_count": 1,
  "discovered_at": "…", "last_seen_at": "…", "acknowledged_at": null,
  "has_evidence": true
}
```

`GET /leaks/{id}` adds the full masked `snippet` (≤ 4,000 characters),
`sha256`, `entities`, `yara_matches` (with namespace, tags, description,
category and score), `ai_analysis`, `cti` and `metadata`. Timestamps are ISO 8601
in UTC without a timezone suffix.

### Asynchronous results

Endpoints that hand work to a worker answer `202` with one of:

| `mode` | Meaning |
|---|---|
| `queued` | published to RabbitMQ; `task_id` is the Celery task id |
| `inline` | no broker; the work ran before the response and `result` holds its output |
| `inline-background` | no broker; the work runs after the response is sent |
| `skipped` | only from the Co-Analyst's `dark_web_probe` without a broker |
