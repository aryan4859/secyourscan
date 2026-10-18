# Operator Runbook

Failure modes, what they look like from outside, and how to resolve them.

## First moves

```bash
docker compose ps                               # what is running, what is restarting
curl -s localhost:8080/system/health            # which backing service disagrees
docker compose logs --tail=80 api
docker compose logs --tail=80 worker-pipeline
```

`/system/health` probes the database, Elasticsearch, object storage and the
broker individually, and names the ones that are `degraded`. Start there rather
than in the logs. Remember that `ai` and `tor` in that response reflect
configuration only; they are not probed.

::: tip `docker compose logs` takes service names
`api`, `worker-pipeline`, `worker-massive`, `beat`, `db`, `tor-lb` — as written
in `docker-compose.yml`.
:::

::: warning Never gate on `/system/status`'s HTTP code
It answers `200` even when the database is unreachable. Parse the body for
`"operational"`, or use `/system/health`, which answers `503`.
:::

---

## The API will not start

**`RuntimeError: JWT_PRIVATE_KEY is required in production`.** `ENV=production`
with no key. With Compose, check that `secrets/jwt_private_key.pem` exists —
`scripts/gen_secrets.py` creates it — and that the `secrets:` mount is intact.

**`ValueError: key is neither a PEM string nor a readable file path`.** The
value starts with neither `-----BEGIN` nor names an existing file. A PEM pasted
into `.env` without its line breaks is the usual cause; mount it as a file
instead.

**`JWT_PRIVATE_KEY must be an Ed25519 key`.** An RSA or EC key. Generate an
Ed25519 one.

**`RuntimeError: ADMIN_PASSWORD must be at least 12 characters`.** Only raised on
an empty database. Lengthen it.

**Settings fail to parse, e.g. `COOKIE_SECURE` "input should be a valid
boolean".** A comment on the same line as a value, as in
`COOKIE_SECURE=false   # true once…`. Current Compose strips it; an older
`docker-compose` passes it through literally. Put comments on their own lines.
(`.env.example` used to have such comments; it no longer does, but an `.env`
generated from the old template still may.)

## Nobody can sign in

**The log says `No users and no ADMIN_EMAIL/ADMIN_PASSWORD set`.** Bootstrap
ran on an empty database without them. Set both and restart the API.

**You changed `ADMIN_PASSWORD` and the old one still works.** Bootstrap runs
only when the `users` table is empty; afterwards the variable is ignored.
Change the password through `PUT /users/me`, or as another admin.

**`429 Too Many Requests` on login.** Ten attempts per minute per client IP. If
every user hits it at once, the API is seeing one IP for everyone — a proxy in
front of `web` that does not set `X-Forwarded-For`.

**Sessions end on every restart.** No `JWT_PRIVATE_KEY` outside production, so
an ephemeral key is generated each start. Set one. The same cause makes
dossiers signed before the restart unverifiable.

**Random `401`s with several uvicorn workers in development.** Each process
generated its own ephemeral key. Set `JWT_PRIVATE_KEY`.

## The browser gets `403 CSRF token missing or invalid`

The request carried the session cookie but no matching `X-SYS-CSRF` header.
Causes: a client other than the SPA using cookie auth (use a Bearer token
instead); the SPA served from a different origin than the API, so it cannot read
`sys_csrf`; or the `sys_csrf` cookie was cleared while `sys_access_token`
survived. Signing in again resets both.

## `400 Invalid host header`

`ALLOWED_HOSTS` does not include the `Host` the request arrived with. Add your
hostname (comma-separated).

## A webhook returns `202` but no leak appears

The answer says `"mode": "queued"`: the message went to RabbitMQ and is waiting
for a worker on the `default` queue.

1. `docker compose ps worker-pipeline` — is it running?
2. `docker compose logs worker-pipeline` — is it consuming, or failing on each
   task? A database error is retried three times, 60 seconds apart, before the
   task is dropped.
3. The RabbitMQ UI at `http://127.0.0.1:15672` (user `sys`, password
   `RABBITMQ_PASS`) shows queue depth per queue.

If the leak was a duplicate, nothing new appears — the existing leak's
`seen_count` goes up. Search for it.

## Scheduled sources never run

- **No beat.** `docker compose ps beat`. Without it nothing is dispatched.
- **No broker.** In inline mode there is no scheduler at all; only
  `POST /sources/{id}/run` works.
- **Inactive source.** `is_active: false` sources are skipped.
- **Interval not elapsed.** Beat checks every five minutes against
  `last_run_at` + `interval_minutes`.

Then look at `GET /sources/runs` — a source that runs and fails shows up there
with `status: error`, not as a missing run.

## A source run fails

Read the run's `error`:

| Message | Fix |
|---|---|
| `TOR_PROXY is not configured` | onion crawls and `.onion` feeds need Tor; set `TOR_PROXY` |
| `the crawler only fetches .onion hosts` | the target is not an onion URL |
| `GITHUB_TOKEN is not configured` / `HIBP_API_KEY is not configured` | set the key, or delete the source |
| `GitHub answered 403: …` | token lacks access or hit GitHub's rate limit |
| `HIBP answered 401` / `429` | bad key / over HIBP's rate limit for your plan |
| `Ahmia answered 403` / `429` / `503` | Ahmia is refusing; try later, or check the Tor pool |
| `t.me answered …` | channel does not exist or is not public |
| `invalid Telegram channel username` | 4–32 characters, letters, digits, underscore, starting with a letter |
| `query must be 2-128 characters after sanitising` | the watch value contains mostly characters the sanitiser strips |
| `URL resolves to a non-public address` (feed) | the feed host resolves to an internal address now, though it did not when the source was created |

**Ahmia runs succeed with zero results.** Check `via_tor` on the run. If Tor is
working, Ahmia's HTML has probably changed and the selectors in
`recon.ahmia_search` no longer match.

**Tor seems dead.** `docker compose logs tor-lb` shows HAProxy marking replicas
up or down; `docker compose logs tor` shows bootstrap progress. A fresh Tor
container can take a minute or more to build circuits.

## Search reports `"engine": "sql"`

Either Elasticsearch is not configured — both `ES_URL` and `ES_PASSWORD` are
needed — or a query failed and the API fell back. Check `/system/health`:
`elasticsearch: degraded`, or `circuits.elasticsearch: open` (five consecutive
failures; it retries after 60 seconds). The API log has
`ES search failed, falling back to SQL: …` with the reason.

Leaks processed while Elasticsearch was down are **not** indexed later, so they
remain findable only through the SQL fallback, on their first 4,000 masked
characters.

## Evidence download fails

| Response | Meaning |
|---|---|
| `404 No raw evidence stored for this leak` | MinIO was off or failing when the leak was processed. It cannot be recovered |
| `503 Object storage unavailable` | MinIO is not configured now |
| `403 Evidence download requires an analyst session` | you used an API key; sign in as a user |
| `500` | MinIO is configured but the read failed; see the API log |

## `403 Platform admin only`

Tenant management (`/tenants`) is reserved for the platform admin — the admin
created at bootstrap from `ADMIN_EMAIL`. A tenant admin cannot list, create or
delete tenants, and the web app hides the Tenants tab from them. There is no API
to make another user a platform admin; it takes
`UPDATE users SET is_platform_admin = true WHERE email = '…'`.

## Bulk ingestion problems

| Symptom | Cause |
|---|---|
| `503 File uploads need object storage` | MinIO is not configured; send a `url` instead |
| `422 Send exactly one of 'file' or 'url'` | both or neither were sent |
| `413` from nginx | the upload exceeds 512 MiB; send a `url` |
| `422 URL resolves to a non-public address` / `host does not resolve` | the `url` points at an internal or unresolvable host; it must be public |
| Memory grows during a large upload | the request body is spooled to `/tmp`, a `tmpfs` in Compose; send a `url` instead |
| Run ends `error` with `SoftTimeLimitExceeded` after about six hours | the bulk task's soft limit; split the dump |
| Run ends `truncated`, error `stopped after 2000 chunks` | the 2,000-chunk cap (1,000,000 matching lines); split the dump or narrow the watchlist |
| Run ends `ok` with `new_leaks: 0` | no line matched the pre-filter (check the watchlist), or every chunk was a duplicate |

## A new YARA rule does not match

- In a worker, rules are reloaded at most every 60 seconds. Wait a minute.
- Test it first with `POST /yara/test` (`{"content": "<rule>", "sample": "<text>"}`).
- If **no** custom rules match anywhere, the combined ruleset failed to compile
  and the analyzer fell back to the static rules. The worker log has
  `YARA compile failed (…); falling back to static rules`.

## The Co-Analyst fails

**`error` event: `AI engine unavailable: …`** (followed by `done`). The model server is unreachable,
returned an error, or the `ai` breaker is open (three consecutive failures,
then 120 seconds). `GET /ai/health` probes it. From inside a container,
`localhost` is the container: use `host.docker.internal` for a server on the
host, or `ollama` for the Compose service.

**It answers without looking at any data.** The model does not support tool
calling, or ignores it. Use a model that does.

**`Stopped after the maximum number of tool iterations`.** Five model turns by
default (`AI_MAX_ITERATIONS`). Ask a narrower question or raise the setting.

**`dark_web_probe` returns `"mode": "skipped"`.** Inline mode; there is no broker
to queue the probe on.

**Triage is slow and the queue backs up.** Each new leak waits for one
completion of up to `AI_TIMEOUT_SECONDS` (90). A small model on a CPU is often
the bottleneck of the whole pipeline. Use a faster model or unset
`AI_ENDPOINT`.

## `GET /system/audit/verify` reports a break

`reason: content` means a row's fields no longer match its hash: it was edited.
`reason: link` means its `prev_hash` does not match the row before: a row was
deleted or inserted. On PostgreSQL, audit writes are serialised per tenant, so a
link break is not explained by concurrency. On SQLite it can be: compare the
`timestamp` of `broken_at` and the row before it; milliseconds apart with the
same `prev_hash` points at two concurrent writes, not tampering. Export the chain with `GET /system/audit/export.csv` before
investigating further.

## Regenerating `.env` on a stack that has run

`scripts/gen_secrets.py` refuses to overwrite `.env`. If you delete it and run
it again, you get **new** database, broker, Elasticsearch and MinIO passwords —
but each datastore keeps the credentials it was initialised with in its volume.
Postgres in particular reads `POSTGRES_PASSWORD` only on first start. The API
then cannot connect, and `/system/status` says `degraded`.

```bash
# A. keep the data: give Postgres the new password
docker compose exec db psql -U sys -d secyourscan \
  -c "ALTER ROLE sys WITH PASSWORD '<POSTGRES_PASSWORD from the new .env>'"
docker compose restart api worker-pipeline worker-massive beat

# B. start clean: discard every volume
docker compose down -v
docker compose up -d
```

RabbitMQ, Elasticsearch and MinIO have the same property for their volumes; for
them, option B or restoring the old values is simpler. The script also generates
a new JWT key if you delete it, which ends every session and makes past dossiers
unverifiable — keep the old public key.

## After an upgrade, queries fail with "no such column"

There are no migrations. `create_all` creates missing tables and leaves existing
ones as they are, so a column added in a release does not exist in your
database. Add it with `ALTER TABLE`, matching the model in
`backend/app/models.py`.
