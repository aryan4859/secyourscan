# Configuration

Every setting SecYourScan reads is a field on one pydantic-settings class,
`Settings` in `backend/app/config.py`. There is no second mechanism: if a value
is not on that class, nothing reads it. (The MCP server is a separate process
with its own two variables; see [MCP Server](/guide/mcp-integration).)

## Where values come from

```python
model_config = SettingsConfigDict(
    env_file=".env",
    extra="ignore",
    secrets_dir="/run/secrets" if os.path.isdir("/run/secrets") else None,
)
```

Highest priority first:

1. **Process environment variables** — what `docker-compose.yml` sets under
   `environment:` and loads from `env_file:`.
2. **`.env`** in the working directory. In the backend image the working
   directory is `/srv` and no `.env` is copied there, so in Compose this source
   is empty; it matters when you run `uvicorn` from `backend/` by hand.
3. **`/run/secrets/<FIELD_NAME>`**, one file per setting, read only if the
   directory exists. The file is named exactly after the field —
   `/run/secrets/JWT_PRIVATE_KEY`, not `jwt_private_key`. Compose mounts the
   signing key this way.

Variable names have **no prefix** — `DATABASE_URL`, not `SYS_DATABASE_URL`.
(The previous version of these docs said otherwise.) Because of
`extra="ignore"`, a misspelt variable is silently discarded.

**Optional services are switched off by leaving their credentials unset.**
`/system/health` then reports them `disabled` rather than broken. An empty
string counts as unset.

## Core

| Setting | Default | Notes |
|---|---|---|
| `ENV` | `development` | `production` disables `/api/docs`, `/api/redoc` and `/api/openapi.json`, and makes `JWT_PRIVATE_KEY` mandatory. `.env.example` sets `production`. |
| `PROJECT_NAME` | `SecYourScan` | declared; not currently read anywhere |

## Database

| Setting | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./secyourscan.db` | any SQLAlchemy async URL. Compose: `postgresql+asyncpg://sys:${POSTGRES_PASSWORD}@db:5432/secyourscan` |
| `DB_POOL_SIZE` | `20` | API pool size; workers use `NullPool` and ignore it |
| `DB_MAX_OVERFLOW` | `10` | API pool overflow |

SQLite is for tests and a laptop. It works, including for the pipeline, but the
SimHash scan and concurrent writers will find its limits quickly.

## Authentication

| Setting | Default | Notes |
|---|---|---|
| `JWT_PRIVATE_KEY` | unset | Ed25519 private key, as a PEM string **or** a path to a PEM file. Unset in development: an ephemeral key is generated at start, so sessions end on restart and dossier signatures stop verifying. Unset in production: the API refuses to start. |
| `JWT_PUBLIC_KEY` | unset | declared but **not read**; the public key is always derived from the private one |
| `JWT_ISSUER` | `secyourscan` | `iss` claim, checked on decode |
| `JWT_AUDIENCE` | `secyourscan-api` | `aud` claim, checked on decode |
| `JWT_LEEWAY_SECONDS` | `30` | clock-skew allowance on `exp`, `nbf`, `iat` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | token lifetime and cookie `max-age` |
| `COOKIE_SECURE` | `false` | set `true` whenever the site is served over HTTPS |
| `ADMIN_EMAIL` | unset | first admin, created only on an **empty** `users` table; the only platform admin |
| `ADMIN_PASSWORD` | unset | at least 12 characters, or the API refuses to start on an empty database |

Give each deployment its own `JWT_ISSUER`/`JWT_AUDIENCE` if more than one ever
shares a key.

## Network

| Setting | Default | Notes |
|---|---|---|
| `CORS_ORIGINS` | `http://localhost:5173` | comma-separated. `.env.example`: `http://localhost:8080`. With the bundled nginx the SPA and API share one origin, so CORS is not exercised |
| `ALLOWED_HOSTS` | `*` | comma-separated `Host` values accepted by `TrustedHostMiddleware`. Set it to your hostname in production |

## Broker

| Setting | Default | Notes |
|---|---|---|
| `RABBITMQ_URL` | unset | Compose: `amqp://sys:${RABBITMQ_PASS}@rabbitmq:5672/`. Unset = inline mode |
| `PIPELINE_INLINE` | `false` | `true` forces inline mode even with a broker configured |

Inline mode runs pipeline work inside the API process. It has no scheduler; see
[Degraded modes](/guide/architecture#degraded-modes).

## Elasticsearch

Enabled when **both** `ES_URL` and `ES_PASSWORD` are set.

| Setting | Default | Notes |
|---|---|---|
| `ES_URL` | unset | Compose: `http://elasticsearch:9200` |
| `ES_USER` | `elastic` | |
| `ES_PASSWORD` | unset | |
| `ES_VERIFY_CERTS` | `true` | applies only to `https://` URLs |
| `ES_INDEX` | `secyourscan-leaks` | created on first use |

## Object storage (MinIO / S3)

Enabled when `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY` and `MINIO_SECRET_KEY` are all
set.

| Setting | Default | Notes |
|---|---|---|
| `MINIO_ENDPOINT` | unset | `host:port`; a leading `http://` or `https://` is stripped. Compose: `minio:9000` |
| `MINIO_ACCESS_KEY` | unset | |
| `MINIO_SECRET_KEY` | unset | |
| `MINIO_SECURE` | `false` | TLS to the object store |

## Tor and crawling

| Setting | Default | Notes |
|---|---|---|
| `TOR_PROXY` | unset | e.g. `socks5h://tor-lb:9050` (Compose). Unset: Ahmia goes over the clearnet, onion crawling fails |
| `AHMIA_URL` | `https://ahmia.fi/search/` | the landing page is derived by replacing `/search/` with `/` |
| `CRAWL_MAX_PAGES` | `10` | onion crawler default page budget when a source does not set one; hard cap 50 |
| `CRAWL_MAX_BYTES` | `1048576` | bytes read per crawled page |

## AI

Enabled when `AI_ENDPOINT` is set.

| Setting | Default | Notes |
|---|---|---|
| `AI_ENDPOINT` | unset | base URL of an OpenAI-compatible API, ending in `/v1`. `/chat/completions` and `/models` are appended |
| `AI_MODEL` | `llama3.1:8b` | must support tool calling for the Co-Analyst to use its tools |
| `AI_API_KEY` | unset | sent as `Authorization: Bearer`. Only hosted APIs need it — and a hosted API means leak text leaves your infrastructure |
| `AI_TIMEOUT_SECONDS` | `90.0` | per completion |
| `AI_MAX_ITERATIONS` | `5` | Co-Analyst model turns per chat request |

## Integrations

| Setting | Default | Notes |
|---|---|---|
| `SOAR_WEBHOOK_URL` | unset | outbound alert webhook |
| `THREATFOX_AUTH_KEY` | unset | ThreatFox IP enrichment is skipped without it |
| `GITHUB_TOKEN` | unset | GitHub code search sources fail without it |
| `HIBP_API_KEY` | unset | HIBP sources fail without it |

## Scoring

| Setting | Default | Notes |
|---|---|---|
| `CRITICAL_THRESHOLD` | `80` | score at or above which a `critical` notification is raised; also the `critical_open` cut-off in `/leaks/stats` |
| `SOAR_THRESHOLD` | `90` | score at or above which the SOAR webhook fires |
| `NEAR_DUP_THRESHOLD` | `3` | maximum SimHash Hamming distance, in bits, for a near-duplicate. `0` = only identical fingerprints |

Changing a threshold affects leaks processed afterwards. Stored severities are
never recomputed.

## Signing

| Setting | Default | Notes |
|---|---|---|
| `DOSSIER_SIGNING_KEY` | unset | Ed25519 PEM string or path. Unset: the JWT private key signs dossiers |

## Constants that are not settings

Values you might expect to configure, and where they are fixed in code:

| Value | Where |
|---|---|
| Login rate limit `10/minute`, webhook `60/minute`, per client IP | `routers/auth.py`, `routers/leaks.py` |
| Webhook body limit 5 MiB; content truncated to 5 Mi characters | `routers/leaks.py`, `services/pipeline.py` |
| Snippet length 4,000 characters; triage input 3,000 | `services/pipeline.py`, `services/triage.py` |
| YARA reload interval 60 s; match timeout 30 s; scan size 8 MiB | `services/pipeline.py`, `services/analyzer.py` |
| SOAR timeout 3 s; CTI timeout 6 s | `services/soar.py`, `services/cti.py` |
| Bulk chunk 500 lines, at most 2,000 chunks | `services/massive.py` |
| Celery time limits 840 s soft / 900 s hard; bulk task 6 h − 60 s / 6 h | `worker/celery_app.py`, `worker/tasks.py` |
| Breaker thresholds | `services/breaker.py` |
| Ahmia follow-up fetches: 5 | `services/collect.py` |
| Elasticsearch severity facet buckets (80 / 60 / 30) | `services/search_index.py` |

## Example `.env`

`.env.example` is the template; `scripts/gen_secrets.py` fills in the generated
values (see [Deployment](/guide/deployment)). The connection URLs for the
Compose services are set in `docker-compose.yml`, not here.

```ini
ENV=production
# Set COOKIE_SECURE=true once served over HTTPS.
COOKIE_SECURE=false
CORS_ORIGINS=http://localhost:8080
ALLOWED_HOSTS=*

# generated
POSTGRES_PASSWORD=…
RABBITMQ_PASS=…
ES_PASSWORD=…
MINIO_ACCESS_KEY=…
MINIO_SECRET_KEY=…

ADMIN_EMAIL=you@yourcompany.com
# generated, 24 characters
ADMIN_PASSWORD=…

# e.g. http://ollama:11434/v1
AI_ENDPOINT=
AI_MODEL=llama3.1:8b

SOAR_WEBHOOK_URL=
THREATFOX_AUTH_KEY=
GITHUB_TOKEN=
HIBP_API_KEY=

CRITICAL_THRESHOLD=80
SOAR_THRESHOLD=90
NEAR_DUP_THRESHOLD=3
```

`POSTGRES_PASSWORD` and `RABBITMQ_PASS` are not settings; Compose interpolates
them into `DATABASE_URL` and `RABBITMQ_URL`. `ES_PASSWORD` and the `MINIO_*`
keys are both — Compose passes them to the datastore containers and the
application reads them too.
