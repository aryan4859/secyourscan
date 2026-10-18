# Deployment

The supported deployment is the Docker Compose stack in `docker-compose.yml`.
It is a sound single-host baseline. It terminates no TLS, and some of its
defaults are for evaluation; the [production checklist](#production-checklist)
lists what to change.

## Requirements

- Docker with Compose v2.
- Python 3 with the `cryptography` package on the machine where you generate
  secrets (any recent Python will do; the script only generates keys).
- About 4 GB of RAM for the stack: Elasticsearch alone is given a 512 MB heap
  and needs headroom around it. More if you add the Ollama profile.
- Outbound internet for the workers (clearnet collectors, CTI, the Tor network).

## Quick start

```bash
python scripts/gen_secrets.py --admin-email you@yourcompany.com
docker compose up -d --build
docker compose ps
curl -s localhost:8080/system/health
```

Open `http://localhost:8080` and sign in as the admin email. This first admin
is the only **platform admin** — the one account that can create and delete
tenants. Admins you create later, including each new tenant's first admin, are
tenant admins. The password is
`ADMIN_PASSWORD` in the generated `.env`; change it after the first sign-in
(`PUT /users/me` with `current_password` and `new_password`).

### What `gen_secrets.py` does

- Generates an Ed25519 private key at `secrets/jwt_private_key.pem` (PKCS#8,
  unencrypted).
- Renders `.env` from `.env.example`, filling in random values for
  `POSTGRES_PASSWORD`, `RABBITMQ_PASS`, `ES_PASSWORD`, `MINIO_ACCESS_KEY`,
  `MINIO_SECRET_KEY`, `ADMIN_EMAIL` and a 24-character `ADMIN_PASSWORD`.
- **Refuses to overwrite** either file if it exists. Delete them first if you
  mean it — and read the runbook entry on
  [rotating the database password](/guide/runbook#regenerating-env-on-a-stack-that-has-run)
  before you do that on a stack that has stored data.

Every `:?` in the Compose file — `POSTGRES_PASSWORD`, `RABBITMQ_PASS`,
`ES_PASSWORD`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY` — makes `docker compose up`
fail with "run scripts/gen_secrets.py" if the value is missing.

## Services

| Service | Image / build | Role | Networks | Published |
|---|---|---|---|---|
| `db` | `postgres:16-alpine` | relational store | backend | — |
| `rabbitmq` | `rabbitmq:3.13-management-alpine` | broker | backend | `127.0.0.1:15672` (management UI) |
| `elasticsearch` | `elasticsearch:8.15.3`, single node, security on, HTTP TLS off | search | backend | — |
| `minio` | `chrislusf/seaweedfs:3.80` (S3 gateway on :9000) | evidence | backend | — |
| `tor` | `infrastructure/tor`, **5 replicas** | Tor SOCKS | tor | — |
| `tor-lb` | `haproxy:2.9-alpine` | balances the Tor pool | tor | — |
| `api` | `backend/Dockerfile` | FastAPI on 8000 | backend, tor | — |
| `worker-pipeline` | same image | `celery … worker -Q default,osint --concurrency=4` | backend, tor | — |
| `worker-massive` | same image | `celery … worker -Q massive --concurrency=1` | backend, tor | — |
| `beat` | same image | `celery … beat`, schedule file in `/tmp` | backend, tor | — |
| `web` | `infrastructure/web/Dockerfile` | nginx serving the SPA and proxying the API | backend | `127.0.0.1:8080` |
| `ollama` | `ollama/ollama:0.3.14`, profile `ai` | optional local model | backend | — |

**Only two ports are published, both on localhost.** The API is not published
at all; it is reached through `web`, which proxies every API path prefix
(`/auth`, `/users`, `/tenants`, `/api-keys`, `/leaks`, `/watchlist`, `/sources`,
`/recon`, `/yara`, `/notifications`, `/ai`, `/system`, `/api`) to `api:8000`. One
origin for the SPA and the API keeps the session cookie first-party, which is
what lets `SameSite=Strict` hold.

**Start order.** The four datastores must be healthy before `api` starts.
`worker-pipeline`, `worker-massive` and `beat` wait for `api` to be healthy,
because the API creates the schema on its first start.

### The application containers

All four share one definition (`x-app`):

- `env_file: .env`, plus `DATABASE_URL`, `RABBITMQ_URL`, `ES_URL`,
  `MINIO_ENDPOINT` and `TOR_PROXY=socks5h://tor-lb:9050` set in the Compose
  file;
- the JWT key mounted as the Docker secret `/run/secrets/JWT_PRIVATE_KEY`, which
  pydantic-settings reads as the `JWT_PRIVATE_KEY` setting;
- `no-new-privileges`, `cap_drop: [ALL]`, a **read-only root filesystem** with
  a `tmpfs` on `/tmp`;
- `extra_hosts: host.docker.internal:host-gateway`, so a model server on the
  host is reachable as `http://host.docker.internal:<port>/v1`.

The image is `python:3.12-slim`, runs as uid `10001`, and has a `HEALTHCHECK`
that requires `/system/status` to answer `"status": "operational"` (the
workers disable it). uvicorn runs with `--proxy-headers
--forwarded-allow-ips *`, so it trusts `X-Forwarded-For` from **any** peer. That
is safe only because nothing but `web` can reach the API; if you publish port
8000, restrict `--forwarded-allow-ips` first, or client IPs in the audit log and
the per-IP rate limits become spoofable.

### The web container

Node 22 builds the SPA; `nginxinc/nginx-unprivileged:1.27-alpine` serves it on
8080 with `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`
and a `self`-only Content-Security-Policy. `client_max_body_size` is 512 MiB for
bulk uploads; `proxy_buffering off` so `/ai/chat` Server-Sent Events arrive as
they are produced; `proxy_read_timeout 300s`.

### Tor

Five `tor` replicas on the `tor` network, behind `tor-lb`. Scale with:

```bash
docker compose up -d --scale tor=5
```

HAProxy discovers replicas through Docker DNS (up to ten), so no configuration
change is needed. See [Architecture](/guide/architecture#_4-tor-pool) for the
Tor and HAProxy settings.

::: warning Tor is not enforced at the network level
The application containers sit on the `backend` network, which has outbound
access, as well as on `tor`. Tor is used because the code asks for it on
specific requests, not because other routes are blocked. The clearnet
collectors need that access; it also means a request the code sends directly
goes out directly. The table on
[Dark Web Recon](/guide/dark-recon#what-goes-through-tor) is the complete list.
:::

## Optional: a local model

```bash
docker compose --profile ai up -d
docker compose exec ollama ollama pull llama3.1:8b
```

Then set `AI_ENDPOINT=http://ollama:11434/v1` in `.env` and recreate the
application containers (`docker compose up -d`). Or run LM Studio or Ollama on
the host and use `http://host.docker.internal:1234/v1` (LM Studio's default
port) or `:11434/v1` (Ollama's). Check with `GET /ai/health`.

## Running without Docker

For development. Everything optional is off by default, so the only
requirement is Python 3.12 and the packages:

```bash
cd backend
python -m venv .venv
.venv/bin/pip install -r requirements.txt      # Windows: .venv\Scripts\pip
export ADMIN_EMAIL=admin@acme.example.com ADMIN_PASSWORD='a-long-password'
.venv/bin/uvicorn app.main:app --reload --port 8000
```

This gives you SQLite at `backend/secyourscan.db`, the pipeline running inline,
SQL search, no evidence storage, no AI and no scheduler. The interactive API
docs are at `http://localhost:8000/api/docs` (not at `/docs`, as an earlier
version of these pages said). The JWT key is ephemeral, so you sign in again
after each restart.

Use an email with a real-looking domain: `email-validator` rejects
special-use TLDs such as `.local` and `.test` when creating users.

To add pieces one at a time, set their variables — for example `RABBITMQ_URL`
and a worker:

```bash
.venv/bin/celery -A app.worker.celery_app worker -Q default,osint,massive --loglevel=INFO
.venv/bin/celery -A app.worker.celery_app beat --loglevel=INFO
```

Run the tests with `.venv/bin/python -m pytest` from `backend/`. They use a
temporary SQLite database and inline mode, and need no other services.

### The web app in development

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

The Vite dev server proxies every API prefix to `http://127.0.0.1:8000`, so
the SPA and the API share one origin in development too, as they do behind
nginx.

### These docs

```bash
cd docs
npm install
npm run dev        # http://localhost:5174
npm run build      # fails on dead links
```

Set `DOCS_BASE=/<repo>/` when building for GitHub Pages.

## Production checklist

1. **Generate secrets with the script**, never reuse `.env.example` values, and
   keep `secrets/` out of version control.
2. **Terminate TLS in front of `web`** (Caddy, Traefik, a load balancer) and set
   `COOKIE_SECURE=true`. The default `false` exists so the stack works over
   plain HTTP on localhost; behind TLS it lets the session cookie travel over a
   downgraded connection.
3. **Set `ALLOWED_HOSTS`** to your hostname and `CORS_ORIGINS` to the real
   origin.
4. **Keep `ENV=production`** (the `.env.example` default), so the interactive
   API docs are off and a missing JWT key is fatal.
5. **Keep the RabbitMQ management UI** (`127.0.0.1:15672`) off untrusted
   networks. The object store and Elasticsearch are not published;
   keep it that way.
6. **Decide on `AI_ENDPOINT` deliberately.** A hosted API receives leak text.
7. **Set a shared rate limit at the reverse proxy.** The application's limits
   are per process.
8. **Back up** the `pgdata`, `miniodata` and `esdata` volumes, and the JWT key.
   Losing the key ends all sessions and makes past dossiers unverifiable.
   Elasticsearch can be rebuilt from PostgreSQL only by re-ingesting — there is
   no re-index command — so back it up too, or accept SQL-only search for old
   data.
9. **Plan upgrades.** There are no migrations: `create_all` creates missing
   tables but never alters existing ones. A release that adds a column needs a
   manual `ALTER TABLE`.
10. **Read the [Security Model](/guide/security)**, especially the known gaps.
    Keep the platform admin account for tenant administration, and restrict
    worker egress if you can — the URL check on feeds and bulk URLs does not
    stop DNS rebinding.
