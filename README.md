<picture>
  <source media="(prefers-color-scheme: dark)" srcset="brand/secyourscan-logo-dark.svg">
  <img alt="SecYourScan" src="brand/secyourscan-logo-light.svg" width="360">
</picture>

# SecYourScan

Self-hosted exposure monitoring for **your organisation's own assets**. Put your domains, emails, keywords, IPs and wallets on a watchlist. SecYourScan then reads breach, paste and dark-web material for them, scores what it finds, masks the secrets, and alerts you. Everything runs on your own infrastructure.

The architecture is modelled on [naso](https://github.com/fabriziosalmi/naso):

```
sources / webhook ─► FastAPI ─► RabbitMQ ─► Celery (default · osint · massive)
                                               │
      sha256 + SimHash dedup ─► Babel extraction + masking ─► YARA ─► watchlist match
      ─► score ─► local-LLM triage (can only raise) ─► MinIO (raw) · PostgreSQL · Elasticsearch
      ─► notifications · SOAR webhook (≥90 or VIP)
Dark-web traffic: workers ─► HAProxy ─► Tor ×5
```

There is deliberately no identity hub and no profiling of individuals. A leak is matched against your watchlist and nothing else.

## Quick start (Docker)

```bash
python scripts/gen_secrets.py --admin-email you@yourcompany.com   # writes .env + secrets/
docker compose up -d --build
# UI + API:  http://localhost:8080   (admin password: ADMIN_PASSWORD in .env)
# optional local LLM:  docker compose --profile ai up -d ; set AI_ENDPOINT=http://ollama:11434/v1
```

Then add your domains to the **Watchlist** and create an API key (Settings) for your own scrapers:

```bash
curl -X POST http://localhost:8080/leaks/ingest/webhook \
  -H "X-API-Key: sys_…" -H "Content-Type: application/json" \
  -d '{"source":"my-scraper","content":"…text you found…","source_url":"https://…"}'
```

## Development without Docker

```bash
cd backend && python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.txt
set PIPELINE_INLINE=true & set ADMIN_EMAIL=admin@acme.example.com & set ADMIN_PASSWORD=change-me-please-now
.venv/Scripts/uvicorn app.main:app --port 8000     # SQLite, in-process pipeline
cd ../frontend && npm install && npm run dev        # http://localhost:5173
cd ../docs && npm install && npm run dev            # http://localhost:5174
```

Tests: `cd backend && .venv/Scripts/python -m pytest`

## Layout

| Path | What |
|---|---|
| `backend/app/services/pipeline.py` | The leak pipeline |
| `backend/app/services/recon.py` | Collectors: Ahmia, onion crawler, Telegram, GitHub, HIBP, feeds |
| `backend/app/services/incidents.py` | Incident queue: auto-open from findings, SLA, write-back |
| `backend/app/services/actors.py`, `actors_data.py` | Threat-actor catalogue, relevance scoring, MITRE ATT&CK view |
| `backend/app/services/ioc.py` | IOC enrichment, retro-hunt, STIX 2.1 (and TAXII 2.1 in `routers/threatintel.py`) |
| `backend/app/services/vendors.py` | Supply-chain vendor ratings |
| `backend/app/routers/` | HTTP API (OpenAPI at `/api/docs` when `ENV` isn't `production`) |
| `backend/app/worker/` | Celery app, tasks, beat schedule |
| `backend/mcp_server.py` | MCP server for Claude Desktop and similar clients (uses an API key) |
| `frontend/` | React SOC console with the Ctrl+K palette |
| `site/` | Public marketing site (Next.js): free email/domain breach check, breach directory |
| `docs/` | VitePress documentation with local search |

Use it only to monitor assets your organisation owns or is authorised to monitor.
