# Ingestion

Two ways to push material in yourself, in addition to the
[collectors](/guide/dark-recon): a webhook for one item at a time, and bulk
ingestion for dumps too large to send as one.

Both need a credential with the `ingest` scope. For scrapers, that should be an
API key holding **only** `ingest`.

## API keys and scopes

API keys are created by an admin, belong to one tenant, and carry a subset of
four scopes:

| Scope | Grants |
|---|---|
| `ingest` | `POST /leaks/ingest/webhook`, `POST /leaks/ingest/bulk` |
| `read` | every `GET` over leaks, watchlist, sources, runs, YARA rules, notifications, plans, stats, exports and the audit log; `POST /yara/test` |
| `write` | triage (status, ack), watchlist, sources, YARA rules, notifications ack, plans, and `POST /ai/chat` |
| `recon` | `/recon/*` probes and `POST /sources/{id}/run` |

A JWT session (browser or bearer) holds all four implicitly; what separates an
admin from an analyst is the role, not scopes. API keys are never admins and
cannot download raw evidence or read `/users/me`.

```bash
# as an admin
curl -X POST http://localhost:8080/api-keys \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "paste-scraper", "scopes": ["ingest"]}'
```

```json
{"id": "…", "name": "paste-scraper", "prefix": "sys_AbC123", "scopes": ["ingest"],
 "created_at": "…", "last_used_at": null, "revoked_at": null,
 "key": "sys_AbC123…"}
```

The `key` is returned once. Only its SHA-256 is stored; `prefix` (the first ten
characters) is kept so you can tell keys apart. `last_used_at` is updated on
every use. `DELETE /api-keys/{id}` revokes a key immediately. Creation and
revocation are audited (`CREATE_API_KEY`, `REVOKE_API_KEY`).

Present the key as either header:

```
X-API-Key: sys_…
Authorization: Bearer sys_…
```

## Webhook: `POST /leaks/ingest/webhook`

One discovered item. The body is JSON:

| Field | Type | Required | Notes |
|---|---|---|---|
| `content` | string | yes | the raw text found |
| `source` | string, 1–64 | no, default `webhook` | name of the tool that found it; becomes the leak's `source` |
| `source_url` | string, ≤ 1024 | no | where it was found |
| `title` | string, ≤ 512 | no | |
| `metadata` | object | no | stored on the leak as-is |

```bash
curl -X POST http://localhost:8080/leaks/ingest/webhook \
  -H "X-API-Key: $SYS_INGEST_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "source": "paste-scraper",
        "source_url": "https://paste.example/raw/abc123",
        "title": "acme dump",
        "content": "ceo@acme.example.com:Winter2026!\nops@acme.example.com:hunter22",
        "metadata": {"scraper_version": "1.4"}
      }'
```

```json
{"status": "accepted", "mode": "queued", "task_id": "5d0c…"}
```

What happens:

1. The raw body is size-checked (**5 MiB** maximum, else `413` with a pointer
   to bulk ingestion), parsed with `orjson` (`400` on invalid JSON) and
   validated (`422`; the error body never echoes your input back).
2. The item is published to the `default` queue and the API answers **`202`**
   without analysing anything. The `task_id` is the Celery task id; the leak
   id is not known yet.
3. A worker runs [the pipeline](/guide/pipeline).

Without a broker the pipeline runs before the response, and the answer is
`{"status": "accepted", "mode": "inline", "result": {"id": …, "created": true,
"severity": 100}}`. `created: false` means it was a duplicate.

The webhook is rate-limited to **60 requests per minute per client IP**, in
memory, per API process.

## Bulk: `POST /leaks/ingest/bulk`

For dumps of any size. `multipart/form-data` with **exactly one** of:

| Field | Meaning |
|---|---|
| `file` | the dump itself; stored in object storage first, so **needs MinIO** (`503` otherwise) |
| `url` | an `http(s)://` URL the worker will stream from; must resolve to a public address (`422` otherwise), redirects are not followed |

and optionally `source` (default `bulk`).

```bash
# from a URL
curl -X POST http://localhost:8080/leaks/ingest/bulk \
  -H "X-API-Key: $SYS_INGEST_KEY" \
  -F url=https://files.example/dump.txt -F source=forum-dump

# from a file
curl -X POST http://localhost:8080/leaks/ingest/bulk \
  -H "X-API-Key: $SYS_INGEST_KEY" \
  -F file=@dump.txt -F source=forum-dump
```

```json
{"status": "accepted", "job_id": "c1a2…", "mode": "queued", "task_id": "…"}
```

`job_id` is a `SourceRun` of kind `massive`; follow it with
`GET /sources/runs/{job_id}`. The request is audited as `BULK_INGEST`.

### How it streams

`services/massive.py`, on the `massive` queue (concurrency 1 in the bundled
Compose file):

1. **Read line by line** — from object storage in 1 MiB chunks, or from the URL
  with `httpx.stream` — never the whole file at once.
2. **Pre-filter.** A line is kept if it contains `PRIVATE KEY-----`, or if it
   contains, case-insensitively, any **active** watch value of three or more
   characters (in inline mode too). With an empty watchlist the filter instead keeps lines that are
   both an email and a credential pair.
3. **Chunk.** Kept lines are batched 500 at a time.
4. **Pipeline.** Each chunk goes through `process_leak` as one leak titled
   `<source> chunk <n>`, with `metadata` carrying `bulk_location`, `scanned`,
   `matched` and `chunk`. Dedup applies to chunks like anything else.

The run records `results` (chunks), `new_leaks`, and `report` (the latest
scan statistics) after every chunk, so progress is visible while it runs. It
ends with status `ok`, `error`, or `truncated` (below).

### Limits

These are real and not obvious:

- **Uploads are streamed to object storage, but buffered on disk first.** The
  API passes the upload to MinIO as a stream in 16 MiB parts
  (`storage.put_stream`) rather than reading it into memory. Before that, the
  ASGI server spools the request body to a temporary file in `/tmp` — which in
  the bundled Compose stack is a `tmpfs`, i.e. RAM. The bundled nginx caps
  request bodies at 512 MiB. For anything larger, put the file somewhere the
  worker can fetch and send the `url`. (Earlier, the API read the whole upload
  into memory.)
- **At most 2,000 chunks** (1,000,000 matching lines) per job. Reaching the cap
  ends the run with status **`truncated`** and the error
  `stopped after 2000 chunks`; the rest of the file is not read. A file whose
  matches end exactly at the cap is also reported `truncated`. (Earlier this
  was reported as `ok`.)
- **Six hours per job.** The bulk task has its own time limits — 6 h hard,
  6 h minus 60 s soft — instead of the 15 minutes every other task gets. A job
  that hits the soft limit ends with status `error`; chunks processed before
  that are kept.
- **Only public URLs.** A `url` that resolves to a loopback, private,
  link-local or otherwise non-global address is refused with `422`, and
  redirects are not followed. See
  [Server-side request protection](/guide/security#server-side-request-protection).
- **A chunk is the unit of a leak.** One leak per 500 matching lines, not per
  account. The chunk's severity reflects everything in it.
- **A pre-filter miss is final.** A line that matches nothing on the watchlist
  at ingestion time is discarded, not stored.
