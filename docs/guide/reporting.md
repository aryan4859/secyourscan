# Reporting & Audit

Exports for people outside the tool, an audit trail for people checking the
tool, and health endpoints for machines watching it.

## Signed dossier

`GET /leaks/export/dossier?min_severity=0`, scope `read`, audited as
`GENERATE_DOSSIER` with the record count and the PDF's SHA-256.

An A4 PDF listing the tenant's leaks at or above `min_severity`, highest
severity first, **at most 5,000 rows** (silently truncated beyond that). Each row
has the discovery time, severity, source and URL, matched watch values, YARA
rules, status, and the SHA-256 of the raw evidence. No secrets and no snippet
text are included. With no matching records the endpoint answers `404` rather
than produce an empty document.

The response carries two headers:

| Header | Value |
|---|---|
| `X-Dossier-SHA256` | hex SHA-256 of the PDF bytes |
| `X-Dossier-Signature` | base64 Ed25519 signature **over the 32-byte SHA-256 digest** (not over the PDF directly) |

The public key is served, as PEM, at `GET /leaks/export/public-key` to any
authenticated caller. The signing key is `DOSSIER_SIGNING_KEY` if set, else the
JWT private key.

### Verifying with OpenSSL

OpenSSL 3.0 or later (`-rawin` is required for Ed25519):

```bash
API=http://localhost:8080
curl -sS -H "Authorization: Bearer $TOKEN" -D headers.txt -o dossier.pdf "$API/leaks/export/dossier"
curl -sS -H "Authorization: Bearer $TOKEN" -o dossier-public.pem "$API/leaks/export/public-key"

grep -i '^x-dossier-signature:' headers.txt | cut -d' ' -f2 | tr -d '\r\n' | base64 -d > dossier.sig
openssl dgst -sha256 -binary dossier.pdf > dossier.sha256

openssl pkeyutl -verify -pubin -inkey dossier-public.pem -rawin \
  -in dossier.sha256 -sigfile dossier.sig
# Signature Verified Successfully
```

### Verifying with Python

```python
import base64, hashlib
from cryptography.hazmat.primitives.serialization import load_pem_public_key

public_key = load_pem_public_key(open("dossier-public.pem", "rb").read())
digest = hashlib.sha256(open("dossier.pdf", "rb").read()).digest()
signature = base64.b64decode(open("signature.txt").read().strip())  # the X-Dossier-Signature value

public_key.verify(signature, digest)  # raises InvalidSignature if the PDF was altered
print("valid:", digest.hex())
```

This is what `test_dossier_signature_verifies` does.

### What the signature does and does not prove

It proves the PDF has not changed since this deployment's key signed it. It
does not prove the contents are true, and:

- **Distribute the public key out of band.** The key endpoint requires
  authentication, so an external recipient cannot fetch it; and a key fetched
  from the same place as the document proves little. Send the PEM separately,
  once.
- **The key must be stable.** In development, with no `JWT_PRIVATE_KEY`, the
  key is generated at startup, so every restart makes earlier dossiers
  unverifiable. Set `DOSSIER_SIGNING_KEY` (or `JWT_PRIVATE_KEY`) before
  producing anything you will need to verify later.
- **Rotating the JWT key rotates the dossier key** unless `DOSSIER_SIGNING_KEY`
  is set separately. Keep old public keys.

Whether this satisfies a particular court or regulator is a question for a
lawyer, not for this page.

## CSV export

`GET /leaks/export/csv`, scope `read`, audited as `EXPORT_CSV`. The tenant's
leaks, newest first, **at most 50,000 rows**. Columns: `id`, `discovered_at`,
`severity`, `category`, `status`, `source`, `source_url`, `watch_matches`,
`yara_rules`, `sha256`. No snippet text.

**Formula neutralisation (CWE-1236).** Every field originates somewhere
hostile — a source name or URL is whatever a scraper or dump supplied. Any cell
that begins with `=`, `+`, `-`, `@`, a tab or a carriage return is prefixed with
`'`, so a spreadsheet shows it as text instead of evaluating it. A source named
`=cmd|' /c calc'!A1` is exported as `'=cmd|' /c calc'!A1` (verified by
`test_csv_export_neutralises_formulas`).

## Audit trail

### What is recorded

`audit_logs`. Each row has the tenant, the actor (`user_id`, or
`apikey:<key id>` for API keys), the action, an optional resource type and id, a
JSON `details` field, the client IP where the request handler passes it, a
timestamp, and two hashes.

Read it with `GET /system/audit` (scope `read`; `limit` up to 200, `offset`,
optional `action=` filter), newest first, own tenant only.

### The chain

Each row's `row_hash` is the SHA-256 of a canonical JSON of its own fields —
tenant, user, action, resource, details, IP, timestamp — **plus the previous
row's hash in the same tenant** (`prev_hash`; the first row's is 64 zeros).
`GET /system/audit/verify` recomputes every hash in order and returns:

```json
{"valid": false, "checked": 41, "broken_at": 42, "reason": "content"}
```

`reason` is `content` if a row's own fields no longer match its hash (an edit),
or `link` if its `prev_hash` does not match the preceding row (a deletion or
insertion). Verified by `test_audit_chain_detects_tampering`.

The ledger is **tamper-evident, not immutable**:

- Anyone with write access to the database can still change a row. They cannot
  do it without the verifier noticing — unless they recompute every hash after
  it, which nothing prevents. Ship the log somewhere append-only if that
  matters.
- **Deleting the newest row is not detectable.** The chain proves each row
  follows the one before; nothing records how many rows there should be. Remove
  the last entry, or the last ten, and `verify` still says `valid`. Copying the
  latest `row_hash` somewhere else periodically closes this.
- **Concurrent writes are serialised on PostgreSQL.** `log_action` takes a
  transaction-scoped advisory lock, `pg_advisory_xact_lock(hashtext('audit:<tenant>'))`,
  before reading the previous hash, so two requests in one tenant can no longer
  both link to the same row. Earlier they could, and the second row then
  failed verification with `reason: link` although nothing was tampered with.
  On SQLite there is no lock, and that false break remains possible.
- **The tenant-less chain cannot be verified through the API.** Failed logins
  for unknown emails and `DELETE_TENANT_COMPLETED` are written with no tenant;
  `verify` always checks the caller's tenant.
- **Deleting a tenant deletes its audit chain.**

### CSV export of the audit log

`GET /system/audit/export.csv`, scope `read`: every row of the tenant, oldest
first, all fields quoted, including `prev_hash` and `row_hash` so the chain can
be re-verified offline. Cells beginning with `=`, `+`, `-`, `@`, a tab or a
carriage return are prefixed with `'`, the same rule as the leak export.
The export itself is not audited.

### Audited actions

Every `action=` string in the code — 33 of them:

| Action | Trigger | Where |
|---|---|---|
| `LOGIN` | successful sign-in | `routers/auth.py` |
| `LOGIN_FAILED` | wrong password, unknown email or disabled user; `details.email` | `routers/auth.py` |
| `LOGOUT` | token revoked | `routers/auth.py` |
| `UPDATE_PROFILE` | own name or password changed; `details.password_changed` | `routers/users.py` |
| `CREATE_USER` / `UPDATE_USER` | admin adds a user / changes role or active flag | `routers/users.py` |
| `CREATE_TENANT` | platform admin creates a tenant (recorded in the platform admin's tenant) | `routers/users.py` |
| `DELETE_TENANT_TRIGGERED` | platform admin requests deletion (recorded in the platform admin's tenant) | `routers/users.py` |
| `DELETE_TENANT_COMPLETED` | saga finished (tenant-less chain) | `worker/tasks.py` |
| `CREATE_API_KEY` / `REVOKE_API_KEY` | key lifecycle | `routers/users.py` |
| `BULK_INGEST` | bulk job accepted | `routers/leaks.py` |
| `UPDATE_LEAK_STATUS` | triage status changed; `details.from`, `details.to` | `routers/leaks.py` |
| `ACKNOWLEDGE_LEAK` / `ACKNOWLEDGE_ALL_CRITICAL` | one leak / bulk acknowledgement with count | `routers/leaks.py` |
| `VIEW_EVIDENCE` | unmasked original downloaded | `routers/leaks.py` |
| `GENERATE_DOSSIER` | PDF produced; record count and SHA-256 | `routers/leaks.py` |
| `EXPORT_CSV` | leak CSV produced | `routers/leaks.py` |
| `CREATE_WATCH_ITEM` / `UPDATE_WATCH_ITEM` / `DELETE_WATCH_ITEM` | watchlist | `routers/monitoring.py` |
| `CREATE_SOURCE` / `UPDATE_SOURCE` / `DELETE_SOURCE` | sources | `routers/monitoring.py` |
| `RUN_SOURCE` | source run requested | `routers/monitoring.py` |
| `DARK_WEB_RECON` / `TELEGRAM_RECON` | probe queued (not completed) | `routers/monitoring.py` |
| `SHODAN_RECON` | InternetDB lookup requested | `routers/monitoring.py` |
| `CREATE_YARA_RULE` / `DELETE_YARA_RULE` | rule changes | `routers/monitoring.py` |
| `AI_CHAT` | chat request; first 500 characters of the prompt | `services/agent.py` |
| `AI_FLAG_LEAK` | Co-Analyst changed a status | `services/agent.py` |
| `AI_DARK_WEB_PROBE` | Co-Analyst queued a probe | `services/agent.py` |

Not audited, so do not look for them: notification acknowledgement, plan and
task changes, the Co-Analyst's read tools and `create_task`, `POST /yara/test`,
reads of leaks and search, and audit log reads and exports. The pipeline
itself writes no audit entries; leak provenance is on the leak and its
`SourceRun`.

The client IP is recorded for every user-initiated action that goes through a
router; it is empty for actions from the Co-Analyst and the worker. It is
whatever uvicorn resolved, which behind the bundled nginx is the
`X-Forwarded-For` client.

## Health endpoints

Both are open — no credentials — and say nothing an anonymous caller could use.

### `GET /system/status`

Can the API reach its database? **Always `200`**; read the body.

```json
{"status": "operational", "latency_ms": {"total": 1.84}}
```

`status` is `degraded` if `SELECT 1` fails. The backend image's Docker
`HEALTHCHECK` parses this body for `operational`, which is the right way to
use it. Monitoring that checks only the HTTP status will read a dead database as
healthy.

### `GET /system/health`

Which backing services are up. **`503` if any configured component is down.**

```json
{
  "status": "ok",
  "components": {
    "database": "ok",
    "elasticsearch": "ok",
    "object_storage": "ok",
    "broker": "ok",
    "ai": "enabled",
    "tor": "configured"
  },
  "circuits": {"elasticsearch": "closed", "minio": "closed", "ai": "closed"}
}
```

| Component | Values | How it is determined |
|---|---|---|
| `database`, `elasticsearch`, `object_storage`, `broker` | `ok`, `degraded`, `disabled` | probed live, 3-second timeout each; `disabled` when not configured |
| `ai` | `enabled`, `disabled` | configuration only — **not probed**. Use `GET /ai/health` (authenticated) to check the model server |
| `tor` | `configured`, `disabled` | configuration only — **not probed** |
| `circuits` | `closed`, `open`, `half-open` | this API process's breakers; they do not affect `status` |

Hostnames and error messages are never included; they go to the API log.
