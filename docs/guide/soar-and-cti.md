# SOAR & CTI

One outbound webhook for your SIEM or SOAR, and three threat-intelligence
lookups.

## SOAR webhook

### When it fires

At the end of [the pipeline](/guide/pipeline#_13-soar-webhook), for a newly
created leak (never for a duplicate), when either:

- severity ≥ `SOAR_THRESHOLD` (default **90**), or
- any watchlist match is VIP — at any severity.

Set the destination with `SOAR_WEBHOOK_URL`. Unset, nothing is sent.

```bash
SOAR_WEBHOOK_URL=https://soar.corp.example/hooks/secyourscan
SOAR_THRESHOLD=90
```

`SOAR_THRESHOLD` is a setting, unlike naso's hard-coded 90. It is independent
of `CRITICAL_THRESHOLD` (which governs in-app notifications) and of the
`min_severity` parameter on `POST /leaks/ack-all`.

### The payload

A single `POST` with a JSON body built by `soar.build_payload`. **It is not
STIX** — the shape below is SecYourScan's own, and a receiver expecting STIX 2.1
bundles will reject it. Map it on the receiving side.

```json
{
  "alert_type": "CRITICAL_EXPOSURE",
  "tag": null,
  "leak": {
    "id": "7f9c2c1e-…",
    "tenant_id": "1b0e…",
    "source": "paste",
    "source_url": "https://paste.example/abc",
    "title": "…",
    "severity": 100,
    "category": "CREDENTIALS",
    "sha256": "e3b0c442…",
    "discovered_at": "2026-10-18T09:12:44.120391",
    "watch_matches": [
      {"id": "…", "type": "domain", "value": "acme.example.com", "vip": true,
       "hits": ["user0@acme.example.com", "user1@acme.example.com"]}
    ],
    "yara_rules": ["combo_list", "leak_marketplace_language"],
    "emails": ["user0@acme.example.com", "…"],
    "credential_count": 6
  }
}
```

| Field | Notes |
|---|---|
| `alert_type` | `CRITICAL_EXPOSURE` at or above the threshold; `VIP_EXPOSURE` for a VIP match below it |
| `tag` | `"[VIP]"` with `VIP_EXPOSURE`, otherwise `null` |
| `leak.discovered_at` | ISO 8601, UTC, **without** a timezone suffix |
| `leak.watch_matches` | the full match objects, including `hits` |
| `leak.emails` | up to 50 extracted addresses |

No passwords, card numbers or snippet text are included — only counts, names
and the evidence hash. Email addresses are included in clear.

### Delivery semantics

- **Three-second timeout**, then give up.
- **Awaited**, not fire-and-forget: a slow receiver delays the worker by up to
  three seconds per qualifying leak.
- **No retry and no record.** A failure is logged by the worker
  (`SOAR webhook failed: …`) and not stored on the leak. If your SOAR is down
  for an hour, that hour's alerts are not re-sent. The notification row in
  SecYourScan remains the system of record.
- **No authentication or signature.** The request carries no secret header and
  no HMAC. Put a secret in the URL's path or query and restrict the receiver
  to your SecYourScan host's address.

## CTI enrichment

`services/cti.py`. Three sources. Every call is best-effort with a six-second
timeout, goes out over the clearnet, and never fails the pipeline.

### mempool.space — Bitcoin balances

Keyless. When a leak contains Bitcoin addresses, the **first** one is looked up
at `https://mempool.space/api/address/<address>` and stored under `cti.btc`:

```json
{"address": "bc1q…", "balance_sats": 125000, "tx_count": 7, "source": "mempool.space"}
```

`balance_sats` is funded minus spent outputs, confirmed chain only. Monero
addresses are extracted but not enriched.

### ThreatFox — IP reputation

**Needs `THREATFOX_AUTH_KEY`.** abuse.ch requires an Auth-Key for the ThreatFox
API; without one the lookup is skipped silently. With one, the **first** IPv4 in
a leak is queried with `search_ioc` and stored under `cti.threatfox`:

```json
{"ip": "203.0.113.7", "found": true, "malware": ["Cobalt Strike"],
 "threat_types": ["botnet_cc"], "confidence": 100}
```

or `{"ip": "…", "found": false}` when ThreatFox has nothing.

### Shodan InternetDB — host exposure

Keyless, and **not** part of the pipeline. It is a manual lookup for your own
public IPs:

```bash
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8080/recon/shodan?ip=198.51.100.10"
```

Scope `recon`, audited as `SHODAN_RECON`. The address must be a public IPv4;
private, loopback and reserved addresses are refused with `422`. The response is
InternetDB's — open ports, CPEs, hostnames, tags and known CVEs — with
`found: true`, or `{"ip": …, "found": false}` on a `404`. If InternetDB is
unreachable the endpoint answers `502`.

### What enrichment tells third parties

Each lookup discloses the value to the service: mempool.space learns which
wallet addresses appeared in your leaks, ThreatFox which IPs, and InternetDB
which hosts you are checking. None of these go through Tor. If that matters,
leave `THREATFOX_AUTH_KEY` unset; the mempool.space lookup cannot currently be
switched off without editing `cti.enrich`.
