# Incidents & Threat Intel

Four modules turn findings into work and add the attacker's side of the picture:

| Page | What it does | API |
|---|---|---|
| **Incidents** | One queue for every finding that needs a person, with owner, status, SLA and timeline | `/incidents` |
| **Threat Actors** | Ranks actor profiles by evidence that they matter to you; maps their ATT&CK techniques | `/actors`, `/threat-intel/profile` |
| **IOC Hunting** | Enriches indicators, retro-hunts them in your own data, shares them as STIX 2.1 / TAXII 2.1 | `/iocs`, `/taxii2/` |
| **Supply Chain** | Outside-in rating of your vendors from public data; alerts when one is breached | `/vendors`, scan module `vendors` |

## Incidents

An incident opens automatically, at most once per finding, for:

| Finding | Severity |
|---|---|
| Leak scoring ≥ `CRITICAL_THRESHOLD` | critical if ≥ `SOAR_THRESHOLD`, else high |
| Open vulnerability of priority critical/high (KEV, EPSS) | the finding's priority |
| Lookalike domain with risk ≥ 70 | high (risk ≥ 90) or medium |
| Live phishing URL (new or reported) | high |
| Ransomware leak-site post naming you | critical |
| One of your hosts listed in a threat feed | critical |
| Malicious IOC seen on one of your assets | critical |
| Vendor named on a ransomware leak site | critical for critical/high vendors, else high |

The sync runs after every external-risk scan, after every critical leak, after
an IOC hunt, and on demand (**Sync findings**, `POST /incidents/sync`).

**Workflow:** `open → investigating → contained → resolved` (or
`false_positive`). Moving out of `open`, or assigning someone, records the
acknowledgement time (MTTA). Closing records the resolution time (MTTR).
Closing also updates the finding: a false positive marks the leak
`false_positive`, the lookalike or phishing URL `benign`, the ransomware hit
`false_positive` and the vulnerability `accepted`. A closed finding never
reopens its incident.

**SLA** (time to resolve): critical 4 h, high 24 h, medium 72 h, low 7 days,
counted from creation. A change of severity re-prices it. States: `on_track`,
`at_risk` (< 25 % left), `overdue`, then `met` / `breached` once closed.

Every change and comment is in the incident timeline and in the audit log.

## Threat Actors

Ships with profiles of the actors most often seen against organisations
(APT28, APT29, Sandworm, Lazarus, Kimsuky, APT41, Volt Typhoon, MuddyWater,
FIN7, Scattered Spider, LockBit, ALPHV, Cl0p, Akira, Play, Qilin, Black Basta,
RansomHub), drawn from MITRE ATT&CK group pages and CISA advisories. Add your
own with **Add actor**. Custom actors are visible to your tenant only.

Set your **threat profile** (sectors and ISO country codes). Relevance (0–100)
is the sum of explained reasons:

| Evidence | Points |
|---|---|
| Named you or one of your vendors on its leak site, or linked to one of your incidents | 60 |
| Targets one of your sectors | 25 |
| Targets one of your countries (exact 20, region such as EU/NATO 15, worldwide 5) | ≤ 20 |
| Leak-site posts in the last 30 days (cached global feed) | ≤ 15 |
| Indicators in your IOC store attributed to it | 10 |

Leak-site group names (`lockbit3`, `alphv`, `clop`…) are aliases, so
ransomware hits link to the right profile.

The **ATT&CK view** counts, for each technique, the relevant actors (relevance
≥ 25) that use it. With no profile and nothing observed it falls back to all
actors. **Defend first** lists the ten most-used techniques with what to do
about each.

## IOC Hunting

Paste up to 100 indicators at a time: IPv4/IPv6, domains, URLs, MD5/SHA-1/SHA-256,
emails. Defanged forms (`hxxp`, `[.]`, `[@]`) are accepted.

| Source | Types | Needs |
|---|---|---|
| abuse.ch exports (URLhaus, Feodo Tracker, ThreatFox), cached 1 h, matched locally | ip, domain, url, hashes | nothing |
| Shodan InternetDB | ip | nothing |
| ThreatFox API, MalwareBazaar | ip/domain/url/hashes, hashes | `ABUSECH_AUTH_KEY` |
| AlienVault OTX | ip, domain, url, hashes | `OTX_API_KEY` |
| AbuseIPDB | ip | `ABUSEIPDB_API_KEY` |
| VirusTotal | ip, domain, url, hashes | `VIRUSTOTAL_API_KEY` |

Private and reserved IPs are never sent to any source. The verdict uses the
highest source score: **malicious** ≥ 75, **suspicious** ≥ 40. **Clean** is
claimed only when a broad-coverage source (OTX, AbuseIPDB, VirusTotal)
answered, or OTX allow-lists the indicator. Otherwise it is **unknown**:
"not in a feed" is not the same as "clean". An analyst verdict overrides the
computed one and survives re-checks.

::: warning abuse.ch keyless exports
As of November 2026, the keyless URLhaus `text_recent` and ThreatFox
`export/json/recent` URLs return `410 Gone`. Feodo Tracker still works. A
feed that cannot be downloaded is named in the result ("ThreatFox
unavailable") and never counted as "not listed". Set `ABUSECH_AUTH_KEY` to
use the ThreatFox and MalwareBazaar APIs instead.
:::

Every indicator is **retro-hunted** in your data:

* `asset`: your attack-surface hosts and their IPs, watchlist, vendors;
* `mention`: leaks (extracted entities, or the hash/URL in the snippet), lookalike domains, phishing URLs.

A malicious indicator with an `asset` sighting opens a critical incident.
Indicators are re-checked daily when older than 7 days (`ioc_refresh`, 03:43 UTC).

### Sharing

* **STIX 2.1 bundle**: `GET /iocs/export/stix?min_verdict=suspicious&max_tlp=amber`.
  Indicators carry standard TLP marking definitions, `confidence` = score,
  and `indicates` relationships to threat-actor objects. Ids are deterministic,
  so re-imports update instead of duplicating.
* **Blocklist**: `GET /iocs/export/blocklist.txt?type=ip`. Malicious only,
  one per line. Every TLP is included, since it feeds your own controls.
* **TAXII 2.1** (read-only): discovery at `/taxii2/`, one collection
  (`b3c1f2e4-7a1d-4f6b-9a0e-5c2d8e7f1a90`) per tenant serving malicious and
  suspicious indicators up to TLP:AMBER. `added_after` is supported, and
  `X-TAXII-Date-Added-Last` tells the client where to resume. Authenticate with
  an API key with the `read` scope: `Authorization: Bearer sys_…`.

## Supply Chain

Add vendors one at a time or import CSV (`name,domain[,criticality[,category]]`).
Scans run every `INTEL_SWEEP_HOURS` with the other modules, or on demand
(`POST /intel/scan/vendors`). Vendor domains need no ownership verification:
every check is passive and limited to what any visitor or mail server does.

| Area | Check | Penalty (cap) |
|---|---|---|
| Breach | Named on a ransomware leak site (ransomware.live search + recent feeds) | 40 within a year, else 15 (45) |
| Threat feeds | Domain or web IP on Feodo Tracker / ThreatFox (URLhaus ignored: it lists malware *hosted on* shared platforms) | 30 (30) |
| Vulnerabilities | CISA KEV CVE on a web IP (InternetDB); other CVEs | 25 each; 2 each ≤ 15 (40) |
| Exposed services | Critical/high-risk port on a web IP (RDP, SMB, databases…) | 15 / 6 (30) |
| Web TLS | Grade from one handshake with the apex (or www) | B 3, C 8, D 15, F 25 (25) |
| Email & DNS | SPF, DMARC (skipped when the domain has no MX), DNSSEC, NS redundancy | 12 critical, 4 warning (25) |
| Your leaks | Vendor domain or staff emails in your collected leaks | 5 each (15) |

Score = 100 − penalties. Grades A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F. Each
scan appends to the vendor's score history (last 30). A new leak-site post
raises a critical notification, goes to `SOAR_WEBHOOK_URL` as `VENDOR_BREACH`,
and opens an incident. A grade drop raises an info notification.
