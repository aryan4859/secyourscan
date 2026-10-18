# External Risk

Four modules look at your organisation from the outside, the way an attacker
would. Each runs every `INTEL_SWEEP_HOURS` (default 6) for every tenant with
active watch items, and on demand from its page (**Scan now**, `POST
/intel/scan/{module}`, scope `recon`). Findings raise ordinary
notifications; critical ones also go to `SOAR_WEBHOOK_URL`. Every feed is
keyless.

| Module | Page | Input | Data sources | Alerts on |
|---|---|---|---|---|
| `surface` | Attack Surface | domain watch items | crt.sh + Cert Spotter, HackerTarget passive DNS, Wayback Machine, AlienVault OTX (optional key), common-name DNS check; Shodan InternetDB; TLS on 443; abuse.ch URLhaus, Feodo Tracker, ThreatFox | new hosts; a host or IP listed in a threat feed; certificates expiring within 30 days |
| `vulns` | Vulnerabilities | surface hosts + IP watch items | InternetDB CVEs, CISA KEV, FIRST EPSS | a CVE newly in KEV on one of your hosts |
| `brand` | Brand Protection | domain watch items | generated permutations, DNS (A, MX), crt.sh; OpenPhish and PhishStats phishing URLs | a lookalike reaching risk ≥ 70; a live phishing URL using your brand |
| `ransomware` | Ransomware Watch | domain and keyword watch items | ransomware.live search and recent victims, RansomLook recent posts | any leak-site post naming you |

Each page lists its sources and what each returned in the last scan, so an
empty result can be told apart from a source that failed.

A `surface` scan refreshes `vulns` when it finishes.

## Attack surface

Hostnames under each watched domain are collected from every discovery
source at once — one failing never sinks the others — and each host records
which sources found it. Certificate transparency alone misses everything
behind a wildcard certificate (`*.example.com`); passive DNS (HackerTarget,
50 free lookups a day; OTX with a free `OTX_API_KEY`), the Wayback Machine
and a check of ~170 common names (`SURFACE_DNS_BRUTEFORCE`, skipping wildcard
DNS answers) fill that gap. Up to `SURFACE_MAX_HOSTS` per domain are then
resolved, and for public addresses
enriched with InternetDB's open ports, CPEs, tags and CVEs. The certificate
served on port 443 is read, not trusted, so expired and self-signed ones still
show their dates. The first scan of a tenant does not alert on "new" hosts.

Only certificate logs and DNS are queried, plus one TLS handshake per live
host. There is no port scanning: ports come from Shodan's existing data.

**Threat-feed reputation.** The abuse.ch URLhaus, Feodo Tracker and ThreatFox
feeds are downloaded whole and matched locally against every discovered host
and IP, so nothing about your assets is sent to them. A listing usually means
a compromised server (serving malware, or acting as botnet C2) and raises a
critical alert.

## Vulnerabilities

Priority is `critical` when the CVE is in CISA's Known Exploited
Vulnerabilities catalogue, `high` at EPSS ≥ 0.5, `medium` at EPSS ≥ 0.1,
otherwise `low`. A finding that disappears from a later scan is marked
`fixed`, and reopens if it returns. InternetDB infers CVEs from banners, so
backported fixes produce false positives; mark them **accept risk**.

## Brand protection

For the registrable part of each watched domain (`jbbl` in `jbbl.com.np`),
up to `LOOKALIKE_MAX_CANDIDATES` permutations are generated: homoglyphs,
omission, transposition, keyboard replacement, repetition, vowel swaps,
hyphenation, insertion, combosquatting (`name-login`, `secure-name`, …), TLD
swaps and additions. Only domains that exist in DNS are stored.

Risk = 30 for existing, +25 web server (A), +20 mail (MX), +15 certificate,
+10 for close-typo or combosquat techniques, capped at 100. Lookalike sites are
never fetched. Track takedowns with the status column.

**Phishing URLs.** The OpenPhish community feed is matched for your brand
label (at least 4 characters), your domains and every registered lookalike;
PhishStats is searched for the brand label and lookalikes. URLs on your real
domains are skipped.

## Ransomware watch

Each domain (and its brand label if at least 5 characters long) and each
keyword of at least 4 characters is searched on ransomware.live; the hourly
recent-victims feed is matched too, so new posts are caught quickly. A hit is
stored once per group and victim. The page also shows the most active groups
and latest posts worldwide.

## Configuration

| Variable | Default |
|---|---|
| `CRTSH_URL` | `https://crt.sh/` |
| `CERTSPOTTER_URL` | `https://api.certspotter.com/v1/issuances` |
| `RANSOMWARE_LIVE_URL` | `https://api.ransomware.live/v2` |
| `KEV_URL` | CISA's `known_exploited_vulnerabilities.json` |
| `EPSS_URL` | `https://api.first.org/data/v1/epss` |
| `HACKERTARGET_URL` | `https://api.hackertarget.com/hostsearch/` |
| `WAYBACK_CDX_URL` | `https://web.archive.org/cdx/search/cdx` |
| `OTX_API_KEY` | unset (OTX passive DNS off) |
| `SURFACE_DNS_BRUTEFORCE` | `true` |
| `URLHAUS_RECENT_URL`, `FEODO_URL`, `THREATFOX_RECENT_URL` | abuse.ch public exports |
| `OPENPHISH_URL` | `https://openphish.com/feed.txt` |
| `PHISHSTATS_URL` | `https://api.phishstats.info/api/phishing` |
| `RANSOMLOOK_URL` | `https://www.ransomlook.io/api` |
| `INTEL_SWEEP_HOURS` | `6` |
| `SURFACE_MAX_HOSTS` | `300` |
| `LOOKALIKE_MAX_CANDIDATES` | `400` |
