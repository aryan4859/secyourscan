# Customer Onboarding

A checklist for installing SecYourScan on a customer's own infrastructure
and getting to a first useful report in under an hour.

## 1. Requirements

| | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 60 GB SSD | 200 GB SSD |
| OS | Linux with Docker Engine 24+ and the compose plugin | Ubuntu 22.04/24.04 LTS |
| Network | Outbound HTTPS to the feeds in [External Risk](/guide/external-risk); outbound Tor (9001/443) for dark-web collection | |

The stack listens only on `127.0.0.1:8080`. Put the customer's reverse proxy
(TLS, SSO if they have it) in front of it.

## 2. Install

```bash
git clone <your release repository> secyourscan && cd secyourscan
./scripts/install.sh --admin-email secops@customer.com \
    --license-key SYS1.xxxxx \
    --public-host scan.customer.com
```

The script checks prerequisites, generates every secret, installs the
licence, builds and starts the containers and waits until the API is healthy.
Re-running it upgrades in place and never overwrites secrets.

## 3. Licence

Licences are signed by the vendor and verified offline; nothing phones home.

- `Settings → Licence` (or `GET /system/license`) shows customer, expiry,
  domain allowance and usage.
- An expired or invalid licence stops new scans; all data stays readable.
- To renew, set the new `LICENSE_KEY` in `.env` and run `docker compose up -d`.

Vendor side (keep the private key in your vault, never on customer machines):

```bash
python scripts/license_tool.py keygen --out vendor_license_key.pem   # once; prints LICENSE_PUBLIC_KEY
python scripts/license_tool.py issue --key vendor_license_key.pem --customer "Acme Bank" --days 365 --max-domains 5
```

Release builds set `LICENSE_PUBLIC_KEY`; with it unset, licensing is off.

## 4. First hour

1. **Sign in** and change the admin password (Settings).
2. **Domains** — add each root domain and publish the TXT record shown.
   Scans cover only verified domains (`REQUIRE_DOMAIN_VERIFICATION`).
3. **Watchlist** — add domains, executive and service mailboxes (mark VIPs),
   brand keywords, public IPs and wallets.
4. **Attack Surface → Scan now**, then **Brand Protection** and
   **Ransomware Watch → Scan now**. After that every module re-runs every
   six hours.
5. **Exposure Report** — export the PDF; it is the natural kick-off
   deliverable for the customer.
6. Optional: `OTX_API_KEY` (free) for more subdomains; `SOAR_WEBHOOK_URL` for
   alerts into the customer's SIEM/SOAR.

## 5. Operations

| Task | Command |
|---|---|
| Status | `docker compose ps` |
| Logs | `docker compose logs -f api worker-pipeline` |
| Upgrade | pull the new release, then `./scripts/install.sh` |
| Backup | `docker compose exec db pg_dump -U sys secyourscan > backup.sql` plus the `secrets/` directory and `.env` |
| Audit integrity | Audit → Verify chain |

## 6. Data protection

Collected material can contain personal data. Before going live, agree with
the customer on the lawful basis, a retention period and who may see raw
evidence. SecYourScan masks secrets in everything it displays and keeps the
unmasked original only in the customer's own object storage.
