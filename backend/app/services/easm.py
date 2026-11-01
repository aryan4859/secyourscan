"""External attack surface and vulnerability intelligence.

Surface: every hostname under a watched domain that appears in certificate
transparency (crt.sh, Cert Spotter as fallback), resolved, with Shodan
InternetDB ports/CVEs for its public IPs and the TLS certificate it serves.

Vulnerabilities: the CVEs InternetDB reports for those hosts (and for watched
IPs), ranked by CISA KEV — exploited in the wild — and FIRST EPSS — the
probability of exploitation in the next 30 days.

Every network call is a module-level function so tests can patch it.
"""

import asyncio
import ipaddress
import logging
import re
import ssl
from datetime import timedelta

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from cryptography import x509
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import SurfaceHost, VulnFinding, WatchItem, utcnow
from . import asm, cti, reputation

logger = logging.getLogger("secyourscan.easm")

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
UA = {"User-Agent": "SecYourScan-EASM/1.0 (+self-hosted exposure monitoring)"}
MAX_IPS = 150
MAX_TLS = 150
KEV_TTL = timedelta(hours=24)
CERT_WARN_DAYS = 30


# ── Network primitives (patched in tests) ────────────────────────────────────


async def ct_names(domain: str) -> set[str]:
    """Hostnames under ``domain`` seen in certificate transparency."""
    names: set[str] = set()
    async with httpx.AsyncClient(timeout=60, headers=UA, follow_redirects=True) as c:
        for attempt in range(3):
            try:
                r = await c.get(settings.CRTSH_URL, params={"q": domain, "output": "json"})
                if r.status_code == 200:
                    for row in r.json():
                        for n in str(row.get("name_value", "")).split("\n"):
                            names.add(n)
                    break
            except (httpx.HTTPError, ValueError) as exc:
                logger.info("crt.sh attempt %d for %s failed: %s", attempt + 1, domain, exc)
            await asyncio.sleep(2 * (attempt + 1))
        # Cert Spotter as well: crt.sh is often overloaded and returns partial results.
        try:
            r = await c.get(settings.CERTSPOTTER_URL, params={"domain": domain, "include_subdomains": "true",
                                                              "expand": "dns_names"})
            if r.status_code == 200:
                for row in r.json():
                    names.update(row.get("dns_names", []))
        except (httpx.HTTPError, ValueError) as exc:
            logger.info("Cert Spotter for %s failed: %s", domain, exc)
    return _clean(names, domain)


def _clean(names, domain: str) -> set[str]:
    out = set()
    for n in names:
        n = str(n).strip().lower().lstrip("*.").rstrip(".")
        if (n == domain or n.endswith("." + domain)) and _HOST_RE.match(n):
            out.add(n)
    return out


async def hackertarget_hosts(domain: str) -> set[str]:
    """Passive DNS. Free tier: 50 queries a day per source IP."""
    async with httpx.AsyncClient(timeout=30, headers=UA) as c:
        r = await c.get(settings.HACKERTARGET_URL, params={"q": domain})
        if r.status_code != 200 or "," not in r.text:  # errors come back as plain text with 200
            return set()
        return _clean((line.split(",")[0] for line in r.text.splitlines()), domain)


async def wayback_hosts(domain: str) -> set[str]:
    """Hostnames the Internet Archive has crawled under the domain."""
    from urllib.parse import urlsplit

    async with httpx.AsyncClient(timeout=60, headers=UA) as c:
        r = await c.get(settings.WAYBACK_CDX_URL, params={"url": domain, "matchType": "domain", "fl": "original",
                                                          "collapse": "urlkey", "limit": 5000})
        if r.status_code != 200:
            return set()
        hosts = set()
        for line in r.text.splitlines():
            try:
                hosts.add(urlsplit(line.strip() if "://" in line else f"http://{line.strip()}").hostname or "")
            except ValueError:
                continue
        return _clean(hosts, domain)


async def otx_hosts(domain: str) -> set[str]:
    """AlienVault OTX passive DNS; needs a free OTX_API_KEY."""
    if not settings.OTX_API_KEY:
        return set()
    async with httpx.AsyncClient(timeout=30, headers={**UA, "X-OTX-API-KEY": settings.OTX_API_KEY}) as c:
        r = await c.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
        if r.status_code != 200:
            return set()
        return _clean((x.get("hostname", "") for x in r.json().get("passive_dns", [])), domain)


SUBDOMAIN_WORDS = (
    "www mail webmail smtp imap pop mx mx1 autodiscover owa exchange vpn sslvpn remote rdp citrix gateway portal "
    "api api2 dev test uat qa staging stage beta demo sandbox admin cms intranet extranet hr erp crm sso auth login id "
    "secure support help status cdn static assets img docs blog shop careers jobs app apps m mobile ns1 ns2 dns git "
    "gitlab jenkins jira confluence wiki monitor grafana kibana db backup files ftp sftp cloud office meet video chat "
    "ticket servicedesk payroll finance pay payment payments card cards atm loan loans remit remittance forex trade "
    "demat invest ir news survey forms onlineforms eservices services onlineservices digital smart wallet qr kyc ekyc "
    "ebanking ibanking netbanking mbanking mobilebanking onlinebanking corporate cib swift internetbanking banking "
    "partner partners vendor b2b proxy old new v2 legacy"
).split()


async def dns_bruteforce(domain: str) -> set[str]:
    """Common subdomain names that resolve. If the zone has wildcard DNS, names
    resolving only to the wildcard's addresses are ignored."""
    import secrets

    wildcard = set(await resolve_a(f"{secrets.token_hex(8)}.{domain}"))
    found = await _gather_limited(30, [f"{w}.{domain}" for w in SUBDOMAIN_WORDS], resolve_a)
    return {h for h, ips in found.items() if ips and not (wildcard and set(ips) <= wildcard)}


DISCOVERY = ("crt.sh", "hackertarget", "wayback", "otx", "dns")


async def discover_hosts(domain: str, status: dict | None = None) -> dict[str, list[str]]:
    """{hostname: [sources that found it]} from every discovery source; one
    failing source never sinks the others. ``status`` (if given) accumulates
    each source's outcome: hosts found, "error" or "disabled"."""
    found: dict[str, set[str]] = {domain: {"watchlist"}}

    fns = {"crt.sh": ct_names, "hackertarget": hackertarget_hosts, "wayback": wayback_hosts, "otx": otx_hosts,
           "dns": dns_bruteforce}

    async def run(name):
        try:
            return name, await fns[name](domain), None
        except Exception as exc:  # noqa: BLE001
            logger.info("%s discovery for %s failed: %s", name, domain, exc)
            return name, set(), "error"

    disabled = {n for n, off in (("otx", not settings.OTX_API_KEY), ("dns", not settings.SURFACE_DNS_BRUTEFORCE)) if off}
    status = status if status is not None else {}
    for name in disabled:
        status.setdefault(name, "disabled")
    for name, hosts, err in await asyncio.gather(*(run(n) for n in DISCOVERY if n not in disabled)):
        prev = status.get(name)
        status[name] = err if err and not isinstance(prev, int) else (prev if isinstance(prev, int) else 0) + len(hosts)
        for h in hosts:
            found.setdefault(h, set()).add(name)
    return {h: sorted(s) for h, s in found.items()}


async def resolve_a(host: str) -> list[str]:
    r = dns.asyncresolver.Resolver()
    r.lifetime = 5
    try:
        ans = await r.resolve(host, "A")
        return sorted({a.to_text() for a in ans})
    except (dns.exception.DNSException, OSError):
        return []


async def internetdb(ip: str) -> dict:
    try:
        return await cti.shodan_internetdb(ip)
    except Exception as exc:  # noqa: BLE001 — one bad IP must not stop the scan
        logger.info("InternetDB %s failed: %s", ip, exc)
        return {}


async def tls_cert(host: str) -> dict | None:
    """Issuer and expiry of the certificate ``host`` serves on 443. The cert is
    read, not trusted: verification is off so expired ones are still seen."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, 443, ssl=ctx, server_hostname=host), 6)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
        cn = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME) or \
            cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return {"issuer": cn[0].value if cn else cert.issuer.rfc4514_string()[:255],
                "not_after": cert.not_valid_after_utc.replace(tzinfo=None)}
    except Exception:  # noqa: BLE001
        return None
    finally:
        writer.close()


async def kev_catalog() -> dict[str, dict]:
    async with httpx.AsyncClient(timeout=60, headers=UA) as c:
        r = await c.get(settings.KEV_URL)
        r.raise_for_status()
        return {v["cveID"]: {"added": v.get("dateAdded"), "name": (v.get("vulnerabilityName") or "")[:255],
                             "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                             # vendor/product/description/due feed vulnerability intelligence
                             "vendor": (v.get("vendorProject") or "")[:120], "product": (v.get("product") or "")[:120],
                             "description": (v.get("shortDescription") or "")[:600], "due": v.get("dueDate"),
                             "action": (v.get("requiredAction") or "")[:300]}
                for v in r.json().get("vulnerabilities", [])}


async def epss_scores(cves: list[str]) -> dict[str, tuple[float, float]]:
    out: dict[str, tuple[float, float]] = {}
    async with httpx.AsyncClient(timeout=30, headers=UA) as c:
        for i in range(0, len(cves), 100):
            try:
                r = await c.get(settings.EPSS_URL, params={"cve": ",".join(cves[i:i + 100])})
                r.raise_for_status()
                for row in r.json().get("data", []):
                    out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                logger.info("EPSS batch failed: %s", exc)
    return out


# ── Scans ────────────────────────────────────────────────────────────────────


def _public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_reserved or a.is_link_local or a.is_multicast)


async def _gather_limited(n: int, items, fn):
    sem = asyncio.Semaphore(n)

    async def one(x):
        async with sem:
            return x, await fn(x)

    return dict(await asyncio.gather(*(one(x) for x in items)))


async def scan_surface(db: AsyncSession, tenant_id: str) -> dict:
    from .domains import in_scope

    domains = await in_scope(db, tenant_id, (await db.execute(select(WatchItem.value).where(
        WatchItem.tenant_id == tenant_id, WatchItem.type == "domain", WatchItem.is_active.is_(True)))).scalars().all())
    existing = {h.hostname: h for h in (await db.execute(
        select(SurfaceHost).where(SurfaceHost.tenant_id == tenant_id))).scalars()}
    first_scan = not existing
    now = utcnow()
    hosts: dict[str, str] = {}
    found_by: dict[str, list[str]] = {}
    per_source: dict[str, int] = {}
    source_status: dict = {}
    for d in domains:
        names = await discover_hosts(d, source_status)
        for n in sorted(names, key=lambda x: (x != d, len(x), x))[: settings.SURFACE_MAX_HOSTS]:
            hosts.setdefault(n, d)
            found_by[n] = sorted(set(found_by.get(n, [])) | set(names[n]))
            for s in names[n]:
                per_source[s] = per_source.get(s, 0) + 1

    resolved = await _gather_limited(30, list(hosts), resolve_a)
    ips = sorted({ip for v in resolved.values() for ip in v if _public(ip)})[:MAX_IPS]
    idb = await _gather_limited(5, ips, internetdb)
    live = [h for h, v in resolved.items() if v][:MAX_TLS]
    certs = await _gather_limited(20, live, tls_cert)
    listings = await reputation.check(list(hosts), ips)

    new = 0
    new_threats = []
    events: list[dict] = []
    for name, root in hosts.items():
        h = existing.get(name)
        before = None if h is None else {"resolves": h.resolves, "ips": list(h.ips or []), "ports": list(h.ports or []),
                                         "tls_not_after": h.tls_not_after.isoformat() if h.tls_not_after else None}
        if h is None:
            h = SurfaceHost(tenant_id=tenant_id, hostname=name, root_domain=root, first_seen=now)
            db.add(h)
            new += 1
        addrs = resolved.get(name, [])
        # Shared CDN edges: their InternetDB ports/CPEs/CVEs describe other
        # customers' sites, so only the host's own (origin) IPs count.
        cdns = {cdn for ip in addrs if (cdn := asm.cdn_provider(ip, (idb.get(ip) or {}).get("tags")))}
        info = [idb.get(ip) or {} for ip in addrs if not asm.cdn_provider(ip, (idb.get(ip) or {}).get("tags"))]
        h.ips = addrs
        h.resolves = bool(addrs)
        h.ports = sorted({p for i in info for p in i.get("ports", [])})
        h.cves = sorted({v for i in info for v in i.get("vulns", [])})
        h.cpes = sorted({c for i in info for c in i.get("cpes", [])})[:50]
        h.tags = sorted({t for i in info for t in i.get("tags", [])} | {f"cdn:{c}" for c in cdns})
        h.sources = found_by.get(name, [])
        threats = listings.get(name, []) + [t for ip in addrs for t in listings.get(ip, [])]
        known = {(t["feed"], t.get("indicator")) for t in (h.threats or [])}
        new_threats += [f"{name}: {t['feed']} ({t.get('malware') or t.get('threat')})" for t in threats
                        if (t["feed"], t.get("indicator")) not in known]
        h.threats = threats
        cert = certs.get(name)
        if cert:
            h.tls_issuer, h.tls_not_after = cert["issuer"], cert["not_after"]
        h.last_seen = now
        if not first_scan:
            after = {"resolves": h.resolves, "ips": h.ips, "ports": h.ports,
                     "tls_not_after": h.tls_not_after.isoformat() if h.tls_not_after else None}
            for ev in asm.host_events(tenant_id, name, before, after, now):
                db.add(ev)
                events.append({"subject": ev.subject, "kind": ev.kind, "severity": ev.severity, "detail": ev.detail})
    await db.commit()
    expiring = sum(1 for h in hosts if (c := certs.get(h)) and c["not_after"] - now <= timedelta(days=CERT_WARN_DAYS))
    return {"domains": len(domains), "hosts": len(hosts), "new": 0 if first_scan else new, "live": len(live),
            "ips": len(ips), "expiring_certs": expiring, "sources": per_source, "source_status": source_status,
            "new_threats": new_threats, "events": events, "live_hosts": live,
            "feeds": listings.get("_feeds", {})}


def _priority(kev: bool, epss: float | None) -> str:
    if kev:
        return "critical"
    if epss is not None and epss >= 0.5:
        return "high"
    if epss is not None and epss >= 0.1:
        return "medium"
    return "low"


async def scan_vulns(db: AsyncSession, tenant_id: str, kev: dict[str, dict]) -> dict:
    """``kev`` is the cached KEV catalogue (see intel.kev)."""
    pairs: dict[tuple[str, str], str | None] = {}
    for h in (await db.execute(select(SurfaceHost).where(SurfaceHost.tenant_id == tenant_id,
                                                         SurfaceHost.resolves.is_(True)))).scalars():
        for cve in h.cves or []:
            pairs[(h.hostname, cve)] = (h.ips or [None])[0]
    watched_ips = (await db.execute(select(WatchItem.value).where(
        WatchItem.tenant_id == tenant_id, WatchItem.type == "ip", WatchItem.is_active.is_(True)))).scalars().all()
    for ip, info in (await _gather_limited(5, [i for i in watched_ips if _public(i) and not asm.cdn_provider(i)],
                                           internetdb)).items():
        if asm.cdn_provider(ip, info.get("tags")):
            continue
        for cve in info.get("vulns", []):
            pairs[(ip, cve)] = ip

    scores = await epss_scores(sorted({c for _, c in pairs}))
    existing = {(f.host, f.cve): f for f in (await db.execute(
        select(VulnFinding).where(VulnFinding.tenant_id == tenant_id))).scalars()}
    now = utcnow()
    new_kev = []
    for (host, cve), ip in pairs.items():
        f = existing.get((host, cve))
        if f is None:
            f = VulnFinding(tenant_id=tenant_id, host=host, cve=cve, first_seen=now)
            db.add(f)
        k = kev.get(cve)
        epss, pct = scores.get(cve, (None, None))
        if k and not f.kev:
            new_kev.append(f"{cve} on {host}")
        f.ip, f.kev, f.epss, f.percentile = ip, bool(k), epss, pct
        f.kev_added, f.kev_name, f.kev_ransomware = (k or {}).get("added"), (k or {}).get("name"), bool((k or {}).get("ransomware"))
        f.priority = _priority(bool(k), epss)
        if f.status == "fixed":
            f.status = "open"  # it came back
        f.last_seen = now
    fixed = withdrawn = 0
    for key, f in existing.items():
        if key in pairs:
            continue
        if asm.cdn_provider(f.ip):
            # Never real: inferred from a shared CDN edge. Remove it and close
            # the incident it opened instead of reporting it as "fixed".
            await _withdraw(db, tenant_id, f)
            withdrawn += 1
        elif f.status == "open":
            f.status = "fixed"
            fixed += 1
    await db.commit()
    return {"findings": len(pairs), "kev": sum(1 for (_, c) in pairs if c in kev), "new_kev": new_kev, "fixed": fixed,
            "withdrawn": withdrawn}


async def _withdraw(db: AsyncSession, tenant_id: str, f: VulnFinding) -> None:
    from ..models import Incident, IncidentEvent

    inc = await db.scalar(select(Incident).where(Incident.tenant_id == tenant_id, Incident.source_type == "vuln",
                                                 Incident.source_id == f.id))
    if inc is not None and inc.status not in ("resolved", "false_positive"):
        now = utcnow()
        inc.status, inc.resolved_at, inc.updated_at = "false_positive", now, now
        inc.acknowledged_at = inc.acknowledged_at or now
        db.add(IncidentEvent(incident_id=inc.id, kind="status", actor="system", at=now,
                             body=f"Closed as false positive: {f.cve} was inferred from shared CDN IP {f.ip}, "
                                  "not from this host."))
    await db.delete(f)
