"""Supply-chain (third-party) risk: an outside-in rating of each vendor.

Vendors are not the tenant's assets, so every check is passive and of the
kind any visitor or mail server performs: public DNS records, one TLS
handshake with the vendor's website, Shodan InternetDB's existing data for
its web IPs, public threat-feed listings and ransomware leak-site posts.
Nothing is port-scanned or probed beyond that.

Score starts at 100 and loses points per finding, capped per area so one
noisy area cannot zero a vendor on its own. Grade: A ≥ 90, B ≥ 80, C ≥ 70,
D ≥ 60, else F.
"""

import asyncio
import logging
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Leak, Vendor, utcnow
from . import asm, easm, ransomware, reputation
from .brand import split_domain

logger = logging.getLogger("secyourscan.vendors")
MAX_VENDORS = 200
AREA_CAP = {"email": 25, "tls": 25, "network": 30, "vulns": 40, "reputation": 30, "breach": 45, "leaks": 15}
HISTORY = 30


def registrable(domain: str) -> str:
    d = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0].rstrip(".")
    return ".".join(split_domain(d.removeprefix("www.")))


def letter(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


async def _safe(coro, default):
    try:
        return await coro
    except Exception as exc:  # noqa: BLE001 — one failed check must not fail the vendor
        logger.info("vendor check failed: %s", exc)
        return default


async def _dns(domain: str) -> list[dict]:
    records = {rt: await _safe(asm.lookup(domain, rt), []) for rt in ("TXT", "NS", "CAA", "MX")}
    dmarc = await _safe(asm.lookup(f"_dmarc.{domain}", "TXT"), [])
    dnssec = await _safe(asm.has_dnssec(domain), False)
    out = []
    for c in asm.posture(records, dmarc, dnssec):
        if c["ok"] or c["severity"] == "info":
            continue
        if not records["MX"] and c["check"].startswith(("SPF", "DMARC")):
            continue  # a domain that receives no mail has less to lose from spoofing
        penalty = 12 if c["severity"] == "critical" else 4
        out.append({"area": "email", "severity": "high" if c["severity"] == "critical" else "low",
                    "title": c["check"], "detail": c["detail"], "penalty": penalty})
    return out


async def _tls(domain: str) -> tuple[list[dict], str | None]:
    host = domain
    facts = await _safe(asm.probe_tls(domain), None)
    if facts is None:
        host = f"www.{domain}"
        facts = await _safe(asm.probe_tls(host), None)
    if facts is None:
        return [], None
    grade, issues = asm.grade(facts)
    penalty = {"A": 0, "B": 3, "C": 8, "D": 15, "F": 25}.get(grade, 0)
    if not penalty:
        return [], grade
    return [{"area": "tls", "severity": "high" if grade in ("D", "F") else "medium" if grade == "C" else "low",
             "title": f"Website TLS graded {grade}", "penalty": penalty,
             "detail": f"{host}: " + "; ".join(i["text"] for i in issues[:3])}], grade


async def _network(ips: list[str], kev: dict) -> tuple[list[dict], dict]:
    findings, seen = [], {"ports": set(), "cves": set()}
    for ip in ips[:4]:
        data = await _safe(easm.internetdb(ip), {})
        for p in data.get("ports") or []:
            info = asm.classify_port(p)
            if p in seen["ports"]:
                continue
            seen["ports"].add(p)
            if info["risk"] in ("critical", "high"):
                findings.append({"area": "network", "severity": info["risk"], "penalty": 15 if info["risk"] == "critical" else 6,
                                 "title": f"{info['service']} ({p}) exposed", "detail": f"{ip}: {info['why']}"})
        for cve in data.get("vulns") or []:
            if cve in seen["cves"]:
                continue
            seen["cves"].add(cve)
            if cve in kev:
                findings.append({"area": "vulns", "severity": "critical", "penalty": 25,
                                 "title": f"{cve} (actively exploited)", "detail": f"{ip}: {kev[cve].get('name') or 'in CISA KEV'}"})
    other = sorted(c for c in seen["cves"] if c not in kev)
    if other:
        findings.append({"area": "vulns", "severity": "medium", "penalty": min(15, 2 * len(other)),
                         "title": f"{len(other)} other known CVE(s) on web hosts", "detail": ", ".join(other[:12])})
    return findings, {"ports": sorted(seen["ports"]), "cves": sorted(seen["cves"])}


async def _breaches(vendor: Vendor, domain: str, recent: list[dict]) -> list[dict]:
    terms = [(domain, "domain")]
    name = vendor.name.strip().lower()
    if len(name) >= 5 and name != domain:
        terms.append((name, "name"))
    found: dict[tuple[str, str], dict] = {}
    for term, how in terms:
        posts = await _safe(ransomware.search_victims(term), [])
        for p in posts + recent:
            if ransomware._matches(p, term, how):
                group = str(p.get("group") or p.get("group_name") or "unknown")[:64]
                victim = str(p.get("victim") or p.get("post_title") or "")[:255]
                when = ransomware._date(p.get("attackdate") or p.get("discovered"))
                found.setdefault((group, victim), {"group": group, "victim": victim,
                                                   "date": when.isoformat() if when else None,
                                                   "url": p.get("url") or p.get("post_url")})
    return list(found.values())


async def _leak_mentions(db: AsyncSession, tenant_id: str, domain: str) -> int:
    n = 0
    for ents in (await db.execute(select(Leak.entities).where(Leak.tenant_id == tenant_id)
                                  .order_by(Leak.discovered_at.desc()).limit(5000))).scalars():
        ents = ents or {}
        if domain in [str(d).lower() for d in ents.get("domains", [])] or \
                any(str(e).lower().endswith("@" + domain) for e in ents.get("emails", [])):
            n += 1
    return n


def rate(findings: list[dict]) -> int:
    by_area: dict[str, int] = {}
    for f in findings:
        by_area[f["area"]] = by_area.get(f["area"], 0) + f["penalty"]
    return max(0, 100 - sum(min(v, AREA_CAP.get(a, 30)) for a, v in by_area.items()))


async def scan_vendors(db: AsyncSession, tenant_id: str, kev: dict, recent: list[dict]) -> dict:
    vendors = (await db.execute(select(Vendor).where(Vendor.tenant_id == tenant_id).order_by(Vendor.created_at)
                                .limit(MAX_VENDORS))).scalars().all()
    if not vendors:
        return {"vendors": 0, "new_breaches": [], "downgraded": []}

    # Pass 1: per-vendor DNS/TLS/network, in parallel across a few vendors at a time.
    sem = asyncio.Semaphore(4)

    async def gather_one(v: Vendor):
        async with sem:
            domain = registrable(v.domain)
            ips = sorted(set(await _safe(easm.resolve_a(domain), [])) | set(await _safe(easm.resolve_a(f"www.{domain}"), [])))
            dns_f, (tls_f, tls_grade), (net_f, net) = await asyncio.gather(_dns(domain), _tls(domain), _network(ips, kev))
            return v, domain, ips, dns_f + tls_f + net_f, tls_grade, net

    gathered = await asyncio.gather(*(gather_one(v) for v in vendors))

    # Pass 2: one download of the threat feeds for every vendor's hosts and IPs.
    all_hosts = [h for _, d, _, _, _, _ in gathered for h in (d, f"www.{d}")]
    all_ips = [ip for _, _, ips, _, _, _ in gathered for ip in ips]
    listings = await _safe(reputation.check(all_hosts, all_ips), {"_feeds": {}})

    now = utcnow()
    new_breaches, downgraded = [], []
    for v, domain, ips, findings, tls_grade, net in gathered:
        for key in (domain, f"www.{domain}", *ips):
            # URLhaus lists malware *hosted on* big shared platforms (github.com, drive.google.com…);
            # that says nothing about the vendor being compromised, so only C2/IOC feeds count here.
            for entry in [e for e in listings.get(key, []) if e.get("feed") != "urlhaus"]:
                findings.append({"area": "reputation", "severity": "critical", "penalty": 30,
                                 "title": f"Listed by {entry['feed']}", "detail": f"{key}: {entry.get('threat') or ''} "
                                                                                  f"{entry.get('malware') or ''}".strip()})
        breaches = await _breaches(v, domain, recent)
        known = {(b.get("group"), b.get("victim")) for b in v.breaches or []}
        for b in breaches:
            when = ransomware._date(b["date"]) if b.get("date") else None
            fresh = when is None or now - when <= timedelta(days=365)
            findings.append({"area": "breach", "severity": "critical" if fresh else "high", "penalty": 40 if fresh else 15,
                             "title": f"Named by {b['group']} on a ransomware leak site",
                             "detail": f"“{b['victim']}”" + (f", {when.date().isoformat()}" if when else "")})
            if (b["group"], b["victim"]) not in known:
                new_breaches.append(f"{v.name}: {b['group']} ({b['victim']})")
        mentions = await _leak_mentions(db, tenant_id, domain)
        if mentions:
            findings.append({"area": "leaks", "severity": "medium", "penalty": min(15, 5 * mentions),
                             "title": f"Appears in {mentions} of your leak findings",
                             "detail": "Vendor domain or staff emails found in collected leak material."})

        score = rate(findings)
        grade = letter(score)
        if v.grade and "ABCDF".index(grade) > "ABCDF".index(v.grade):
            downgraded.append(f"{v.name}: {v.grade} → {grade}")
        findings.sort(key=lambda f: (-f["penalty"], f["area"]))
        v.findings = findings
        v.facts = {"domain": domain, "ips": ips, **net, "tls_grade": tls_grade}
        v.breaches = sorted({(b["group"], b["victim"]): b for b in [*(v.breaches or []), *breaches]}.values(),
                            key=lambda b: b.get("date") or "", reverse=True)
        v.score, v.grade, v.last_scanned_at = score, grade, now
        v.history = [*(v.history or []), {"at": now.isoformat(), "score": score, "grade": grade}][-HISTORY:]
    await db.commit()
    return {"vendors": len(vendors), "new_breaches": new_breaches, "downgraded": downgraded,
            "feeds": listings.get("_feeds", {})}
