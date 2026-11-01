"""Vulnerability intelligence: the CVEs that matter to *this* tenant.

Feeds (shared by all tenants, cached in ``intel_cache``):
  * CISA KEV — exploited in the wild, with vendor/product and due date;
  * NVD — CVEs published recently with CVSS v3 ≥ 7, with the CPEs they affect;
  * FIRST EPSS — probability of exploitation in the next 30 days.

The tenant's technology stack is what it declares (vendor / product /
version) plus what the attack-surface scan fingerprinted on its hosts (CPEs).
Every feed entry is matched against that stack by vendor and product; version
ranges are not evaluated, so a match reads "potentially affected — confirm the
version".
"""

import logging
import re
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import SurfaceHost, utcnow
from . import easm, incidents, intel

logger = logging.getLogger("secyourscan.vulnintel")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DAYS = 30
NVD_TTL = timedelta(hours=6)
MAX_STACK = 200
_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def norm(s: str | None) -> str:
    return _TOKEN_RE.sub("_", (s or "").lower()).strip("_")


def parse_cpe(cpe: str) -> dict | None:
    """``cpe:/a:nginx:nginx:1.18.0`` or ``cpe:2.3:a:nginx:nginx:1.18.0:*…``."""
    parts = cpe.split(":")
    if cpe.startswith("cpe:2.3:") and len(parts) >= 6:
        vendor, product, version = parts[3], parts[4], parts[5]
    elif cpe.startswith("cpe:/") and len(parts) >= 4:
        vendor, product = parts[2], parts[3]
        version = parts[4] if len(parts) > 4 else ""
    else:
        return None
    version = "" if version in ("*", "-") else version
    return {"vendor": vendor.replace("\\", ""), "product": product.replace("\\", ""), "version": version}


# ── Feeds ────────────────────────────────────────────────────────────────────


async def fetch_nvd(days: int = NVD_DAYS) -> list[dict]:
    end = utcnow()
    start = end - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    headers = dict(easm.UA)
    if getattr(settings, "NVD_API_KEY", None):
        headers["apiKey"] = settings.NVD_API_KEY
    out: list[dict] = []
    async with httpx.AsyncClient(timeout=90, headers=headers) as c:
        for sev in ("CRITICAL", "HIGH"):
            r = await c.get(NVD_URL, params={"pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt),
                                             "cvssV3Severity": sev, "resultsPerPage": 2000})
            r.raise_for_status()
            for v in r.json().get("vulnerabilities", []):
                cve = v.get("cve") or {}
                desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                metric = next(iter((cve.get("metrics") or {}).get("cvssMetricV31") or (cve.get("metrics") or {}).get("cvssMetricV30") or []), {})
                data = metric.get("cvssData") or {}
                cpes = set()
                for conf in cve.get("configurations") or []:
                    for node in conf.get("nodes") or []:
                        for m in node.get("cpeMatch") or []:
                            if m.get("vulnerable") and (p := parse_cpe(m.get("criteria", ""))):
                                cpes.add(f"{p['vendor']}:{p['product']}")
                out.append({"cve": cve.get("id"), "published": (cve.get("published") or "")[:10],
                            "description": desc[:600], "cvss": data.get("baseScore"),
                            "severity": (data.get("baseSeverity") or sev).lower(), "vector": data.get("attackVector"),
                            "products": sorted(cpes)[:40]})
    return out


async def nvd(db: AsyncSession, *, refresh: bool = False) -> tuple[list[dict], str | None]:
    row = await intel.cache_get(db, "feed:nvd")
    if row and not refresh and utcnow() - row.updated_at < NVD_TTL:
        return row.data.get("items", []), row.updated_at.isoformat()
    if not refresh:
        return (row.data.get("items", []) if row else []), (row.updated_at.isoformat() if row else None)
    try:
        items = await fetch_nvd()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("NVD refresh failed: %s", exc)
        return (row.data.get("items", []) if row else []), (row.updated_at.isoformat() if row else None)
    await intel.cache_put(db, "feed:nvd", {"items": items})
    return items, utcnow().isoformat()


async def refresh_feeds(db: AsyncSession) -> dict:
    """Refresh KEV, NVD and EPSS for everything in them. Shared, not per tenant."""
    status = {}
    try:
        row = await intel.cache_get(db, "feed:kev")
        if row is None or "vendor" not in next(iter(row.data.values()), {}):
            await intel.cache_put(db, "feed:kev", await easm.kev_catalog())  # old cache lacks vendor/product
        kev = await intel.kev(db)
        status["kev"] = len(kev)
    except (httpx.HTTPError, ValueError) as exc:
        kev = {}
        status["kev_error"] = str(exc)[:200]
    items, _ = await nvd(db, refresh=True)
    status["nvd"] = len(items)
    recent_kev = [c for c, v in kev.items() if (v.get("added") or "") >= (utcnow() - timedelta(days=90)).date().isoformat()]
    cves = sorted({*recent_kev, *(i["cve"] for i in items if i.get("cve"))})
    if cves:
        scores = await easm.epss_scores(cves)
        await intel.cache_put(db, "feed:epss", {c: list(v) for c, v in scores.items()})
        status["epss"] = len(scores)
    return status


# ── Stack ────────────────────────────────────────────────────────────────────


async def declared_stack(db: AsyncSession, tenant_id: str) -> list[dict]:
    row = await intel.cache_get(db, f"techstack:{tenant_id}")
    return list((row.data or {}).get("items", [])) if row else []


async def save_stack(db: AsyncSession, tenant_id: str, items: list[dict]) -> list[dict]:
    clean, seen = [], set()
    for it in items[:MAX_STACK]:
        vendor, product = (it.get("vendor") or "").strip()[:80], (it.get("product") or "").strip()[:80]
        if not product:
            continue
        key = (norm(vendor), norm(product), (it.get("version") or "").strip())
        if key in seen:
            continue
        seen.add(key)
        clean.append({"vendor": vendor, "product": product, "version": (it.get("version") or "").strip()[:40],
                      "critical": bool(it.get("critical"))})
    await intel.cache_put(db, f"techstack:{tenant_id}", {"items": clean})
    return clean


async def detected_stack(db: AsyncSession, tenant_id: str) -> list[dict]:
    found: dict[tuple, dict] = {}
    for h in (await db.execute(select(SurfaceHost.hostname, SurfaceHost.cpes).where(SurfaceHost.tenant_id == tenant_id))).all():
        for cpe in h.cpes or []:
            p = parse_cpe(cpe)
            if not p:
                continue
            key = (norm(p["vendor"]), norm(p["product"]))
            entry = found.setdefault(key, {"vendor": p["vendor"], "product": p["product"], "versions": set(), "hosts": set()})
            if p["version"]:
                entry["versions"].add(p["version"])
            entry["hosts"].add(h.hostname)
    return [{"vendor": e["vendor"], "product": e["product"], "versions": sorted(e["versions"]),
             "hosts": sorted(e["hosts"])[:50]} for e in found.values()]


def _matches(item_vendor: str, item_product: str, vendor: str, product: str) -> bool:
    iv, ip, v, p = norm(item_vendor), norm(item_product), norm(vendor), norm(product)
    if not ip or not p:
        return False
    if iv and v and iv != v and iv not in v and v not in iv:
        return False
    if ip == p:
        return True
    # "exchange" ~ "exchange_server", "fortios" ~ "fortios"; short tokens must be exact.
    return len(ip) >= 4 and len(p) >= 4 and (ip in p or p in ip)


def _affects(stack: list[dict], vendor: str, product: str) -> list[dict]:
    return [s for s in stack if _matches(s.get("vendor", ""), s.get("product", ""), vendor, product)]


def _priority(kev: bool, ransomware: bool, cvss: float | None, epss: float | None, affected: bool) -> str:
    if affected and (kev or (epss or 0) >= 0.5):
        return "critical"
    if affected and ((cvss or 0) >= 9 or (epss or 0) >= 0.1):
        return "high"
    if affected or kev and ransomware:
        return "medium"
    return "low"


async def feed(db: AsyncSession, tenant_id: str, *, days: int = 30, only_affecting: bool = False,
               q: str | None = None, limit: int = 300) -> dict:
    declared = await declared_stack(db, tenant_id)
    detected = await detected_stack(db, tenant_id)
    stack = [{**d, "origin": "declared"} for d in declared] + [
        {"vendor": d["vendor"], "product": d["product"], "version": ", ".join(d["versions"][:3]), "hosts": d["hosts"],
         "origin": "detected"} for d in detected]

    kev_row = await intel.cache_get(db, "feed:kev")
    kev = kev_row.data if kev_row else {}
    nvd_items, nvd_at = await nvd(db)
    epss_row = await intel.cache_get(db, "feed:epss")
    epss = epss_row.data if epss_row else {}
    since = (utcnow() - timedelta(days=days)).date().isoformat()

    rows: dict[str, dict] = {}
    for cve, v in kev.items():
        if (v.get("added") or "") < since:
            continue
        rows[cve] = {"cve": cve, "title": v.get("name") or cve, "description": v.get("description") or "",
                     "vendor": v.get("vendor"), "product": v.get("product"), "date": v.get("added"),
                     "kev": True, "kev_added": v.get("added"), "kev_due": v.get("due"), "action": v.get("action"),
                     "ransomware": bool(v.get("ransomware")), "cvss": None, "severity": None,
                     "products": [f"{norm(v.get('vendor'))}:{norm(v.get('product'))}"]}
    for it in nvd_items:
        cve = it.get("cve")
        if not cve:
            continue
        r = rows.get(cve)
        if r is None:
            vendor, _, product = (it["products"][0] if it.get("products") else "::").partition(":")
            k = kev.get(cve) or {}
            r = rows[cve] = {"cve": cve, "title": (it.get("description") or cve)[:140], "description": it.get("description") or "",
                             "vendor": vendor or None, "product": product or None, "date": it.get("published"),
                             "kev": bool(k), "kev_added": k.get("added"), "kev_due": k.get("due"), "action": k.get("action"),
                             "ransomware": bool(k.get("ransomware")), "products": []}
        r["cvss"], r["severity"], r["vector"] = it.get("cvss"), it.get("severity"), it.get("vector")
        r["products"] = sorted(set(r["products"]) | set(it.get("products") or []))
        if not r.get("description"):
            r["description"] = it.get("description") or ""

    out = []
    for r in rows.values():
        affected: list[dict] = []
        for pair in r["products"]:
            vendor, _, product = pair.partition(":")
            for s in _affects(stack, vendor, product):
                if s not in affected:
                    affected.append(s)
        e = epss.get(r["cve"])
        r["epss"], r["percentile"] = (e[0], e[1]) if e else (None, None)
        r["affects"] = [{"vendor": s["vendor"], "product": s["product"], "version": s.get("version"),
                         "origin": s["origin"], "hosts": s.get("hosts", [])} for s in affected]
        r["hosts"] = sorted({h for s in affected for h in s.get("hosts", [])})
        r["priority"] = _priority(r["kev"], r["ransomware"], r.get("cvss"), r["epss"], bool(affected))
        if only_affecting and not affected:
            continue
        if q and q.lower() not in f"{r['cve']} {r.get('vendor')} {r.get('product')} {r.get('title')}".lower():
            continue
        out.append(r)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out.sort(key=lambda r: (order[r["priority"]], -(r["epss"] or 0), r.get("date") or "", r["cve"]), reverse=False)
    affecting = [r for r in out if r["affects"]]
    return {
        "items": out[:limit],
        "stats": {
            "total": len(out), "affecting": len(affecting), "kev": sum(1 for r in out if r["kev"]),
            "kev_affecting": sum(1 for r in affecting if r["kev"]),
            "ransomware": sum(1 for r in out if r["ransomware"]),
            "critical": sum(1 for r in out if r["priority"] == "critical"),
            "high": sum(1 for r in out if r["priority"] == "high"),
            "stack": len(stack),
        },
        "stack": stack,
        "feeds": {"kev_updated": kev_row.updated_at.isoformat() if kev_row else None, "kev_entries": len(kev),
                  "nvd_updated": nvd_at, "nvd_entries": len(nvd_items),
                  "epss_updated": epss_row.updated_at.isoformat() if epss_row else None},
        "days": days,
    }


async def open_incidents(db: AsyncSession, tenant_id: str) -> int:
    """One incident per critical/high CVE that affects the stack (idempotent)."""
    data = await feed(db, tenant_id, days=30, only_affecting=True, limit=1000)
    n = 0
    for r in data["items"]:
        if r["priority"] not in ("critical", "high"):
            continue
        what = ", ".join(f"{a['vendor']} {a['product']}".strip() for a in r["affects"][:3])
        why = f"in CISA KEV since {r['kev_added']}" if r["kev"] else f"CVSS {r.get('cvss')}, EPSS {round((r['epss'] or 0) * 100)}%"
        inc = await incidents.open_incident(
            db, tenant_id, title=f"{r['cve']} may affect {what}"[:255], category="vuln", severity=r["priority"],
            source_type="vulnintel", source_id=r["cve"], tags=["vuln-intel"] + (["kev"] if r["kev"] else []),
            description=(f"{r['title']}\n{r['description']}\nWhy: {why}."
                         + (f"\nHosts: {', '.join(r['hosts'][:10])}." if r["hosts"] else "")
                         + (f"\nRequired action: {r['action']}" if r.get("action") else "")
                         + "\nVersion ranges are not checked: confirm the installed version is affected."))
        n += 1 if inc else 0
    await db.commit()
    return n
