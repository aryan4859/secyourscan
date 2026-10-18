"""Runs the external-risk modules, caches shared feeds, records scan status
and raises alerts.

Modules: ``surface`` (then ``vulns`` on the fresh surface), ``brand`` and
``ransomware``. Each run's outcome is kept in ``IntelCache`` under
``scan:<tenant>:<module>`` so the UI can show progress and last results.
Alerts are ordinary notifications; critical ones also go to the SOAR webhook.
"""

import logging
from datetime import timedelta

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import IntelCache, Lookalike, Notification, PhishingUrl, RansomwareHit, SurfaceHost, TlsGrade, VulnFinding, utcnow
from . import asm, brand, easm, ransomware

logger = logging.getLogger("secyourscan.intel")

MODULES = ("surface", "vulns", "brand", "ransomware")
RECENT_TTL = timedelta(hours=1)


# ── Cache ────────────────────────────────────────────────────────────────────


async def cache_get(db: AsyncSession, key: str) -> IntelCache | None:
    return await db.get(IntelCache, key)


async def cache_put(db: AsyncSession, key: str, data) -> None:
    row = await db.get(IntelCache, key)
    if row is None:
        db.add(IntelCache(key=key, data=data, updated_at=utcnow()))
    else:
        row.data, row.updated_at = data, utcnow()
    await db.commit()


async def kev(db: AsyncSession) -> dict[str, dict]:
    row = await cache_get(db, "feed:kev")
    if row and utcnow() - row.updated_at < easm.KEV_TTL:
        return row.data
    try:
        data = await easm.kev_catalog()
    except (httpx.HTTPError, ValueError) as exc:
        if row:  # stale beats nothing
            logger.warning("KEV refresh failed, using cache from %s: %s", row.updated_at, exc)
            return row.data
        raise
    await cache_put(db, "feed:kev", data)
    return data


async def recent_ransomware(db: AsyncSession, *, refresh: bool = False) -> list[dict]:
    row = await cache_get(db, "feed:ransomware_recent")
    if row and not refresh and utcnow() - row.updated_at < RECENT_TTL:
        return row.data.get("items", [])
    feeds = []
    for name, fn in (("ransomware.live", ransomware.recent_victims), ("ransomlook", ransomware.ransomlook_recent)):
        try:
            feeds.append(await fn())
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("%s recent feed failed: %s", name, exc)
    if not feeds:
        return row.data.get("items", []) if row else []
    items = ransomware.merge_feeds(*feeds)
    await cache_put(db, "feed:ransomware_recent", {"items": items})
    return items


# ── Status & alerts ──────────────────────────────────────────────────────────


def _status_key(tenant_id: str, module: str) -> str:
    return f"scan:{tenant_id}:{module}"


async def set_status(db: AsyncSession, tenant_id: str, module: str, **fields) -> None:
    row = await cache_get(db, _status_key(tenant_id, module))
    await cache_put(db, _status_key(tenant_id, module), {**(row.data if row else {}), **fields})


async def statuses(db: AsyncSession, tenant_id: str) -> dict:
    rows = (await db.execute(select(IntelCache).where(IntelCache.key.like(f"scan:{tenant_id}:%")))).scalars()
    out = {m: {"status": "never"} for m in MODULES}
    for r in rows:
        out[r.key.rsplit(":", 1)[1]] = r.data
    return out


async def _alert(db: AsyncSession, tenant_id: str, level: str, title: str, body: str, *, soar_type: str | None = None):
    db.add(Notification(tenant_id=tenant_id, level=level, title=title[:255], body=body[:2000]))
    await db.commit()
    if soar_type and settings.SOAR_WEBHOOK_URL:
        try:
            async with httpx.AsyncClient(timeout=3.0) as c:
                await c.post(settings.SOAR_WEBHOOK_URL, json={"alert_type": soar_type, "tenant_id": tenant_id,
                                                               "title": title, "detail": body})
        except httpx.HTTPError as exc:
            logger.error("SOAR webhook failed: %s", exc)


async def run_module(db: AsyncSession, tenant_id: str, module: str) -> dict:
    if module not in MODULES:
        raise ValueError(f"unknown module {module!r}")
    started = utcnow()
    await set_status(db, tenant_id, module, status="running", started_at=started.isoformat(), error=None)
    try:
        if module == "surface":
            result = await easm.scan_surface(db, tenant_id)
            result["tls"] = await asm.grade_hosts(db, tenant_id, result.pop("live_hosts", []))
            dns_result = await asm.monitor_dns(db, tenant_id)
            result["dns"] = {k: v for k, v in dns_result.items() if k != "posture"}
            await cache_put(db, f"posture:{tenant_id}", dns_result["posture"])
            crit_events = [e for e in result["events"] if e["severity"] == "critical"]
            if crit_events:
                await _alert(db, tenant_id, "critical", f"{len(crit_events)} critical change(s) on your attack surface",
                             "; ".join(f"{e['subject']}: {e['detail']}" for e in crit_events[:8]), soar_type="SURFACE_CHANGE")
            dns_crit = [c for c in dns_result["changes"] if c["severity"] == "critical"]
            if dns_crit:
                await _alert(db, tenant_id, "critical", "Name-server or mail DNS records changed",
                             "; ".join(f"{c['domain']} {c['detail']}" for c in dns_crit[:8]), soar_type="DNS_CHANGE")
            if result["tls"]["worsened"]:
                await _alert(db, tenant_id, "info", "TLS configuration got worse", "; ".join(result["tls"]["worsened"][:8]))
            if result["new_threats"]:
                await _alert(db, tenant_id, "critical", f"{len(result['new_threats'])} of your hosts listed in threat feeds",
                             "; ".join(result["new_threats"][:10]), soar_type="THREAT_FEED_LISTING")
            if result["new"]:
                await _alert(db, tenant_id, "info", f"{result['new']} new host(s) on your attack surface",
                             "Discovered in certificate-transparency logs. Review them on Attack Surface.")
            if result["expiring_certs"]:
                prev = (await cache_get(db, _status_key(tenant_id, module)))
                if not prev or prev.data.get("result", {}).get("expiring_certs") != result["expiring_certs"]:
                    await _alert(db, tenant_id, "info", f"{result['expiring_certs']} TLS certificate(s) expire within "
                                 f"{easm.CERT_WARN_DAYS} days", "See Attack Surface for the hosts.")
        elif module == "vulns":
            result = await easm.scan_vulns(db, tenant_id, await kev(db))
            if result["new_kev"]:
                await _alert(db, tenant_id, "critical", f"{len(result['new_kev'])} actively exploited CVE(s) on your hosts",
                             ", ".join(result["new_kev"][:10]), soar_type="KEV_EXPOSURE")
        elif module == "brand":
            result = await brand.scan_brand(db, tenant_id)
            if result["new_high_risk"]:
                await _alert(db, tenant_id, "critical", f"{len(result['new_high_risk'])} high-risk lookalike domain(s)",
                             ", ".join(result["new_high_risk"][:10]), soar_type="LOOKALIKE_DOMAIN")
            if result["new_phishing"]:
                await _alert(db, tenant_id, "critical", f"{len(result['new_phishing'])} live phishing URL(s) using your brand",
                             "\n".join(result["new_phishing"][:10]), soar_type="PHISHING_URL")
        else:
            result = await ransomware.scan_ransomware(db, tenant_id, await recent_ransomware(db))
            if result["new"]:
                await _alert(db, tenant_id, "critical", "Named on a ransomware leak site", "; ".join(result["new"][:10]),
                             soar_type="RANSOMWARE_MENTION")
    except Exception as exc:  # noqa: BLE001 — recorded for the UI, then re-raised for the worker log
        await db.rollback()
        await set_status(db, tenant_id, module, status="error", error=str(exc)[:500], finished_at=utcnow().isoformat())
        raise
    await set_status(db, tenant_id, module, status="ok", finished_at=utcnow().isoformat(), result=result)
    return result


async def run_surface_then_vulns(db: AsyncSession, tenant_id: str) -> dict:
    surface = await run_module(db, tenant_id, "surface")
    return {"surface": surface, "vulns": await run_module(db, tenant_id, "vulns")}


# ── Dashboard summary ────────────────────────────────────────────────────────


async def summary(db: AsyncSession, tenant_id: str) -> dict:
    now = utcnow()
    hosts = (await db.execute(select(SurfaceHost).where(SurfaceHost.tenant_id == tenant_id))).scalars().all()
    vulns = (await db.execute(select(VulnFinding.priority, VulnFinding.kev, func.count())
                              .where(VulnFinding.tenant_id == tenant_id, VulnFinding.status == "open")
                              .group_by(VulnFinding.priority, VulnFinding.kev))).all()
    look = (await db.execute(select(Lookalike.risk, Lookalike.status).where(Lookalike.tenant_id == tenant_id))).all()
    rw = (await db.execute(select(RansomwareHit.status).where(RansomwareHit.tenant_id == tenant_id))).scalars().all()
    phish = (await db.execute(select(PhishingUrl.status).where(PhishingUrl.tenant_id == tenant_id))).scalars().all()
    tls = (await db.execute(select(TlsGrade.grade).where(TlsGrade.tenant_id == tenant_id))).scalars().all()
    posture = await cache_get(db, f"posture:{tenant_id}")
    by_priority = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    kev_open = 0
    for p, is_kev, n in vulns:
        by_priority[p] = by_priority.get(p, 0) + n
        kev_open += n if is_kev else 0
    return {
        "surface": {
            "hosts": len(hosts), "live": sum(1 for h in hosts if h.resolves),
            "new_7d": sum(1 for h in hosts if now - h.first_seen <= timedelta(days=7)),
            "open_ports": sum(len(h.ports or []) for h in hosts),
            "expiring_certs": sum(1 for h in hosts if h.tls_not_after and h.tls_not_after - now <= timedelta(days=easm.CERT_WARN_DAYS)),
            "expired_certs": sum(1 for h in hosts if h.tls_not_after and h.tls_not_after < now),
            "listed": sum(1 for h in hosts if h.threats),
            "critical_ports": sum(1 for h in hosts if h.resolves for p in (h.ports or [])
                                  if asm.classify_port(p)["risk"] == "critical"),
            "tls_failing": sum(1 for g in tls if g in ("D", "F")),
            "dns_failing": sum(1 for d in (posture.data.values() if posture else [])
                               for c in d.get("checks", []) if not c["ok"] and c["severity"] == "critical"),
        },
        "vulns": {"open": sum(by_priority.values()), "kev": kev_open, "by_priority": by_priority},
        "brand": {"lookalikes": len(look), "high_risk": sum(1 for r, s in look if r >= 70 and s not in ("benign",)),
                  "takedown": sum(1 for _, s in look if s == "takedown"),
                  "phishing": sum(1 for s in phish if s in ("new", "reported"))},
        "ransomware": {"hits": len(rw), "new": sum(1 for s in rw if s == "new")},
        "scans": await statuses(db, tenant_id),
    }
