"""External risk: attack surface, vulnerabilities, brand protection, ransomware."""

from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..database import get_db
from ..deps import Principal, client_ip, require_scope
from ..models import DnsRecord, Lookalike, PhishingUrl, RansomwareHit, SurfaceEvent, SurfaceHost, TlsGrade, VulnFinding, utcnow
from ..services import asm, broker, easm, intel, jobs, license, ransomware
from .serializers import iso

router = APIRouter(tags=["external risk"])
_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ── Scans ────────────────────────────────────────────────────────────────────


@router.get("/intel/status")
async def scan_status(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return await intel.statuses(db, principal.tenant_id)


@router.get("/intel/summary")
async def intel_summary(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return await intel.summary(db, principal.tenant_id)


@router.post("/intel/scan/{module}", status_code=202)
async def start_scan(module: Literal["surface", "vulns", "brand", "ransomware"], request: Request, background: BackgroundTasks,
                     principal: Principal = Depends(require_scope("recon")), db: AsyncSession = Depends(get_db)):
    """Queue a scan. ``surface`` also refreshes ``vulns`` when it finishes."""
    ok, reason = license.can_scan()
    if not ok:
        raise HTTPException(402, f"Scanning is disabled: {reason}")
    current = (await intel.statuses(db, principal.tenant_id)).get(module, {})
    if current.get("status") in ("queued", "running"):
        raise HTTPException(409, f"A {module} scan is already {current['status']}")
    await intel.set_status(db, principal.tenant_id, module, status="queued", queued_at=utcnow().isoformat(), error=None)
    await log_action(db, action="INTEL_SCAN", tenant_id=principal.tenant_id, user_id=principal.actor,
                     details={"module": module}, ip_address=client_ip(request))
    return await jobs.enqueue(broker.TASK_INTEL, principal.tenant_id, module, background=background)


# ── Attack surface ───────────────────────────────────────────────────────────


@router.get("/surface/hosts")
async def surface_hosts(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    now = utcnow()
    rows = (await db.execute(select(SurfaceHost).where(SurfaceHost.tenant_id == principal.tenant_id)
                             .order_by(SurfaceHost.root_domain, SurfaceHost.hostname))).scalars()
    return [{
        "id": h.id, "hostname": h.hostname, "root_domain": h.root_domain, "ips": h.ips, "resolves": h.resolves,
        "ports": h.ports, "cves": h.cves, "cpes": h.cpes, "tags": h.tags, "sources": h.sources or [],
        "threats": h.threats or [], "tls_issuer": h.tls_issuer,
        "tls_not_after": iso(h.tls_not_after),
        "tls_days_left": (h.tls_not_after - now).days if h.tls_not_after else None,
        "first_seen": iso(h.first_seen), "last_seen": iso(h.last_seen),
        "is_new": now - h.first_seen <= timedelta(days=7),
    } for h in rows]


@router.get("/surface/ports")
async def surface_ports(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    """Every exposed host:port with its risk class, worst first."""
    rows = []
    for h in (await db.execute(select(SurfaceHost).where(SurfaceHost.tenant_id == principal.tenant_id,
                                                         SurfaceHost.resolves.is_(True)))).scalars():
        for p in h.ports or []:
            rows.append({"hostname": h.hostname, "ips": h.ips, **asm.classify_port(p)})
    rows.sort(key=lambda r: (asm.RISK_ORDER.get(r["risk"], 9), r["port"], r["hostname"]))
    return rows


@router.get("/surface/tls")
async def surface_tls(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(TlsGrade).where(TlsGrade.tenant_id == principal.tenant_id))).scalars().all()
    rows.sort(key=lambda g: ("FDCBA".index(g.grade) if g.grade in "FDCBA" else 9, g.hostname))
    return [{"hostname": g.hostname, "grade": g.grade, "issues": g.issues, "details": g.details,
             "checked_at": iso(g.checked_at)} for g in rows]


@router.get("/surface/dns")
async def surface_dns(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    records: dict[str, dict] = {}
    for r in (await db.execute(select(DnsRecord).where(DnsRecord.tenant_id == principal.tenant_id))).scalars():
        records.setdefault(r.domain, {})[r.rtype] = {"values": r.values, "changed_at": iso(r.changed_at),
                                                      "checked_at": iso(r.checked_at)}
    posture = await intel.cache_get(db, f"posture:{principal.tenant_id}")
    p = posture.data if posture else {}
    return [{"domain": d, "records": records.get(d, {}), "checks": (p.get(d) or {}).get("checks", []),
             "dmarc": (p.get(d) or {}).get("dmarc", [])} for d in sorted(set(records) | set(p))]


@router.get("/surface/events")
async def surface_events(limit: int = Query(200, ge=1, le=1000), principal: Principal = Depends(require_scope("read")),
                         db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(SurfaceEvent).where(SurfaceEvent.tenant_id == principal.tenant_id)
                             .order_by(SurfaceEvent.at.desc()).limit(limit))).scalars()
    return [{"id": e.id, "subject": e.subject, "kind": e.kind, "severity": e.severity, "detail": e.detail,
             "at": iso(e.at)} for e in rows]


# ── Vulnerabilities ──────────────────────────────────────────────────────────


@router.get("/vulns")
async def vulns(status: Literal["open", "fixed", "accepted", "all"] = "open",
                principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    q = select(VulnFinding).where(VulnFinding.tenant_id == principal.tenant_id)
    if status != "all":
        q = q.where(VulnFinding.status == status)
    rows = (await db.execute(q)).scalars().all()
    rows.sort(key=lambda f: (_PRIORITY.get(f.priority, 9), -(f.epss or 0), f.cve))
    return [{
        "id": f.id, "host": f.host, "ip": f.ip, "cve": f.cve, "kev": f.kev, "kev_added": f.kev_added,
        "kev_name": f.kev_name, "kev_ransomware": f.kev_ransomware, "epss": f.epss, "percentile": f.percentile,
        "priority": f.priority, "status": f.status, "first_seen": iso(f.first_seen), "last_seen": iso(f.last_seen),
    } for f in rows]


class VulnUpdate(BaseModel):
    status: Literal["open", "accepted"]


@router.patch("/vulns/{finding_id}")
async def update_vuln(finding_id: str, body: VulnUpdate, request: Request,
                      principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    f = await db.get(VulnFinding, finding_id)
    if f is None or f.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Finding not found")
    f.status = body.status
    await log_action(db, action="UPDATE_VULN", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="vuln_finding", resource_id=f.id, details={"cve": f.cve, "host": f.host, "status": body.status},
                     ip_address=client_ip(request))
    return {"id": f.id, "status": f.status}


# ── Brand protection ─────────────────────────────────────────────────────────


@router.get("/brand/lookalikes")
async def lookalikes(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    now = utcnow()
    rows = (await db.execute(select(Lookalike).where(Lookalike.tenant_id == principal.tenant_id)
                             .order_by(Lookalike.risk.desc(), Lookalike.domain))).scalars()
    return [{
        "id": x.id, "domain": x.domain, "target": x.target, "technique": x.technique, "ips": x.ips, "has_mx": x.has_mx,
        "has_cert": x.has_cert, "risk": x.risk, "status": x.status, "first_seen": iso(x.first_seen),
        "last_seen": iso(x.last_seen), "is_new": now - x.first_seen <= timedelta(days=7),
    } for x in rows]


class LookalikeUpdate(BaseModel):
    status: Literal["new", "reviewing", "takedown", "benign"]


@router.patch("/brand/lookalikes/{item_id}")
async def update_lookalike(item_id: str, body: LookalikeUpdate, request: Request,
                           principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    x = await db.get(Lookalike, item_id)
    if x is None or x.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Lookalike not found")
    x.status = body.status
    await log_action(db, action="UPDATE_LOOKALIKE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="lookalike", resource_id=x.id, details={"domain": x.domain, "status": body.status},
                     ip_address=client_ip(request))
    return {"id": x.id, "status": x.status}


@router.get("/brand/phishing")
async def phishing_urls(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(PhishingUrl).where(PhishingUrl.tenant_id == principal.tenant_id)
                             .order_by(PhishingUrl.first_seen.desc()))).scalars()
    return [{"id": p.id, "url": p.url, "host": p.host, "target": p.target, "source": p.source, "ip": p.ip,
             "status": p.status, "first_seen": iso(p.first_seen), "last_seen": iso(p.last_seen)} for p in rows]


class PhishingUpdate(BaseModel):
    status: Literal["new", "reported", "down", "benign"]


@router.patch("/brand/phishing/{item_id}")
async def update_phishing(item_id: str, body: PhishingUpdate, request: Request,
                          principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    p = await db.get(PhishingUrl, item_id)
    if p is None or p.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Phishing URL not found")
    p.status = body.status
    await log_action(db, action="UPDATE_PHISHING_URL", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="phishing_url", resource_id=p.id, details={"host": p.host, "status": body.status},
                     ip_address=client_ip(request))
    return {"id": p.id, "status": p.status}


# ── Ransomware ───────────────────────────────────────────────────────────────


@router.get("/ransomware/hits")
async def ransomware_hits(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(RansomwareHit).where(RansomwareHit.tenant_id == principal.tenant_id)
                             .order_by(RansomwareHit.first_seen.desc()))).scalars()
    return [{
        "id": h.id, "group": h.group, "victim": h.victim, "domain": h.domain, "country": h.country, "activity": h.activity,
        "description": h.description, "matched": h.matched, "url": h.url, "attack_date": iso(h.attack_date),
        "status": h.status, "first_seen": iso(h.first_seen),
    } for h in rows]


class HitUpdate(BaseModel):
    status: Literal["new", "acknowledged", "false_positive"]


@router.patch("/ransomware/hits/{hit_id}")
async def update_hit(hit_id: str, body: HitUpdate, request: Request,
                     principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    h = await db.get(RansomwareHit, hit_id)
    if h is None or h.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Hit not found")
    h.status = body.status
    await log_action(db, action="UPDATE_RANSOMWARE_HIT", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="ransomware_hit", resource_id=h.id, details={"group": h.group, "status": body.status},
                     ip_address=client_ip(request))
    return {"id": h.id, "status": h.status}


@router.get("/ransomware/activity")
async def ransomware_activity(days: int = Query(7, ge=1, le=30), principal: Principal = Depends(require_scope("read")),
                              db: AsyncSession = Depends(get_db)):
    """Global context from ransomware.live's recent-victims feed (cached 1 h)."""
    return ransomware.activity(await intel.recent_ransomware(db), days)


# Keep the CERT warning window discoverable for the UI.
@router.get("/surface/config")
async def surface_config(principal: Principal = Depends(require_scope("read"))):
    return {"cert_warn_days": easm.CERT_WARN_DAYS}
