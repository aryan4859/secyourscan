"""Incident (alarm) management.

Every module's findings land in its own table; this service turns the ones
that need a human into incidents with an owner, a status workflow, an SLA and
a timeline. ``sync`` is idempotent: it runs after every scan and every
processed leak, and a finding opens at most one incident, ever, so closing
an incident never causes it to come back.

Closing an incident also closes its finding (a false positive here marks the
lookalike benign, the leak a false positive, and so on), so the source pages
and the incident queue agree.
"""

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import (
    Incident,
    IncidentEvent,
    Ioc,
    Leak,
    Lookalike,
    PhishingUrl,
    RansomwareHit,
    SurfaceHost,
    Vendor,
    VulnFinding,
    utcnow,
)

SEVERITIES = ("critical", "high", "medium", "low")
STATUSES = ("open", "investigating", "contained", "resolved", "false_positive")
CLOSED = ("resolved", "false_positive")
# Time to resolve, by severity. Response (first acknowledgement) is a quarter of it.
SLA_HOURS = {"critical": 4, "high": 24, "medium": 72, "low": 168}

# What closing an incident does to the finding it came from: {source_type: {incident status: finding status}}.
_WRITE_BACK = {
    "leak": (Leak, {"resolved": "resolved", "false_positive": "false_positive", "investigating": "reviewing"}),
    "lookalike": (Lookalike, {"false_positive": "benign", "investigating": "reviewing"}),
    "phishing": (PhishingUrl, {"resolved": "down", "false_positive": "benign"}),
    "ransomware": (RansomwareHit, {"false_positive": "false_positive", "investigating": "acknowledged",
                                   "resolved": "acknowledged"}),
    "vuln": (VulnFinding, {"false_positive": "accepted"}),
}


def sla_due(severity: str, start) -> object:
    return start + timedelta(hours=SLA_HOURS.get(severity, 72))


def sla_state(inc: Incident, now=None) -> str:
    """met | breached (closed late) | on_track | at_risk (<25 % left) | overdue."""
    now = now or utcnow()
    total = (inc.sla_due_at - inc.created_at).total_seconds() or 1
    if inc.status in CLOSED:
        return "met" if inc.resolved_at and inc.resolved_at <= inc.sla_due_at else "breached"
    left = (inc.sla_due_at - now).total_seconds()
    if left < 0:
        return "overdue"
    return "at_risk" if left / total < 0.25 else "on_track"


async def _next_number(db: AsyncSession, tenant_id: str) -> int:
    return (await db.scalar(select(func.max(Incident.number)).where(Incident.tenant_id == tenant_id)) or 0) + 1


async def open_incident(db: AsyncSession, tenant_id: str, *, title: str, category: str, severity: str,
                        description: str = "", source_type: str | None = None, source_id: str | None = None,
                        actor: str | None = None, tags: list | None = None, created_by: str = "system",
                        assignee_id: str | None = None) -> Incident | None:
    """Open one incident, or None when this finding already has one. Flushes, does not commit."""
    if source_type and source_id:
        exists = await db.scalar(select(Incident.id).where(Incident.tenant_id == tenant_id,
                                                           Incident.source_type == source_type,
                                                           Incident.source_id == str(source_id)))
        if exists:
            return None
    now = utcnow()
    severity = severity if severity in SEVERITIES else "medium"
    inc = Incident(tenant_id=tenant_id, number=await _next_number(db, tenant_id), title=title[:255],
                   description=description[:8000], category=category, severity=severity, status="open",
                   source_type=source_type, source_id=str(source_id) if source_id else None,
                   actor=(actor or None) and actor[:64], tags=tags or [], created_by=created_by[:64],
                   assignee_id=assignee_id, created_at=now, updated_at=now, sla_due_at=sla_due(severity, now))
    inc.events.append(IncidentEvent(kind="created", actor=created_by[:255], at=now,
                                    body=f"Opened from {source_type}" if source_type else "Opened by hand"))
    db.add(inc)
    await db.flush()
    return inc


def _leak_severity(score: int) -> str:
    return "critical" if score >= settings.SOAR_THRESHOLD else "high"


async def sync(db: AsyncSession, tenant_id: str) -> list[str]:
    """Open incidents for every finding that warrants one and has none yet.
    Returns the new incidents' titles."""
    have = {(t, i) for t, i in (await db.execute(
        select(Incident.source_type, Incident.source_id).where(Incident.tenant_id == tenant_id,
                                                               Incident.source_type.is_not(None)))).all()}
    candidates: list[dict] = []

    def add(source_type, source_id, **kw):
        if (source_type, str(source_id)) not in have:
            candidates.append({"source_type": source_type, "source_id": str(source_id), **kw})

    for lk in (await db.execute(select(Leak).where(
            Leak.tenant_id == tenant_id, Leak.severity >= settings.CRITICAL_THRESHOLD,
            Leak.status.in_(["new", "reviewing", "escalated"])))).scalars():
        matched = ", ".join(m["value"] for m in (lk.watch_matches or [])[:5])
        add("leak", lk.id, category="leak", severity=_leak_severity(lk.severity),
            title=f"{lk.category or 'Exposure'} leak ({lk.severity}) from {lk.source}"[:255],
            description=f"{lk.title or ''}\nMatched: {matched or 'n/a'}\n\n{(lk.snippet or '')[:600]}".strip())

    for f in (await db.execute(select(VulnFinding).where(
            VulnFinding.tenant_id == tenant_id, VulnFinding.status == "open",
            VulnFinding.priority.in_(["critical", "high"])))).scalars():
        why = f"in CISA KEV since {f.kev_added}" if f.kev else f"EPSS {round((f.epss or 0) * 100)}%"
        add("vuln", f.id, category="vuln", severity=f.priority, tags=["kev"] if f.kev else [],
            title=f"{f.cve} on {f.host}",
            description=f"{f.kev_name or f.cve} on {f.host} ({f.ip or 'ip unknown'}), {why}."
                        + (" Known to be used by ransomware." if f.kev_ransomware else ""))

    for x in (await db.execute(select(Lookalike).where(
            Lookalike.tenant_id == tenant_id, Lookalike.risk >= 70,
            Lookalike.status.in_(["new", "reviewing", "takedown"])))).scalars():
        add("lookalike", x.id, category="lookalike", severity="high" if x.risk >= 90 else "medium",
            title=f"Lookalike domain {x.domain} imitates {x.target}",
            description=f"Technique: {x.technique}. Risk {x.risk}. Mail server: {'yes' if x.has_mx else 'no'}; "
                        f"TLS certificate: {'yes' if x.has_cert else 'no'}; IPs: {', '.join(x.ips or []) or 'none'}.")

    for p in (await db.execute(select(PhishingUrl).where(
            PhishingUrl.tenant_id == tenant_id, PhishingUrl.status.in_(["new", "reported"])))).scalars():
        add("phishing", p.id, category="phishing", severity="high", title=f"Phishing page targets {p.target}: {p.host}"[:255],
            description=f"{p.url}\nReported by {p.source}. IP: {p.ip or 'unknown'}.")

    for h in (await db.execute(select(RansomwareHit).where(
            RansomwareHit.tenant_id == tenant_id, RansomwareHit.status.in_(["new", "acknowledged"])))).scalars():
        add("ransomware", h.id, category="ransomware", severity="critical", actor=h.group,
            title=f"{h.group} lists “{h.victim}” on its leak site"[:255],
            description=f"Matched “{h.matched}”. {h.description[:1500]}".strip())

    for host in (await db.execute(select(SurfaceHost).where(SurfaceHost.tenant_id == tenant_id))).scalars():
        for t in host.threats or []:
            key = f"{host.hostname}|{t.get('feed')}|{t.get('indicator')}"[:64]
            add("surface", key, category="surface", severity="critical",
                title=f"{host.hostname} listed by {t.get('feed')}"[:255],
                description=f"{t.get('indicator')} — {t.get('threat') or ''} {t.get('malware') or ''}".strip())

    for i in (await db.execute(select(Ioc).where(Ioc.tenant_id == tenant_id, Ioc.verdict == "malicious"))).scalars():
        assets = [s for s in i.sightings or [] if s.get("kind") == "asset"]
        if assets:
            where = "; ".join(s.get("where", "") for s in assets[:5])
            add("ioc", i.id, category="ioc", severity="critical", actor=(i.actors or [None])[0],
                title=f"Malicious {i.type} seen in your data: {i.value}"[:255],
                description=f"Verdict {i.verdict} ({i.score}). Seen in: {where}.")

    for v in (await db.execute(select(Vendor).where(Vendor.tenant_id == tenant_id))).scalars():
        for b in v.breaches or []:
            add("vendor", f"{v.id}|{b.get('group')}|{b.get('victim')}"[:64], category="vendor",
                severity="critical" if v.criticality in ("critical", "high") else "high", actor=b.get("group"),
                title=f"Vendor {v.name} named by {b.get('group')} on a leak site"[:255],
                description=f"{v.name} ({v.domain}) is a {v.criticality}-criticality vendor. Post: {b.get('victim')}. "
                            "Check what data you share with them and rotate shared credentials.")

    new = []
    for c in candidates:
        inc = await open_incident(db, tenant_id, **c)
        if inc:
            new.append(inc.title)
    await db.commit()
    return new


async def write_back(db: AsyncSession, inc: Incident) -> None:
    """Mirror the incident's status onto its finding, where that makes sense."""
    model, mapping = _WRITE_BACK.get(inc.source_type or "", (None, {}))
    if model is None or inc.status not in mapping:
        return
    row = await db.get(model, inc.source_id)
    if row is not None and row.tenant_id == inc.tenant_id:
        row.status = mapping[inc.status]


async def stats(db: AsyncSession, tenant_id: str) -> dict:
    rows = (await db.execute(select(Incident).where(Incident.tenant_id == tenant_id))).scalars().all()
    now = utcnow()
    open_rows = [i for i in rows if i.status not in CLOSED]
    acked = [(i.acknowledged_at - i.created_at).total_seconds() for i in rows if i.acknowledged_at]
    resolved = [(i.resolved_at - i.created_at).total_seconds() for i in rows if i.resolved_at and i.status == "resolved"]
    closed = [i for i in rows if i.status in CLOSED]
    by = lambda attr, items, keys: {k: sum(1 for i in items if getattr(i, attr) == k) for k in keys}  # noqa: E731
    return {
        "total": len(rows),
        "open": len(open_rows),
        "unassigned": sum(1 for i in open_rows if not i.assignee_id),
        "overdue": sum(1 for i in open_rows if sla_state(i, now) == "overdue"),
        "at_risk": sum(1 for i in open_rows if sla_state(i, now) == "at_risk"),
        "by_status": by("status", rows, STATUSES),
        "by_severity_open": by("severity", open_rows, SEVERITIES),
        "by_category_open": {c: n for c, n in sorted(
            {i.category: sum(1 for j in open_rows if j.category == i.category) for i in open_rows}.items(),
            key=lambda kv: -kv[1])},
        "mtta_minutes": round(sum(acked) / len(acked) / 60) if acked else None,
        "mttr_hours": round(sum(resolved) / len(resolved) / 3600, 1) if resolved else None,
        "sla_met_pct": round(100 * sum(1 for i in closed if sla_state(i, now) == "met") / len(closed)) if closed else None,
        "opened_7d": sum(1 for i in rows if now - i.created_at <= timedelta(days=7)),
        "closed_7d": sum(1 for i in closed if i.resolved_at and now - i.resolved_at <= timedelta(days=7)),
    }
