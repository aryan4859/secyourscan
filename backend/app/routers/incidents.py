"""Incident (alarm) management: one queue for everything that needs a human."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..database import get_db
from ..deps import Principal, client_ip, require_scope
from ..models import Incident, IncidentEvent, User, utcnow
from ..services import incidents as svc
from .serializers import iso

router = APIRouter(prefix="/incidents", tags=["incidents"])

Severity = Literal["critical", "high", "medium", "low"]
Status = Literal["open", "investigating", "contained", "resolved", "false_positive"]
_SEV_ORDER = {s: i for i, s in enumerate(svc.SEVERITIES)}


async def _people(db: AsyncSession, tenant_id: str) -> dict[str, User]:
    return {u.id: u for u in (await db.execute(select(User).where(User.tenant_id == tenant_id))).scalars()}


def _who(principal: Principal) -> str:
    return principal.email or principal.actor


def _summary(i: Incident, people: dict[str, User], now) -> dict:
    a = people.get(i.assignee_id) if i.assignee_id else None
    return {
        "id": i.id, "number": i.number, "ref": f"INC-{i.number:04d}", "title": i.title, "category": i.category,
        "severity": i.severity, "status": i.status, "actor": i.actor, "tags": i.tags or [],
        "assignee": {"id": a.id, "email": a.email, "name": a.full_name or a.email} if a else None,
        "source_type": i.source_type, "source_id": i.source_id, "created_by": i.created_by,
        "created_at": iso(i.created_at), "updated_at": iso(i.updated_at), "sla_due_at": iso(i.sla_due_at),
        "sla_state": svc.sla_state(i, now), "acknowledged_at": iso(i.acknowledged_at), "resolved_at": iso(i.resolved_at),
    }


def _detail(i: Incident, people: dict[str, User]) -> dict:
    return {**_summary(i, people, utcnow()), "description": i.description,
            "events": [{"id": e.id, "kind": e.kind, "actor": e.actor, "body": e.body, "at": iso(e.at)} for e in i.events]}


async def _get(db: AsyncSession, principal: Principal, incident_id: str) -> Incident:
    i = await db.get(Incident, incident_id)
    if i is None or i.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Incident not found")
    await db.refresh(i, ["events"])
    return i


@router.get("")
async def list_incidents(
    status: str = Query("active", description="active | closed | all | one status"),
    severity: Severity | None = None, category: str | None = None,
    assignee: str | None = Query(None, description="me | unassigned | a user id"),
    q: str | None = Query(None, max_length=200), limit: int = Query(500, ge=1, le=2000),
    principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db),
):
    stmt = select(Incident).where(Incident.tenant_id == principal.tenant_id)
    if status == "active":
        stmt = stmt.where(Incident.status.not_in(svc.CLOSED))
    elif status == "closed":
        stmt = stmt.where(Incident.status.in_(svc.CLOSED))
    elif status != "all":
        if status not in svc.STATUSES:
            raise HTTPException(422, "Unknown status")
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if category:
        stmt = stmt.where(Incident.category == category)
    if assignee == "me":
        stmt = stmt.where(Incident.assignee_id == principal.user_id)
    elif assignee == "unassigned":
        stmt = stmt.where(Incident.assignee_id.is_(None))
    elif assignee:
        stmt = stmt.where(Incident.assignee_id == assignee)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Incident.title.ilike(like), Incident.description.ilike(like), Incident.actor.ilike(like)))
    rows = (await db.execute(stmt.order_by(Incident.created_at.desc()).limit(limit))).scalars().all()
    rows.sort(key=lambda i: (i.status in svc.CLOSED, _SEV_ORDER.get(i.severity, 9), i.sla_due_at))
    people, now = await _people(db, principal.tenant_id), utcnow()
    return [_summary(i, people, now) for i in rows]


@router.get("/stats")
async def incident_stats(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return {**await svc.stats(db, principal.tenant_id), "sla_hours": svc.SLA_HOURS}


@router.get("/assignees")
async def assignees(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return [{"id": u.id, "email": u.email, "name": u.full_name or u.email}
            for u in (await _people(db, principal.tenant_id)).values() if u.is_active]


@router.post("/sync")
async def sync_incidents(request: Request, principal: Principal = Depends(require_scope("write")),
                         db: AsyncSession = Depends(get_db)):
    """Open incidents for findings that need one now (also runs after every scan)."""
    new = await svc.sync(db, principal.tenant_id)
    if new:
        await log_action(db, action="SYNC_INCIDENTS", tenant_id=principal.tenant_id, user_id=principal.actor,
                         details={"opened": len(new)}, ip_address=client_ip(request))
    return {"opened": len(new), "titles": new[:50]}


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    description: str = Field("", max_length=8000)
    severity: Severity = "medium"
    category: Literal["manual", "leak", "vuln", "lookalike", "phishing", "ransomware", "surface", "ioc", "vendor"] = "manual"
    assignee_id: str | None = None
    actor: str | None = Field(None, max_length=64)
    tags: list[str] = Field(default_factory=list, max_length=20)


@router.post("", status_code=201)
async def create_incident(body: IncidentCreate, request: Request, principal: Principal = Depends(require_scope("write")),
                          db: AsyncSession = Depends(get_db)):
    people = await _people(db, principal.tenant_id)
    if body.assignee_id and body.assignee_id not in people:
        raise HTTPException(422, "Assignee is not a user of this tenant")
    inc = await svc.open_incident(db, principal.tenant_id, title=body.title, description=body.description,
                                  severity=body.severity, category=body.category, actor=body.actor,
                                  tags=[t[:40] for t in body.tags], created_by=_who(principal), assignee_id=body.assignee_id)
    await db.commit()
    await log_action(db, action="CREATE_INCIDENT", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="incident", resource_id=inc.id, details={"title": inc.title, "severity": inc.severity},
                     ip_address=client_ip(request))
    return _detail(await _get(db, principal, inc.id), people)


@router.get("/{incident_id}")
async def get_incident(incident_id: str, principal: Principal = Depends(require_scope("read")),
                       db: AsyncSession = Depends(get_db)):
    return _detail(await _get(db, principal, incident_id), await _people(db, principal.tenant_id))


class IncidentUpdate(BaseModel):
    status: Status | None = None
    severity: Severity | None = None
    assignee_id: str | None = None  # send null to unassign
    title: str | None = Field(None, min_length=3, max_length=255)
    note: str | None = Field(None, max_length=4000, description="Optional comment recorded with the change")


@router.patch("/{incident_id}")
async def update_incident(incident_id: str, body: IncidentUpdate, request: Request,
                          principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    inc = await _get(db, principal, incident_id)
    people = await _people(db, principal.tenant_id)
    who, now = _who(principal), utcnow()
    changes: dict = {}

    def event(kind, text):
        inc.events.append(IncidentEvent(kind=kind, actor=who[:255], body=text, at=now))

    if body.status and body.status != inc.status:
        changes["status"] = [inc.status, body.status]
        event("status", f"{inc.status} → {body.status}")
        if inc.acknowledged_at is None and body.status != "open":
            inc.acknowledged_at = now
        inc.resolved_at = now if body.status in svc.CLOSED else None
        inc.status = body.status
        await svc.write_back(db, inc)
    if body.severity and body.severity != inc.severity:
        changes["severity"] = [inc.severity, body.severity]
        event("severity", f"{inc.severity} → {body.severity}")
        inc.severity = body.severity
        inc.sla_due_at = svc.sla_due(body.severity, inc.created_at)
    if "assignee_id" in body.model_fields_set and body.assignee_id != inc.assignee_id:
        if body.assignee_id and body.assignee_id not in people:
            raise HTTPException(422, "Assignee is not a user of this tenant")
        new = people.get(body.assignee_id) if body.assignee_id else None
        changes["assignee"] = body.assignee_id
        event("assignee", f"assigned to {new.email}" if new else "unassigned")
        inc.assignee_id = body.assignee_id
        if inc.acknowledged_at is None and body.assignee_id:
            inc.acknowledged_at = now
    if body.title and body.title != inc.title:
        changes["title"] = body.title
        event("comment", f"renamed from “{inc.title}”")
        inc.title = body.title
    if body.note:
        event("comment", body.note)
    if changes or body.note:
        inc.updated_at = now
        await db.commit()
        await log_action(db, action="UPDATE_INCIDENT", tenant_id=principal.tenant_id, user_id=principal.actor,
                         resource_type="incident", resource_id=inc.id, details=changes, ip_address=client_ip(request))
    return _detail(await _get(db, principal, inc.id), people)


class Comment(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


@router.post("/{incident_id}/comments", status_code=201)
async def comment(incident_id: str, body: Comment, principal: Principal = Depends(require_scope("write")),
                  db: AsyncSession = Depends(get_db)):
    inc = await _get(db, principal, incident_id)
    now = utcnow()
    inc.events.append(IncidentEvent(kind="comment", actor=_who(principal)[:255], body=body.body, at=now))
    inc.updated_at = now
    await db.commit()
    return _detail(await _get(db, principal, inc.id), await _people(db, principal.tenant_id))
