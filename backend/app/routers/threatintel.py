"""Threat intelligence: actor profiles and ATT&CK, IOC hunting, and sharing
indicators as STIX 2.1 (file export and a read-only TAXII 2.1 server)."""

import json
import re
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..database import get_db
from ..deps import Principal, client_ip, require_scope
from ..models import Ioc, Tenant, ThreatActor
from ..services import actors as actors_svc
from ..services import incidents as incidents_svc
from ..services import ioc as ioc_svc
from ..services.actors_data import SECTORS, TECHNIQUES
from .serializers import iso

router = APIRouter(tags=["threat intelligence"])

_VERDICT_ORDER = {"malicious": 0, "suspicious": 1, "unknown": 2, "clean": 3}


# ── Threat profile & actors ──────────────────────────────────────────────────


@router.get("/threat-intel/profile")
async def get_profile(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return await actors_svc.get_profile(db, principal.tenant_id)


class ProfileUpdate(BaseModel):
    sectors: list[str] = Field(default_factory=list, max_length=len(SECTORS))
    countries: list[str] = Field(default_factory=list, max_length=60)


@router.put("/threat-intel/profile")
async def put_profile(body: ProfileUpdate, request: Request, principal: Principal = Depends(require_scope("write")),
                      db: AsyncSession = Depends(get_db)):
    out = await actors_svc.set_profile(db, principal.tenant_id, body.sectors, body.countries)
    await log_action(db, action="UPDATE_THREAT_PROFILE", tenant_id=principal.tenant_id, user_id=principal.actor,
                     details={"sectors": out["sectors"], "countries": out["countries"]}, ip_address=client_ip(request))
    return out


@router.get("/actors")
async def list_actors(q: str | None = Query(None, max_length=100), kind: str | None = None,
                      principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = await actors_svc.ranked(db, principal.tenant_id)
    if kind:
        rows = [a for a in rows if a["kind"] == kind]
    if q:
        needle = actors_svc.norm(q)
        rows = [a for a in rows if any(needle in k for k in actors_svc.keys(a))
                or any(needle in actors_svc.norm(m) for m in a.get("malware", []))]
    return [{k: a[k] for k in ("id", "name", "aliases", "kind", "origin", "motivation", "sectors", "countries", "builtin",
                               "relevance", "reasons", "observed", "posts_30d", "malware")}
            | {"techniques": len(a.get("techniques", []))} for a in rows]


@router.get("/actors/attack-matrix")
async def attack_matrix(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    return await actors_svc.matrix(db, principal.tenant_id)


@router.get("/actors/{actor_id}")
async def get_actor(actor_id: str, principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    a = await actors_svc.detail(db, principal.tenant_id, actor_id)
    if a is None:
        raise HTTPException(404, "Actor not found")
    return a


class ActorCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    aliases: list[str] = Field(default_factory=list, max_length=30)
    kind: Literal["apt", "ransomware", "cybercrime", "hacktivist"] = "cybercrime"
    origin: str | None = Field(None, max_length=64)
    motivation: str | None = Field(None, max_length=64)
    description: str = Field("", max_length=8000)
    sectors: list[str] = Field(default_factory=list, max_length=len(SECTORS))
    countries: list[str] = Field(default_factory=list, max_length=60)
    techniques: list[str] = Field(default_factory=list, max_length=200)
    malware: list[str] = Field(default_factory=list, max_length=50)
    references: list[str] = Field(default_factory=list, max_length=20)


@router.post("/actors", status_code=201)
async def create_actor(body: ActorCreate, request: Request, principal: Principal = Depends(require_scope("write")),
                       db: AsyncSession = Depends(get_db)):
    existing = await actors_svc.all_actors(db, principal.tenant_id)
    if actors_svc.norm(body.name) in {k for a in existing for k in actors_svc.keys(a)}:
        raise HTTPException(409, "An actor with this name or alias already exists")
    bad = [t for t in body.techniques if not re.fullmatch(r"T\d{4}(\.\d{3})?", t)]
    if bad:
        raise HTTPException(422, f"Not ATT&CK technique ids: {', '.join(bad[:5])}")
    row = ThreatActor(tenant_id=principal.tenant_id, name=body.name.strip(), aliases=[a.strip()[:64] for a in body.aliases if a.strip()],
                      kind=body.kind, origin=body.origin, motivation=body.motivation, description=body.description,
                      sectors=[s for s in body.sectors if s in SECTORS],
                      countries=[c.upper() for c in body.countries if re.fullmatch(r"[A-Za-z]{2}|\*[A-Z_]+", c)],
                      techniques=sorted(set(body.techniques)), malware=[m[:64] for m in body.malware],
                      references=[r for r in body.references if r.startswith(("https://", "http://"))])
    db.add(row)
    await db.commit()
    await log_action(db, action="CREATE_THREAT_ACTOR", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="threat_actor", resource_id=row.id, details={"name": row.name}, ip_address=client_ip(request))
    return await actors_svc.detail(db, principal.tenant_id, row.id)


@router.delete("/actors/{actor_id}", status_code=204)
async def delete_actor(actor_id: str, request: Request, principal: Principal = Depends(require_scope("write")),
                       db: AsyncSession = Depends(get_db)):
    if actor_id.startswith("builtin:"):
        raise HTTPException(403, "Built-in actors cannot be deleted")
    row = await db.get(ThreatActor, actor_id)
    if row is None or row.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Actor not found")
    await db.delete(row)
    await db.commit()
    await log_action(db, action="DELETE_THREAT_ACTOR", tenant_id=principal.tenant_id, user_id=principal.actor,
                     resource_type="threat_actor", resource_id=actor_id, details={"name": row.name},
                     ip_address=client_ip(request))
    return Response(status_code=204)


@router.get("/attack/techniques")
async def techniques(principal: Principal = Depends(require_scope("read"))):
    return [{"id": t, "name": n, "tactic": tac, "mitigation": m} for t, (n, tac, m) in sorted(TECHNIQUES.items())]


# ── IOCs ─────────────────────────────────────────────────────────────────────


def _ioc(i: Ioc, *, full: bool = False) -> dict:
    out = {"id": i.id, "type": i.type, "value": i.value, "verdict": i.verdict, "score": i.score,
           "verdict_override": i.verdict_override, "malware": i.malware or [], "actors": i.actors or [],
           "tags": i.tags or [], "tlp": i.tlp, "sightings": len(i.sightings or []),
           "asset_sightings": sum(1 for s in i.sightings or [] if s.get("kind") == "asset"),
           "sources": {k: (v.get("summary") if "error" not in v else f"error: {v['error']}")
                       for k, v in (i.enrichment or {}).items() if isinstance(v, dict)},
           "first_seen": iso(i.first_seen), "last_enriched_at": iso(i.last_enriched_at)}
    if full:
        out |= {"enrichment": i.enrichment or {}, "sightings_detail": i.sightings or [], "note": i.note,
                "created_by": i.created_by}
    return out


@router.get("/iocs/sources")
async def ioc_sources(principal: Principal = Depends(require_scope("read"))):
    """Which enrichment sources are configured on this deployment."""
    return ioc_svc.configured()


class HuntRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000, description="Indicators separated by whitespace, commas or newlines; defanged values are accepted")
    tags: list[str] = Field(default_factory=list, max_length=10)


@router.post("/iocs/hunt")
async def hunt(body: HuntRequest, request: Request, principal: Principal = Depends(require_scope("write")),
               db: AsyncSession = Depends(get_db)):
    out = await ioc_svc.hunt(db, principal.tenant_id, body.text, actor=principal.email or principal.actor,
                             tags=[t.strip()[:40] for t in body.tags if t.strip()])
    if not out["results"]:
        raise HTTPException(422, "No indicators found in the input" + (f" (rejected: {', '.join(out['rejected'][:5])})" if out["rejected"] else ""))
    opened = await incidents_svc.sync(db, principal.tenant_id)
    await log_action(db, action="IOC_HUNT", tenant_id=principal.tenant_id, user_id=principal.actor,
                     details={"indicators": len(out["results"]), "malicious": sum(1 for r, _ in out["results"] if r.verdict == "malicious")},
                     ip_address=client_ip(request))
    results = sorted(out["results"], key=lambda rc: (_VERDICT_ORDER.get(rc[0].verdict, 9), -rc[0].score))
    return {"results": [{**_ioc(r), "new": created} for r, created in results], "rejected": out["rejected"],
            "truncated": out["truncated"], "incidents_opened": len(opened)}


@router.get("/iocs")
async def list_iocs(type: str | None = None, verdict: str | None = None, q: str | None = Query(None, max_length=200),
                    sighted: bool = False, limit: int = Query(1000, ge=1, le=5000),
                    principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    stmt = select(Ioc).where(Ioc.tenant_id == principal.tenant_id)
    if type:
        stmt = stmt.where(Ioc.type == type)
    if verdict:
        stmt = stmt.where(Ioc.verdict == verdict)
    if q:
        stmt = stmt.where(or_(Ioc.value.ilike(f"%{q}%"), Ioc.note.ilike(f"%{q}%")))
    rows = (await db.execute(stmt.order_by(Ioc.first_seen.desc()).limit(limit))).scalars().all()
    if sighted:
        rows = [r for r in rows if r.sightings]
    rows.sort(key=lambda r: (_VERDICT_ORDER.get(r.verdict, 9), -r.score))
    return [_ioc(r) for r in rows]


@router.get("/iocs/stats")
async def ioc_stats(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Ioc.type, Ioc.verdict, Ioc.sightings).where(Ioc.tenant_id == principal.tenant_id))).all()
    by_verdict = {v: 0 for v in _VERDICT_ORDER}
    by_type: dict[str, int] = {}
    for t, v, _ in rows:
        by_verdict[v] = by_verdict.get(v, 0) + 1
        by_type[t] = by_type.get(t, 0) + 1
    return {"total": len(rows), "by_verdict": by_verdict, "by_type": by_type,
            "sighted_malicious": sum(1 for _, v, s in rows if v == "malicious" and any(x.get("kind") == "asset" for x in s or []))}


def _tlp_allowed(max_tlp: str) -> list[str]:
    order = ["clear", "green", "amber", "red"]
    return order[: order.index(max_tlp) + 1]


async def _export_rows(db: AsyncSession, tenant_id: str, min_verdict: str, max_tlp: str, added_after: datetime | None = None):
    verdicts = ["malicious"] if min_verdict == "malicious" else ["malicious", "suspicious"] if min_verdict == "suspicious" \
        else ["malicious", "suspicious", "unknown", "clean"]
    stmt = select(Ioc).where(Ioc.tenant_id == tenant_id, Ioc.verdict.in_(verdicts), Ioc.tlp.in_(_tlp_allowed(max_tlp)))
    if added_after:
        stmt = stmt.where(Ioc.last_enriched_at > added_after)
    return (await db.execute(stmt.order_by(Ioc.last_enriched_at))).scalars().all()


@router.get("/iocs/export/stix")
async def export_stix(min_verdict: Literal["malicious", "suspicious", "any"] = "suspicious",
                      max_tlp: Literal["clear", "green", "amber", "red"] = "amber",
                      principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = await _export_rows(db, principal.tenant_id, min_verdict, max_tlp)
    tenant = await db.get(Tenant, principal.tenant_id)
    bundle = ioc_svc.stix_bundle(ioc_svc.stix_objects(principal.tenant_id, tenant.name, rows,
                                                      await actors_svc.all_actors(db, principal.tenant_id)))
    return Response(json.dumps(bundle, indent=2), media_type="application/stix+json;version=2.1",
                    headers={"Content-Disposition": 'attachment; filename="secyourscan-iocs.stix.json"'})


@router.get("/iocs/export/blocklist.txt")
async def export_blocklist(type: Literal["ip", "domain", "url", "md5", "sha1", "sha256"] = "ip",
                           principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    """Malicious indicators of one type, one per line: for firewall, proxy or DNS blocklists."""
    rows = (await db.execute(select(Ioc.value).where(Ioc.tenant_id == principal.tenant_id, Ioc.type == type,
                                                    Ioc.verdict == "malicious").order_by(Ioc.value))).scalars().all()
    return Response("\n".join(rows) + ("\n" if rows else ""), media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="blocklist-{type}.txt"'})


@router.get("/iocs/{ioc_id}")
async def get_ioc(ioc_id: str, principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    row = await db.get(Ioc, ioc_id)
    if row is None or row.tenant_id != principal.tenant_id:
        raise HTTPException(404, "IOC not found")
    return _ioc(row, full=True)


class IocUpdate(BaseModel):
    verdict: Literal["malicious", "suspicious", "clean", "unknown"] | None = None
    clear_override: bool = False
    tags: list[str] | None = Field(None, max_length=20)
    note: str | None = Field(None, max_length=4000)
    tlp: Literal["clear", "green", "amber", "red"] | None = None


@router.patch("/iocs/{ioc_id}")
async def update_ioc(ioc_id: str, body: IocUpdate, request: Request, principal: Principal = Depends(require_scope("write")),
                     db: AsyncSession = Depends(get_db)):
    row = await db.get(Ioc, ioc_id)
    if row is None or row.tenant_id != principal.tenant_id:
        raise HTTPException(404, "IOC not found")
    if body.verdict:
        row.verdict, row.verdict_override = body.verdict, True
    elif body.clear_override:
        row.verdict_override = False
        row.verdict, row.score = ioc_svc.verdict(row.enrichment or {})
    if body.tags is not None:
        row.tags = sorted({t.strip()[:40] for t in body.tags if t.strip()})
    if body.note is not None:
        row.note = body.note
    if body.tlp:
        row.tlp = body.tlp
    await db.commit()
    await log_action(db, action="UPDATE_IOC", tenant_id=principal.tenant_id, user_id=principal.actor, resource_type="ioc",
                     resource_id=row.id, details=body.model_dump(exclude_none=True), ip_address=client_ip(request))
    return _ioc(row, full=True)


@router.post("/iocs/{ioc_id}/enrich")
async def re_enrich(ioc_id: str, principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    row = await db.get(Ioc, ioc_id)
    if row is None or row.tenant_id != principal.tenant_id:
        raise HTTPException(404, "IOC not found")
    await ioc_svc.refresh(db, row)
    await db.commit()
    await incidents_svc.sync(db, principal.tenant_id)
    return _ioc(row, full=True)


@router.delete("/iocs/{ioc_id}", status_code=204)
async def delete_ioc(ioc_id: str, request: Request, principal: Principal = Depends(require_scope("write")),
                     db: AsyncSession = Depends(get_db)):
    row = await db.get(Ioc, ioc_id)
    if row is None or row.tenant_id != principal.tenant_id:
        raise HTTPException(404, "IOC not found")
    await db.delete(row)
    await db.commit()
    await log_action(db, action="DELETE_IOC", tenant_id=principal.tenant_id, user_id=principal.actor, resource_type="ioc",
                     resource_id=ioc_id, details={"value": row.value}, ip_address=client_ip(request))
    return Response(status_code=204)


# ── TAXII 2.1 (read-only) ────────────────────────────────────────────────────
# One API root and one collection per tenant, served to an API key with the
# "read" scope (Authorization: Bearer sys_… or X-API-Key). Point a SIEM/TIP's
# TAXII 2.1 client at /taxii2/ to pull the tenant's suspicious and malicious
# indicators up to TLP:AMBER.

TAXII = "application/taxii+json;version=2.1"
STIX = "application/stix+json;version=2.1"
COLLECTION_ID = "b3c1f2e4-7a1d-4f6b-9a0e-5c2d8e7f1a90"


def _taxii(data: dict, media=TAXII) -> Response:
    return Response(json.dumps(data), media_type=media)


@router.get("/taxii2/", include_in_schema=False)
async def taxii_discovery(principal: Principal = Depends(require_scope("read"))):
    return _taxii({"title": "SecYourScan TAXII", "description": "Indicators from SecYourScan IOC Hunting",
                   "default": "/taxii2/api/", "api_roots": ["/taxii2/api/"]})


@router.get("/taxii2/api/", include_in_schema=False)
async def taxii_root(principal: Principal = Depends(require_scope("read"))):
    return _taxii({"title": "SecYourScan", "versions": [TAXII], "max_content_length": 10_485_760})


def _collection() -> dict:
    return {"id": COLLECTION_ID, "title": "SecYourScan indicators",
            "description": "Malicious and suspicious indicators, TLP:CLEAR to TLP:AMBER",
            "can_read": True, "can_write": False, "media_types": [STIX]}


@router.get("/taxii2/api/collections/", include_in_schema=False)
async def taxii_collections(principal: Principal = Depends(require_scope("read"))):
    return _taxii({"collections": [_collection()]})


@router.get("/taxii2/api/collections/{collection_id}/", include_in_schema=False)
async def taxii_collection(collection_id: str, principal: Principal = Depends(require_scope("read"))):
    if collection_id != COLLECTION_ID:
        raise HTTPException(404, "Unknown collection")
    return _taxii(_collection())


@router.get("/taxii2/api/collections/{collection_id}/objects/", include_in_schema=False)
async def taxii_objects(collection_id: str, added_after: str | None = None, limit: int = Query(1000, ge=1, le=5000),
                        principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    if collection_id != COLLECTION_ID:
        raise HTTPException(404, "Unknown collection")
    after = None
    if added_after:
        try:
            after = datetime.fromisoformat(added_after.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            raise HTTPException(400, "added_after must be an RFC 3339 timestamp")
    every = await _export_rows(db, principal.tenant_id, "suspicious", "amber", after)
    rows = every[:limit]  # oldest first, so a client resumes with added_after = X-TAXII-Date-Added-Last
    tenant = await db.get(Tenant, principal.tenant_id)
    objects = ioc_svc.stix_objects(principal.tenant_id, tenant.name, rows, await actors_svc.all_actors(db, principal.tenant_id))
    resp = _taxii({"more": len(every) > limit, "objects": objects}, media=TAXII)
    if rows:
        first, last = rows[0].last_enriched_at, rows[-1].last_enriched_at
        resp.headers["X-TAXII-Date-Added-First"] = ioc_svc._ts(first)
        resp.headers["X-TAXII-Date-Added-Last"] = ioc_svc._ts(last)
    return resp
