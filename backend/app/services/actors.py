"""Threat-actor intelligence: who is likely to come after this tenant, and how.

Relevance is explained, not a black box. Each actor gets points for
* having named the tenant (or one of its vendors) on a leak site — observed;
* targeting the tenant's sectors and countries (from the threat profile);
* current activity in the ransomware leak-site feed (cached, last 30 days);
* indicators in the tenant's IOC store attributed to it.

The ATT&CK view weights each technique by the relevant actors that use it,
which turns "who" into "what to defend first".
"""

import re
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Incident, Ioc, RansomwareHit, ThreatActor, Vendor, utcnow
from . import intel
from .actors_data import ACTORS, REGIONS, SECTORS, TACTICS, TECHNIQUES
from .ransomware import _date

RELEVANT = 25  # relevance at which an actor counts toward the ATT&CK view


def norm(s: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _builtin(a: dict) -> dict:
    return {**{k: v for k, v in a.items() if k != "slug"}, "id": f"builtin:{a['slug']}", "builtin": True}


def _custom(a: ThreatActor) -> dict:
    return {"id": a.id, "builtin": False, "name": a.name, "aliases": a.aliases or [], "kind": a.kind, "origin": a.origin,
            "motivation": a.motivation, "description": a.description, "sectors": a.sectors or [],
            "countries": a.countries or [], "techniques": a.techniques or [], "malware": a.malware or [],
            "references": a.references or []}


def keys(actor: dict) -> set[str]:
    return {k for k in [norm(actor["name"]), *(norm(x) for x in actor.get("aliases", []))] if k}


async def all_actors(db: AsyncSession, tenant_id: str) -> list[dict]:
    custom = (await db.execute(select(ThreatActor).where(ThreatActor.tenant_id == tenant_id))).scalars().all()
    return [_builtin(a) for a in ACTORS] + [_custom(a) for a in custom]


def find_by_group(actors: list[dict], group: str | None) -> dict | None:
    g = norm(group)
    if not g:
        return None
    return next((a for a in actors if g in keys(a)), None)


# ── Threat profile ───────────────────────────────────────────────────────────


def _profile_key(tenant_id: str) -> str:
    return f"profile:{tenant_id}"


async def get_profile(db: AsyncSession, tenant_id: str) -> dict:
    row = await intel.cache_get(db, _profile_key(tenant_id))
    data = row.data if row else {}
    return {"sectors": data.get("sectors", []), "countries": data.get("countries", []), "sector_options": SECTORS}


async def set_profile(db: AsyncSession, tenant_id: str, sectors: list[str], countries: list[str]) -> dict:
    clean_c = sorted({c.strip().upper() for c in countries if re.fullmatch(r"[A-Za-z]{2}", c.strip())})
    clean_s = sorted({s for s in sectors if s in SECTORS})
    await intel.cache_put(db, _profile_key(tenant_id), {"sectors": clean_s, "countries": clean_c})
    return await get_profile(db, tenant_id)


# ── Relevance ────────────────────────────────────────────────────────────────


async def _context(db: AsyncSession, tenant_id: str) -> dict:
    """Everything relevance needs, loaded once per request. Never hits the network."""
    observed: dict[str, list[str]] = {}
    for h in (await db.execute(select(RansomwareHit).where(RansomwareHit.tenant_id == tenant_id,
                                                           RansomwareHit.status != "false_positive"))).scalars():
        observed.setdefault(norm(h.group), []).append(f"listed you as “{h.victim}”")
    for v in (await db.execute(select(Vendor).where(Vendor.tenant_id == tenant_id))).scalars():
        for b in v.breaches or []:
            observed.setdefault(norm(b.get("group")), []).append(f"listed your vendor {v.name}")
    for g in (await db.execute(select(Incident.actor).where(Incident.tenant_id == tenant_id,
                                                            Incident.actor.is_not(None)))).scalars():
        observed.setdefault(norm(g), [])

    activity: dict[str, int] = {}
    cached = await intel.cache_get(db, "feed:ransomware_recent")
    now = utcnow()
    for p in (cached.data.get("items", []) if cached else []):
        when = _date(p.get("discovered") or p.get("attackdate"))
        if when and now - when <= timedelta(days=30):
            activity[norm(p.get("group"))] = activity.get(norm(p.get("group")), 0) + 1

    ioc_actors: dict[str, int] = {}
    for names in (await db.execute(select(Ioc.actors).where(Ioc.tenant_id == tenant_id))).scalars():
        for n in names or []:
            ioc_actors[norm(n)] = ioc_actors.get(norm(n), 0) + 1
    return {"profile": await get_profile(db, tenant_id), "observed": observed, "activity": activity,
            "ioc_actors": ioc_actors}


def _country_match(actor_countries: list[str], ours: list[str]) -> tuple[int, str | None]:
    ours_set = set(ours)
    exact = sorted(ours_set & set(actor_countries))
    if exact:
        return 20, f"targets {', '.join(exact)}"
    for token, members in REGIONS.items():
        if token in actor_countries and ours_set & members:
            return 15, f"targets {token[1:].replace('_', ' ').title()} ({', '.join(sorted(ours_set & members))})"
    if "*GLOBAL" in actor_countries and ours_set:
        return 5, "targets organisations worldwide"
    return 0, None


def score(actor: dict, ctx: dict) -> tuple[int, list[str], bool]:
    """(relevance 0–100, reasons, observed)."""
    k = keys(actor)
    pts, reasons, observed = 0, [], False
    hit_keys = [key for key in k if key in ctx["observed"]]
    if hit_keys:
        observed = True
        seen = [r for key in hit_keys for r in ctx["observed"][key]]
        pts += 60
        reasons.append("Observed: " + ("; ".join(seen[:3]) if seen else "linked to one of your incidents"))
    sectors = sorted(set(actor.get("sectors", [])) & set(ctx["profile"]["sectors"]))
    if sectors:
        pts += 25
        reasons.append(f"Targets your sector: {', '.join(sectors)}")
    c_pts, c_reason = _country_match(actor.get("countries", []), ctx["profile"]["countries"])
    if c_pts:
        pts += c_pts
        reasons.append(c_reason[0].upper() + c_reason[1:])
    posts = sum(ctx["activity"].get(key, 0) for key in k)
    if posts:
        pts += min(15, 3 + posts // 5)
        reasons.append(f"{posts} leak-site post(s) in the last 30 days")
    iocs = sum(ctx["ioc_actors"].get(key, 0) for key in k)
    if iocs:
        pts += 10
        reasons.append(f"{iocs} indicator(s) in your IOC store")
    return min(100, pts), reasons, observed


async def ranked(db: AsyncSession, tenant_id: str) -> list[dict]:
    ctx = await _context(db, tenant_id)
    out = []
    for a in await all_actors(db, tenant_id):
        rel, reasons, observed = score(a, ctx)
        posts = sum(ctx["activity"].get(key, 0) for key in keys(a))
        out.append({**a, "relevance": rel, "reasons": reasons, "observed": observed, "posts_30d": posts})
    out.sort(key=lambda a: (-a["relevance"], -a["posts_30d"], a["name"].lower()))
    return out


async def detail(db: AsyncSession, tenant_id: str, actor_id: str) -> dict | None:
    actor = next((a for a in await ranked(db, tenant_id) if a["id"] == actor_id), None)
    if actor is None:
        return None
    k = keys(actor)
    hits = [h for h in (await db.execute(select(RansomwareHit).where(RansomwareHit.tenant_id == tenant_id))).scalars()
            if norm(h.group) in k]
    malware = {norm(m) for m in actor.get("malware", [])}
    iocs = [i for i in (await db.execute(select(Ioc).where(Ioc.tenant_id == tenant_id))).scalars()
            if {norm(x) for x in i.actors or []} & k or {norm(x) for x in i.malware or []} & malware]
    incidents = [i for i in (await db.execute(select(Incident).where(Incident.tenant_id == tenant_id,
                                                                     Incident.actor.is_not(None)))).scalars()
                 if norm(i.actor) in k]
    return {
        **actor,
        "techniques_detail": [{"id": t, "name": TECHNIQUES.get(t, (t, "other", ""))[0],
                               "tactic": TECHNIQUES.get(t, (t, "other", ""))[1],
                               "mitigation": TECHNIQUES.get(t, (t, "other", ""))[2]} for t in actor.get("techniques", [])],
        "your_hits": [{"id": h.id, "victim": h.victim, "status": h.status, "first_seen": h.first_seen.isoformat()} for h in hits],
        "your_iocs": [{"id": i.id, "type": i.type, "value": i.value, "verdict": i.verdict} for i in iocs[:50]],
        "your_incidents": [{"id": i.id, "number": i.number, "title": i.title, "status": i.status} for i in incidents],
    }


async def matrix(db: AsyncSession, tenant_id: str) -> dict:
    """ATT&CK tactics × techniques, weighted by relevant actors.

    With no profile and nothing observed, every actor counts, so the view is
    still useful on day one."""
    actors = await ranked(db, tenant_id)
    relevant = [a for a in actors if a["relevance"] >= RELEVANT]
    basis = relevant or actors
    by_tech: dict[str, list[str]] = {}
    for a in basis:
        for t in a.get("techniques", []):
            by_tech.setdefault(t, []).append(a["name"])
    columns = []
    for tid, label in TACTICS:
        cells = [{"id": t, "name": name, "mitigation": mit, "actors": sorted(by_tech.get(t, [])),
                  "count": len(by_tech.get(t, []))}
                 for t, (name, tactic, mit) in TECHNIQUES.items() if tactic == tid]
        cells.sort(key=lambda c: (-c["count"], c["id"]))
        if cells:
            columns.append({"tactic": tid, "label": label, "techniques": cells})
    top = sorted(({"id": t, "name": TECHNIQUES[t][0], "tactic": TECHNIQUES[t][1], "mitigation": TECHNIQUES[t][2],
                   "count": len(v), "actors": sorted(v)} for t, v in by_tech.items() if t in TECHNIQUES),
                 key=lambda x: (-x["count"], x["id"]))[:10]
    return {"basis": "relevant" if relevant else "all", "actors": len(basis), "max": max((len(v) for v in by_tech.values()), default=0),
            "columns": columns, "top": top}
