"""Ransomware leak-site monitoring via ransomware.live (keyless).

The tenant's domains and keywords are searched among published victims; any
post naming one is stored and alerted. The global feed of recent victims is
cached for the dashboard's "active groups" view.
"""

import logging
from datetime import datetime
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import RansomwareHit, WatchItem, utcnow
from .brand import split_domain

logger = logging.getLogger("secyourscan.ransomware")
UA = {"User-Agent": "SecYourScan/1.0 (+self-hosted exposure monitoring)"}
MAX_TERMS = 25


async def search_victims(term: str) -> list[dict]:
    async with httpx.AsyncClient(timeout=30, headers=UA) as c:
        r = await c.get(f"{settings.RANSOMWARE_LIVE_URL}/searchvictims/{quote(term, safe='')}")
        if r.status_code == 404:
            return []
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []


async def recent_victims() -> list[dict]:
    async with httpx.AsyncClient(timeout=30, headers=UA) as c:
        r = await c.get(f"{settings.RANSOMWARE_LIVE_URL}/recentvictims")
        r.raise_for_status()
        data = r.json()
        return [{**p, "source": "ransomware.live"} for p in data] if isinstance(data, list) else []


async def ransomlook_recent() -> list[dict]:
    """RansomLook's recent posts, reshaped to ransomware.live's fields."""
    async with httpx.AsyncClient(timeout=30, headers=UA) as c:
        r = await c.get(f"{settings.RANSOMLOOK_URL}/recent")
        r.raise_for_status()
        data = r.json()
    out = []
    for p in data if isinstance(data, list) else []:
        out.append({"group": p.get("group_name"), "victim": p.get("post_title"), "description": p.get("description") or "",
                    "discovered": str(p.get("discovered") or "").replace(" ", "T"), "source": "ransomlook"})
    return out


def merge_feeds(*feeds: list[dict]) -> list[dict]:
    """One list, first feed wins on (group, victim) duplicates."""
    seen, out = set(), []
    for feed in feeds:
        for p in feed:
            key = (str(p.get("group") or "").lower(), str(p.get("victim") or "").lower())
            if key not in seen:
                seen.add(key)
                out.append(p)
    return out


def _date(v) -> datetime | None:
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _terms(items: list[WatchItem]) -> list[tuple[str, str]]:
    """(search term, how to match) — a domain also matches its brand label."""
    out: dict[str, str] = {}
    for w in items:
        v = w.value.lower()
        if w.type == "domain":
            name, suffix = split_domain(v)
            out.setdefault(f"{name}.{suffix}", "domain")
            if len(name) >= 5:
                out.setdefault(name, "name")
        elif w.type == "keyword" and len(v) >= 4:
            out.setdefault(v, "keyword")
    return list(out.items())[:MAX_TERMS]


def _matches(post: dict, term: str, how: str) -> bool:
    victim = str(post.get("victim") or post.get("post_title") or "").lower()
    domain = str(post.get("domain") or post.get("website") or "").lower().removeprefix("www.")
    desc = str(post.get("description") or "").lower()
    if how == "domain":
        return domain == term or domain.endswith("." + term) or term in victim or term in desc
    return term in victim or term in domain.split(".")[0] or (how == "keyword" and term in desc)


async def scan_ransomware(db: AsyncSession, tenant_id: str, recent: list[dict]) -> dict:
    """``recent`` is the cached global feed, also matched so a fresh post is
    caught before the search index has it."""
    items = (await db.execute(select(WatchItem).where(WatchItem.tenant_id == tenant_id, WatchItem.is_active.is_(True),
                                                      WatchItem.type.in_(["domain", "keyword"])))).scalars().all()
    from .domains import in_scope

    allowed = set(await in_scope(db, tenant_id, [w.value for w in items if w.type == "domain"]))
    terms = _terms([w for w in items if w.type != "domain" or w.value in allowed])
    found: dict[tuple[str, str], tuple[dict, str]] = {}
    errors = 0
    for term, how in terms:
        try:
            posts = await search_victims(term)
        except (httpx.HTTPError, ValueError) as exc:
            logger.info("ransomware.live search %r failed: %s", term, exc)
            errors += 1
            posts = []
        for p in posts + recent:
            if _matches(p, term, how):
                key = (str(p.get("group") or p.get("group_name") or "unknown")[:64], str(p.get("victim") or p.get("post_title") or "")[:255])
                found.setdefault(key, (p, term))
    if terms and errors == len(terms):
        raise RuntimeError("ransomware.live did not answer any search")

    existing = {(h.group, h.victim): h for h in (await db.execute(
        select(RansomwareHit).where(RansomwareHit.tenant_id == tenant_id))).scalars()}
    new = []
    for (group, victim), (p, term) in found.items():
        if (group, victim) in existing:
            continue
        db.add(RansomwareHit(
            tenant_id=tenant_id, group=group, victim=victim, matched=term[:255],
            domain=(p.get("domain") or p.get("website") or None), country=(p.get("country") or None),
            activity=(str(p.get("activity"))[:64] if p.get("activity") else None),
            description=str(p.get("description") or "")[:4000],
            url=(p.get("url") or p.get("post_url") or None), attack_date=_date(p.get("attackdate") or p.get("discovered")),
            first_seen=utcnow()))
        new.append(f"{group}: {victim}")
    await db.commit()
    return {"terms": len(terms), "matches": len(found), "new": new}


def activity(recent: list[dict], days: int = 7) -> dict:
    """Group counts and latest posts from the global feed."""
    now = utcnow()
    groups: dict[str, int] = {}
    countries: dict[str, int] = {}
    latest = []
    for p in recent:
        when = _date(p.get("discovered") or p.get("attackdate"))
        if when is None or (now - when).days >= days:
            continue
        g = str(p.get("group") or "unknown")
        groups[g] = groups.get(g, 0) + 1
        if p.get("country"):
            countries[p["country"]] = countries.get(p["country"], 0) + 1
        latest.append({"group": g, "victim": p.get("victim"), "country": p.get("country"), "activity": p.get("activity"),
                       "discovered": when.isoformat(), "source": p.get("source")})
    latest.sort(key=lambda x: x["discovered"], reverse=True)
    sources: dict[str, int] = {}
    for p in recent:
        sources[p.get("source") or "unknown"] = sources.get(p.get("source") or "unknown", 0) + 1
    return {"days": days, "posts": len(latest), "sources": sources,
            "groups": sorted(({"group": g, "count": n} for g, n in groups.items()), key=lambda x: -x["count"])[:12],
            "countries": sorted(({"country": c, "count": n} for c, n in countries.items()), key=lambda x: -x["count"])[:10],
            "latest": latest[:15]}
