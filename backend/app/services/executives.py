"""Executive / VIP protection.

An executive is a name plus the emails, handles and phone numbers that belong
to them. Their profile pulls together, from data already collected:

* leaks naming their email, name, handle or phone (dark web, paste, Telegram…);
* identity intelligence for their mailboxes (stealer infections, reuse);
* impersonation: lookalike domains and phishing URLs built from their name,
  and handles seen in underground chatter.

Their emails and name are mirrored onto the watchlist as VIP items so the
pipeline raises and notifies on new matches as they arrive.
"""

import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Executive, Leak, Lookalike, PhishingUrl, TakedownRequest, WatchItem
from . import identity
from .normalization import normalize_identifier

ROW_CAP = 20_000
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugs(name: str) -> set[str]:
    """Strings an impersonation domain is built from: johncarter, john-carter, jcarter."""
    parts = [p for p in _SLUG_RE.split(name.lower()) if p]
    if len(parts) < 2:
        return {parts[0]} if parts and len(parts[0]) >= 5 else set()
    first, last = parts[0], parts[-1]
    return {f"{first}{last}", f"{first}-{last}", f"{first}.{last}", f"{first[0]}{last}", f"{last}{first}"}


async def sync_watchlist(db: AsyncSession, x: Executive) -> int:
    """Make sure each email and the full name are VIP watch items."""
    want = [("email", normalize_identifier(e, "email")) for e in x.emails or []]
    if len(x.name.strip()) >= 3:
        want.append(("keyword", x.name.strip().lower()))
    n = 0
    for typ, value in want:
        row = await db.scalar(select(WatchItem).where(WatchItem.tenant_id == x.tenant_id, WatchItem.type == typ,
                                                      WatchItem.value == value))
        if row is None:
            db.add(WatchItem(tenant_id=x.tenant_id, type=typ, value=value, is_vip=True))
            n += 1
        elif not row.is_vip or not row.is_active:
            row.is_vip, row.is_active = True, True
            n += 1
    await db.flush()
    return n


def _needles(x: Executive) -> dict[str, list[str]]:
    return {
        "email": [normalize_identifier(e, "email") for e in x.emails or []],
        "name": [x.name.lower()] if len(x.name) >= 5 else [],
        "handle": [h.lower().lstrip("@") for h in x.usernames or [] if len(h.lstrip("@")) >= 4],
        "phone": [re.sub(r"\D", "", p) for p in x.phones or [] if len(re.sub(r"\D", "", p)) >= 7],
    }


async def profiles(db: AsyncSession, tenant_id: str, *, only: str | None = None) -> list[dict]:
    q = select(Executive).where(Executive.tenant_id == tenant_id).order_by(Executive.name)
    if only:
        q = q.where(Executive.id == only)
    execs = (await db.execute(q)).scalars().all()
    if not execs:
        return []

    leaks = (await db.execute(
        select(Leak.id, Leak.title, Leak.source, Leak.source_url, Leak.severity, Leak.status, Leak.discovered_at,
               Leak.snippet, Leak.entities)
        .where(Leak.tenant_id == tenant_id).order_by(Leak.discovered_at.desc()).limit(ROW_CAP))).all()
    lookalikes = (await db.execute(select(Lookalike).where(Lookalike.tenant_id == tenant_id))).scalars().all()
    phishing = (await db.execute(select(PhishingUrl).where(PhishingUrl.tenant_id == tenant_id))).scalars().all()
    takedowns = (await db.execute(select(TakedownRequest.target, TakedownRequest.status, TakedownRequest.id)
                                  .where(TakedownRequest.tenant_id == tenant_id))).all()
    td_by_target = {t.target.lower(): {"id": t.id, "status": t.status} for t in takedowns}
    ident = await identity.collect(db, tenant_id)

    out = []
    for x in execs:
        needles = _needles(x)
        mentions = []
        for lk in leaks:
            low = (lk.snippet or "").lower()
            emails = set((lk.entities or {}).get("emails") or [])
            digits = re.sub(r"\D", "", lk.snippet or "") if needles["phone"] else ""
            how = [f"email {e}" for e in needles["email"] if e in emails or e in low]
            how += [f"name “{x.name}”" for n in needles["name"] if n in low]
            how += [f"handle @{h}" for h in needles["handle"] if h in low]
            how += [f"phone ending {p[-4:]}" for p in needles["phone"] if p in digits]
            if how:
                mentions.append({"leak_id": lk.id, "title": lk.title or lk.source, "source": lk.source,
                                 "url": lk.source_url, "severity": lk.severity, "status": lk.status,
                                 "at": lk.discovered_at.isoformat(), "matched": how})

        sl = slugs(x.name)
        imp = []
        for la in lookalikes:
            if any(s in la.domain for s in sl):
                imp.append({"kind": "domain", "target": la.domain, "detail": f"lookalike of {la.target} ({la.technique})",
                            "risk": la.risk, "source_type": "lookalike", "source_id": la.id,
                            "takedown": td_by_target.get(la.domain.lower())})
        for p in phishing:
            if any(s in p.url.lower() for s in sl):
                imp.append({"kind": "url", "target": p.url, "detail": f"phishing page via {p.source}", "risk": 85,
                            "source_type": "phishing", "source_id": p.id, "takedown": td_by_target.get(p.url.lower())})
        for m in mentions:
            if any("handle" in h for h in m["matched"]) and m["source"] in ("telegram", "onion", "ahmia"):
                imp.append({"kind": "social", "target": m["url"] or m["title"], "detail": f"handle mentioned on {m['source']}",
                            "risk": 60, "source_type": "leak", "source_id": m["leak_id"],
                            "takedown": td_by_target.get((m["url"] or "").lower())})

        accounts = [identity._out(i, detail=False) for e in needles["email"] if (i := ident["identities"].get(e))]
        stealer = [a for a in accounts if a["stealer"]]
        open_mentions = [m for m in mentions if m["status"] in ("new", "reviewing", "escalated")]
        risk = min(100, (40 if stealer else 0) + (20 if any(a["reused"] for a in accounts) else 0)
                   + min(25, 5 * len(open_mentions)) + min(30, 10 * len(imp))
                   + (10 if any(m["severity"] >= 80 for m in open_mentions) else 0))
        out.append({
            "id": x.id, "name": x.name, "title": x.title, "emails": x.emails, "usernames": x.usernames, "phones": x.phones,
            "notes": x.notes, "created_at": x.created_at.isoformat(), "risk": risk,
            "band": "critical" if risk >= 80 else "high" if risk >= 60 else "medium" if risk >= 30 else "low",
            "counts": {"mentions": len(mentions), "open_mentions": len(open_mentions), "accounts": len(accounts),
                       "stealer": len(stealer), "impersonation": len(imp),
                       "dark_web": sum(1 for m in mentions if m["source"] in ("ahmia", "onion", "telegram"))},
            "mentions": mentions[:100], "accounts": accounts, "impersonation": imp,
            "last_seen": max((m["at"] for m in mentions), default=None),
        })
    out.sort(key=lambda p: (-p["risk"], p["name"]))
    return out
