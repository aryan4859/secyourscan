"""Takedown requests: who to ask, what to send, where it stands.

For a domain or URL the registrar and the hosting network are looked up over
RDAP (rdap.org bootstraps to the right registry / RIR) and their abuse
contacts collected. An evidence pack is assembled from the finding the
request came from, and a notice is drafted for the analyst to send. Nothing
is emailed from here: the analyst sends it and records the outcome.
"""

import logging
from urllib.parse import urlsplit

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Leak, Lookalike, PhishingUrl, TakedownRequest, utcnow
from . import easm

logger = logging.getLogger("secyourscan.takedown")

RDAP = "https://rdap.org"
STATUSES = ("draft", "submitted", "acknowledged", "taken_down", "rejected", "withdrawn")
OPEN = ("draft", "submitted", "acknowledged")
REASONS = {
    "phishing": "is being used for phishing: it imitates our organisation to collect credentials or payments from our customers and staff",
    "impersonation": "impersonates our organisation or one of our executives",
    "trademark": "uses our registered trademark without authorisation in a way likely to confuse the public",
    "data_leak": "publishes confidential data stolen from our organisation",
    "malware": "distributes malware or hosts command-and-control infrastructure",
    "fraud": "is being used to defraud our customers",
}


def host_of(target: str) -> str:
    t = target if "://" in target else f"http://{target}"
    try:
        return (urlsplit(t).hostname or "").lower()
    except ValueError:
        return ""


def _vcard(entity: dict) -> tuple[str | None, str | None]:
    name = email = None
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        if item[0] == "fn":
            name = str(item[3])[:255]
        elif item[0] == "email":
            email = str(item[3])[:255]
    return name, email


def _contacts(doc: dict, source: str) -> tuple[str | None, list[dict]]:
    """Registrar / network name and every abuse contact in an RDAP document."""
    owner, out = None, []

    def walk(entities, parent_roles=()):
        nonlocal owner
        for e in entities or []:
            roles = set(e.get("roles") or [])
            name, email = _vcard(e)
            if "registrar" in roles and name and owner is None:
                owner = name
            if ("registrant" in roles or "administrative" in roles) and name and owner is None and source == "network":
                owner = name
            if email and ("abuse" in roles or "abuse" in parent_roles):
                out.append({"role": f"{source} abuse", "name": name, "email": email, "source": "rdap"})
            walk(e.get("entities"), tuple(roles))

    walk(doc.get("entities"))
    if source == "network" and not owner:
        owner = doc.get("name") or doc.get("handle")
    return owner, out


async def rdap(kind: str, value: str) -> dict:
    async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers=easm.UA) as c:
        r = await c.get(f"{RDAP}/{kind}/{value}")
        r.raise_for_status()
        return r.json()


def _registered(host: str) -> str:
    """Registrable domain, good enough for RDAP: the last two labels (three for
    common second-level suffixes like co.uk)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org", "gov", "ac", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


async def lookup(target: str) -> dict:
    """Registrar, hosting network and abuse contacts for a domain or URL."""
    host = host_of(target)
    result = {"host": host, "registrar": None, "hosting": None, "ips": [], "contacts": [], "errors": []}
    if not host or host.endswith(".onion"):
        result["errors"].append("no RDAP for this target (onion or not a hostname)")
        return result
    try:
        result["registrar"], contacts = _contacts(await rdap("domain", _registered(host)), "registrar")
        result["contacts"] += contacts
    except (httpx.HTTPError, ValueError) as exc:
        result["errors"].append(f"domain RDAP: {str(exc)[:160]}")
    try:
        result["ips"] = (await easm.resolve_a(host))[:4]
    except Exception as exc:  # noqa: BLE001 — DNS failures are reported, not fatal
        result["errors"].append(f"DNS: {str(exc)[:160]}")
    if result["ips"]:
        try:
            result["hosting"], contacts = _contacts(await rdap("ip", result["ips"][0]), "network")
            result["contacts"] += contacts
        except (httpx.HTTPError, ValueError) as exc:
            result["errors"].append(f"IP RDAP: {str(exc)[:160]}")
    seen, uniq = set(), []
    for c in result["contacts"]:
        if c["email"].lower() not in seen:
            seen.add(c["email"].lower())
            uniq.append(c)
    result["contacts"] = uniq
    return result


async def evidence_for(db: AsyncSession, tenant_id: str, source_type: str | None, source_id: str | None) -> tuple[dict, str | None, str]:
    """(evidence, target, kind) for the finding a takedown starts from."""
    if source_type == "lookalike":
        x = await db.get(Lookalike, source_id)
        if x and x.tenant_id == tenant_id:
            return ({"finding": "lookalike domain", "imitates": x.target, "technique": x.technique, "risk": x.risk,
                     "mail_server": x.has_mx, "tls_certificate": x.has_cert, "ips": x.ips,
                     "first_seen": x.first_seen.isoformat()}, x.domain, "domain")
    elif source_type == "phishing":
        p = await db.get(PhishingUrl, source_id)
        if p and p.tenant_id == tenant_id:
            return ({"finding": "phishing URL", "targets": p.target, "reported_by": p.source, "ip": p.ip,
                     "first_seen": p.first_seen.isoformat()}, p.url, "url")
    elif source_type == "leak":
        lk = await db.get(Leak, source_id)
        if lk and lk.tenant_id == tenant_id:
            return ({"finding": "leaked content", "title": lk.title, "source": lk.source, "severity": lk.severity,
                     "category": lk.category, "sha256": lk.sha256, "first_seen": lk.discovered_at.isoformat(),
                     "excerpt": (lk.snippet or "")[:400]}, lk.source_url, "content")
    return {}, None, "url"


def draft_notice(org: str, td: TakedownRequest) -> str:
    why = REASONS.get(td.reason, REASONS["phishing"])
    ev = td.evidence or {}
    lines = [f"Subject: Abuse report: {td.target} ({td.reason.replace('_', ' ')})", "",
             "Hello,", "",
             f"We are writing on behalf of {org}. The {'domain' if td.kind == 'domain' else 'resource'} below {why}.", "",
             f"  Target:      {td.target}"]
    if td.registrar:
        lines.append(f"  Registrar:   {td.registrar}")
    if td.hosting:
        lines.append(f"  Hosted by:   {td.hosting}")
    for k, v in ev.items():
        if v not in (None, "", [], {}) and k != "excerpt":
            lines.append(f"  {k.replace('_', ' ').capitalize() + ':':<13}{', '.join(map(str, v)) if isinstance(v, list) else v}")
    if ev.get("excerpt"):
        lines += ["", "Excerpt (secrets masked):", *("  " + ln for ln in str(ev["excerpt"]).splitlines()[:8])]
    lines += ["", "We ask that you suspend or remove it under your acceptable-use policy and confirm by reply.",
              "We can provide further evidence on request. This report is made in good faith; the information in it is",
              "accurate to the best of our knowledge.", "", "Regards,", f"{org} security team",
              f"Reference: TD-{td.number:04d}"]
    return "\n".join(lines)


async def next_number(db: AsyncSession, tenant_id: str) -> int:
    return (await db.scalar(select(func.max(TakedownRequest.number)).where(TakedownRequest.tenant_id == tenant_id)) or 0) + 1


async def write_back(db: AsyncSession, td: TakedownRequest) -> None:
    """Mirror progress onto the finding the request came from."""
    if td.source_type == "lookalike":
        x = await db.get(Lookalike, td.source_id)
        if x and x.tenant_id == td.tenant_id and td.status in ("draft", "submitted", "acknowledged", "taken_down"):
            x.status = "takedown"
    elif td.source_type == "phishing":
        p = await db.get(PhishingUrl, td.source_id)
        if p and p.tenant_id == td.tenant_id:
            if td.status in ("submitted", "acknowledged"):
                p.status = "reported"
            elif td.status == "taken_down":
                p.status = "down"
    elif td.source_type == "leak" and td.status == "taken_down":
        lk = await db.get(Leak, td.source_id)
        if lk and lk.tenant_id == td.tenant_id and lk.status in ("new", "reviewing", "escalated"):
            lk.status = "resolved"


def serialize(td: TakedownRequest, full: bool = False) -> dict:
    now = utcnow()
    base = {"id": td.id, "ref": f"TD-{td.number:04d}", "kind": td.kind, "target": td.target, "reason": td.reason,
            "status": td.status, "source_type": td.source_type, "source_id": td.source_id, "registrar": td.registrar,
            "hosting": td.hosting, "contacts": td.contacts, "created_by": td.created_by,
            "created_at": td.created_at.isoformat(),
            "submitted_at": td.submitted_at.isoformat() if td.submitted_at else None,
            "resolved_at": td.resolved_at.isoformat() if td.resolved_at else None,
            "age_days": (now - td.created_at).days,
            "hours_to_resolve": round((td.resolved_at - (td.submitted_at or td.created_at)).total_seconds() / 3600, 1)
            if td.resolved_at else None}
    if full:
        base.update({"evidence": td.evidence, "notice": td.notice, "history": td.history})
    return base


async def stats(db: AsyncSession, tenant_id: str) -> dict:
    rows = (await db.execute(select(TakedownRequest).where(TakedownRequest.tenant_id == tenant_id))).scalars().all()
    done = [r for r in rows if r.status == "taken_down" and r.resolved_at]
    closed = [r for r in rows if r.status in ("taken_down", "rejected")]
    hours = [(r.resolved_at - (r.submitted_at or r.created_at)).total_seconds() / 3600 for r in done]
    return {"total": len(rows), "open": sum(1 for r in rows if r.status in OPEN),
            "by_status": {s: sum(1 for r in rows if r.status == s) for s in STATUSES},
            "by_kind": {k: sum(1 for r in rows if r.kind == k) for k in ("domain", "url", "content", "social")},
            "success_rate": round(100 * len(done) / len(closed)) if closed else None,
            "median_hours": round(sorted(hours)[len(hours) // 2], 1) if hours else None}
