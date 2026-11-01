"""IOC hunting: enrich indicators across reputation sources, retro-hunt them in
the tenant's own data, keep them in a store and share them as STIX 2.1.

Sources, each optional and best-effort (a failing source is recorded, never fatal):

==============  =========================  ==================================
source          indicator types            needs
==============  =========================  ==================================
abuse.ch feeds  ip, domain, url, hashes    nothing (URLhaus/Feodo/ThreatFox
                                           recent exports, cached 1 h, matched
                                           locally)
InternetDB      ip                         nothing (Shodan)
ThreatFox API   ip, domain, url, hashes    ABUSECH_AUTH_KEY
MalwareBazaar   hashes                     ABUSECH_AUTH_KEY
AlienVault OTX  ip, domain, url, hashes    OTX_API_KEY
AbuseIPDB       ip                         ABUSEIPDB_API_KEY
VirusTotal      ip, domain, url, hashes    VIRUSTOTAL_API_KEY
==============  =========================  ==================================

Private and reserved IP addresses are never sent anywhere.

A "sighting" is the indicator appearing in the tenant's own data: its attack
surface, watchlist, vendors (``kind: asset``) or a leak, lookalike or
phishing record (``kind: mention``). A malicious indicator with an asset
sighting opens an incident.
"""

import asyncio
import base64
import ipaddress
import logging
import re
import uuid
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import Ioc, Leak, Lookalike, PhishingUrl, SurfaceHost, Vendor, WatchItem, utcnow
from . import actors as actors_svc
from . import cti, intel, reputation

logger = logging.getLogger("secyourscan.ioc")
UA = {"User-Agent": "SecYourScan/1.0 (+self-hosted exposure monitoring)"}
TIMEOUT = httpx.Timeout(12.0)
TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256", "email")
HASHES = ("md5", "sha1", "sha256")
MAX_HUNT = 100
FEED_TTL = timedelta(hours=1)
STALE_AFTER = timedelta(days=7)

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[a-z0-9.-]+\.[a-z]{2,63}$")
_HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


# ── Parsing ──────────────────────────────────────────────────────────────────


def refang(value: str) -> str:
    v = value.strip().strip("\"'<>`").strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    v = re.sub(r"^fxp", "ftp", v, flags=re.I)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":"), ("[@]", "@"), ("[at]", "@")):
        v = v.replace(a, b)
    return v


def classify(raw: str) -> tuple[str, str] | None:
    """(type, normalised value), or None when it is not an indicator."""
    v = refang(raw)
    if not v or len(v) > 1024:
        return None
    if re.fullmatch(r"[A-Fa-f0-9]+", v) and len(v) in _HASH_LEN:
        return _HASH_LEN[len(v)], v.lower()
    if re.match(r"^[a-z][a-z0-9+.-]{1,15}://", v, re.I):
        return "url", v
    try:
        return "ip", str(ipaddress.ip_address(v))
    except ValueError:
        pass
    low = v.lower().rstrip(".")
    if _EMAIL_RE.fullmatch(low):
        return "email", low
    if _DOMAIN_RE.fullmatch(low):
        return "domain", low
    return None


def parse_many(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Split on whitespace and commas; (indicators, rejected tokens). De-duplicated, order kept."""
    seen, out, bad = set(), [], []
    for tok in re.split(r"[\s,;]+", text or ""):
        if not tok:
            continue
        c = classify(tok)
        if c is None:
            bad.append(tok[:100])
        elif c not in seen:
            seen.add(c)
            out.append(c)
    return out, bad


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def host_of(ioc_type: str, value: str) -> str | None:
    if ioc_type == "domain":
        return value
    if ioc_type == "url":
        return reputation._host(value) or None
    return None


# ── Providers ────────────────────────────────────────────────────────────────
# Each returns None when it does not apply (type or missing key), or a dict:
#   {"found": bool, "score": 0–100, "malware": [...], "tags": [...], "summary": str, …}


def _abusech_key() -> str | None:
    return settings.ABUSECH_AUTH_KEY or settings.THREATFOX_AUTH_KEY


async def _feed_index(db: AsyncSession) -> dict:
    """abuse.ch recent exports, cached 1 h: {indicator or host: [listing, …]}."""
    row = await intel.cache_get(db, "feed:abusech")
    if row is None or utcnow() - row.updated_at >= FEED_TTL:
        items, errors = [], []
        for name, fn in (("urlhaus", reputation.urlhaus), ("feodo", reputation.feodo), ("threatfox", reputation.threatfox)):
            try:
                items += [[e["indicator"], e.get("host"), e["feed"], e.get("malware"), e.get("threat")] for e in await fn()]
            except (httpx.HTTPError, ValueError, KeyError, AttributeError) as exc:
                logger.info("abuse.ch %s feed failed: %s", name, exc)
                errors.append(name)
        if items or row is None:
            await intel.cache_put(db, "feed:abusech", {"items": items, "errors": errors})
            row = await intel.cache_get(db, "feed:abusech")
    index: dict[str, list] = {"_errors": row.data.get("errors", [])}
    for ind, host, feed, malware, threat in row.data.get("items", []):
        entry = {"feed": feed, "indicator": ind, "malware": malware, "threat": threat}
        index.setdefault(str(ind).lower(), []).append(entry)
        if host and host != ind:
            index.setdefault(f"host:{str(host).lower()}", []).append(entry)
    return index


def feeds_lookup(index: dict, ioc_type: str, value: str) -> dict:
    exact = index.get(value.lower(), [])
    host = host_of(ioc_type, value) or (value if ioc_type == "ip" else None)
    by_host = index.get(f"host:{host.lower()}", []) if host else []
    hits = exact or by_host
    down = set(index.get("_errors", []))
    if not hits:
        names = {"urlhaus": "URLhaus", "feodo": "Feodo Tracker", "threatfox": "ThreatFox"}
        checked = [n for k, n in names.items() if k not in down]
        if not checked:
            raise RuntimeError("no abuse.ch feed could be downloaded")
        return {"found": False, "score": 0,
                "summary": f"not in {', '.join(checked)}" + (f" ({', '.join(names[k] for k in sorted(down))} unavailable)" if down else "")}
    feeds = sorted({h["feed"] for h in hits})
    malware = sorted({h["malware"] for h in hits if h.get("malware")})
    # A listed URL on a host is strong for that URL, weaker for the whole host (shared hosting).
    strong = bool(exact) or ioc_type == "ip"
    return {"found": True, "score": (90 if "feodo" in feeds else 85) if strong else 55, "malware": malware,
            "tags": sorted({h["threat"] for h in hits if h.get("threat")}), "listings": hits[:10],
            "summary": f"listed by {', '.join(feeds)}" + ("" if strong else " (other URLs on this host)")}


async def internetdb(ioc_type: str, value: str) -> dict | None:
    if ioc_type != "ip":
        return None
    data = await cti.shodan_internetdb(value)
    if not data.get("found", True) or not (data.get("ports") or data.get("tags")):
        return {"found": False, "score": 0, "summary": "nothing known to Shodan"}
    tags = data.get("tags") or []
    bad = {"compromised", "malware", "c2", "botnet"} & {t.lower() for t in tags}
    return {"found": True, "score": 60 if bad else (25 if "tor" in tags else 0), "tags": tags,
            "ports": data.get("ports", []), "vulns": (data.get("vulns") or [])[:20], "hostnames": (data.get("hostnames") or [])[:10],
            "summary": f"{len(data.get('ports', []))} open port(s)" + (f", tags: {', '.join(tags)}" if tags else "")}


async def threatfox_api(ioc_type: str, value: str) -> dict | None:
    if not _abusech_key() or ioc_type == "email":
        return None
    body = {"query": "search_hash", "hash": value} if ioc_type in HASHES else {"query": "search_ioc", "search_term": value}
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={**UA, "Auth-Key": _abusech_key()}) as c:
        r = await c.post("https://threatfox-api.abuse.ch/api/v1/", json=body)
        r.raise_for_status()
        data = r.json()
    rows = data.get("data") if data.get("query_status") == "ok" and isinstance(data.get("data"), list) else []
    if not rows:
        return {"found": False, "score": 0, "summary": "no ThreatFox record"}
    malware = sorted({x.get("malware_printable") for x in rows if x.get("malware_printable")})
    return {"found": True, "score": 90, "malware": malware,
            "tags": sorted({t for x in rows for t in (x.get("tags") or [])})[:20],
            "confidence": max((x.get("confidence_level") or 0) for x in rows),
            "summary": f"{len(rows)} ThreatFox record(s): {', '.join(malware) or 'unknown malware'}"}


async def malwarebazaar(ioc_type: str, value: str) -> dict | None:
    if not _abusech_key() or ioc_type not in HASHES:
        return None
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={**UA, "Auth-Key": _abusech_key()}) as c:
        r = await c.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": value})
        r.raise_for_status()
        data = r.json()
    if data.get("query_status") != "ok":
        return {"found": False, "score": 0, "summary": "not in MalwareBazaar"}
    s = (data.get("data") or [{}])[0]
    return {"found": True, "score": 95, "malware": [s["signature"]] if s.get("signature") else [],
            "tags": (s.get("tags") or [])[:20], "file_type": s.get("file_type"), "file_name": s.get("file_name"),
            "first_seen": s.get("first_seen"), "summary": f"malware sample: {s.get('signature') or s.get('file_type') or 'unknown'}"}


_OTX_SECTION = {"domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file"}


async def otx(ioc_type: str, value: str) -> dict | None:
    if not settings.OTX_API_KEY or ioc_type == "email":
        return None
    section = ("IPv6" if ":" in value else "IPv4") if ioc_type == "ip" else _OTX_SECTION[ioc_type]
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={**UA, "X-OTX-API-KEY": settings.OTX_API_KEY}) as c:
        r = await c.get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general")
        if r.status_code in (400, 404):
            return {"found": False, "score": 0, "summary": "unknown to OTX"}
        r.raise_for_status()
        data = r.json()
    if data.get("validation"):  # OTX's own allow-list: popular, known-good indicators
        return {"found": True, "score": 0, "summary": "on OTX's allow-list", "allowlisted": True}
    info = data.get("pulse_info") or {}
    count = int(info.get("count") or 0)
    pulses = info.get("pulses") or []
    malware = sorted({m.get("display_name") for p in pulses for m in (p.get("malware_families") or [])
                      if isinstance(m, dict) and m.get("display_name")})[:15]
    adversaries = sorted({p.get("adversary") for p in pulses if p.get("adversary")})[:10]
    return {"found": count > 0, "score": min(80, 30 + 10 * count) if count else 0, "pulses": count,
            "malware": malware, "adversaries": adversaries,
            "tags": sorted({t for p in pulses for t in (p.get("tags") or [])})[:20],
            "summary": f"in {count} OTX pulse(s)" if count else "in no OTX pulse"}


async def abuseipdb(ioc_type: str, value: str) -> dict | None:
    if not settings.ABUSEIPDB_API_KEY or ioc_type != "ip":
        return None
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={**UA, "Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}) as c:
        r = await c.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": value, "maxAgeInDays": 90})
        r.raise_for_status()
        d = r.json().get("data") or {}
    s = int(d.get("abuseConfidenceScore") or 0)
    return {"found": bool(d.get("totalReports")), "score": s, "reports": d.get("totalReports", 0), "country": d.get("countryCode"),
            "isp": d.get("isp"), "usage": d.get("usageType"),
            "summary": f"abuse confidence {s}% from {d.get('totalReports', 0)} report(s)"}


def _vt_path(ioc_type: str, value: str) -> str | None:
    if ioc_type == "ip":
        return f"ip_addresses/{value}"
    if ioc_type == "domain":
        return f"domains/{value}"
    if ioc_type == "url":
        return "urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    if ioc_type in HASHES:
        return f"files/{value}"
    return None


async def virustotal(ioc_type: str, value: str) -> dict | None:
    if not settings.VIRUSTOTAL_API_KEY or not (path := _vt_path(ioc_type, value)):
        return None
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={**UA, "x-apikey": settings.VIRUSTOTAL_API_KEY}) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/{path}")
        if r.status_code == 404:
            return {"found": False, "score": 0, "summary": "unknown to VirusTotal"}
        r.raise_for_status()
        attrs = (r.json().get("data") or {}).get("attributes") or {}
    st = attrs.get("last_analysis_stats") or {}
    m, s = int(st.get("malicious") or 0), int(st.get("suspicious") or 0)
    score = 90 if m >= 5 else 70 if m >= 2 else 45 if (m or s) else 0
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    return {"found": True, "score": score, "malicious": m, "suspicious": s,
            "engines": sum(int(v or 0) for v in st.values()), "malware": [label] if label else [],
            "reputation": attrs.get("reputation"), "summary": f"{m} engine(s) malicious, {s} suspicious"}


PROVIDERS = {
    "internetdb": internetdb, "threatfox": threatfox_api, "malwarebazaar": malwarebazaar,
    "otx": otx, "abuseipdb": abuseipdb, "virustotal": virustotal,
}
BROAD = {"otx", "abuseipdb", "virustotal"}  # a clean answer from one of these means "clean", not just "not listed"


def configured() -> dict:
    return {"abuse.ch feeds": True, "internetdb": True, "threatfox": bool(_abusech_key()), "malwarebazaar": bool(_abusech_key()),
            "otx": bool(settings.OTX_API_KEY), "abuseipdb": bool(settings.ABUSEIPDB_API_KEY),
            "virustotal": bool(settings.VIRUSTOTAL_API_KEY)}


def verdict(enrichment: dict) -> tuple[str, int]:
    answered = {k: v for k, v in enrichment.items() if isinstance(v, dict) and "error" not in v and not k.startswith("_")}
    if any(v.get("allowlisted") for v in answered.values()):
        return "clean", 0
    score = max((int(v.get("score") or 0) for v in answered.values()), default=0)
    if score >= 75:
        return "malicious", score
    if score >= 40:
        return "suspicious", score
    if answered.keys() & BROAD:
        return "clean", score
    return "unknown", score


async def enrich(db: AsyncSession, ioc_type: str, value: str, feed_index: dict | None = None) -> dict:
    """{source: result or {"error": …}} for every source that applies."""
    if ioc_type == "ip" and not is_public_ip(value):
        return {"_note": {"summary": "private or reserved address: not looked up externally"}}
    out: dict = {}
    if ioc_type != "email":
        try:
            out["abuse.ch feeds"] = feeds_lookup(feed_index if feed_index is not None else await _feed_index(db), ioc_type, value)
        except Exception as exc:  # noqa: BLE001
            out["abuse.ch feeds"] = {"error": str(exc)[:200]}

    async def one(name, fn):
        try:
            return name, await fn(ioc_type, value)
        except Exception as exc:  # noqa: BLE001 — any provider failure is data, not a crash
            logger.info("%s lookup of %s failed: %s", name, value, exc)
            return name, {"error": f"{type(exc).__name__}: {str(exc)[:160]}"}

    for name, res in await asyncio.gather(*(one(n, f) for n, f in PROVIDERS.items())):
        if res is not None:
            out[name] = res
    return out


# ── Retro-hunt in our own data ───────────────────────────────────────────────


async def sightings(db: AsyncSession, tenant_id: str, ioc_type: str, value: str) -> list[dict]:
    v = value.lower()
    out: list[dict] = []

    def add(kind, where, ref=None):
        if len(out) < 25:
            out.append({"kind": kind, "where": where, "ref": ref})

    if ioc_type in ("ip", "domain", "url"):
        host = v if ioc_type != "url" else (host_of("url", value) or "")
        for h in (await db.execute(select(SurfaceHost).where(SurfaceHost.tenant_id == tenant_id))).scalars():
            if (ioc_type == "ip" and v in (h.ips or [])) or (host and h.hostname == host):
                add("asset", f"attack surface host {h.hostname}", f"surface:{h.id}")
        for vd in (await db.execute(select(Vendor).where(Vendor.tenant_id == tenant_id))).scalars():
            if host and (host == vd.domain or host.endswith("." + vd.domain)):
                add("asset", f"vendor {vd.name} ({vd.domain})", f"vendor:{vd.id}")
        for x in (await db.execute(select(Lookalike).where(Lookalike.tenant_id == tenant_id))).scalars():
            if (ioc_type == "ip" and v in (x.ips or [])) or (host and x.domain == host):
                add("mention", f"lookalike domain {x.domain}", f"lookalike:{x.id}")
        for p in (await db.execute(select(PhishingUrl).where(PhishingUrl.tenant_id == tenant_id))).scalars():
            if (ioc_type == "ip" and p.ip == v) or (host and p.host == host) or (ioc_type == "url" and p.url == value):
                add("mention", f"phishing URL {p.url[:120]}", f"phishing:{p.id}")
    watch_type = {"ip": "ip", "domain": "domain", "email": "email"}.get(ioc_type)
    if watch_type:
        for w in (await db.execute(select(WatchItem).where(WatchItem.tenant_id == tenant_id, WatchItem.type == watch_type))).scalars():
            if w.value.lower() == v or (watch_type == "domain" and v.endswith("." + w.value.lower())):
                add("asset", f"watchlist {w.type} {w.value}", f"watch:{w.id}")
    entity_key = {"ip": "ips", "domain": "domains", "email": "emails"}.get(ioc_type)
    leaks = (await db.execute(select(Leak).where(Leak.tenant_id == tenant_id).order_by(Leak.discovered_at.desc())
                              .limit(5000))).scalars()
    for lk in leaks:
        ents = lk.entities or {}
        hit = (entity_key and v in [str(x).lower() for x in ents.get(entity_key, [])]) \
            or (ioc_type == "sha256" and lk.sha256 == v) \
            or (ioc_type in ("url", *HASHES) and v in (lk.snippet or "").lower())
        if hit:
            add("mention", f"leak “{(lk.title or lk.source)[:80]}”", f"leak:{lk.id}")
    return out


# ── Store ────────────────────────────────────────────────────────────────────


def _attribute(row: Ioc, enrichment: dict, actor_list: list[dict]) -> None:
    malware = sorted({m for v in enrichment.values() if isinstance(v, dict) for m in (v.get("malware") or []) if m})[:20]
    names = set(row.actors or [])
    mal_norm = {actors_svc.norm(m) for m in malware}
    adversaries = {actors_svc.norm(a) for v in enrichment.values() if isinstance(v, dict) for a in (v.get("adversaries") or [])}
    for a in actor_list:
        if mal_norm & {actors_svc.norm(m) for m in a.get("malware", [])} or adversaries & actors_svc.keys(a):
            names.add(a["name"])
    row.malware, row.actors = malware, sorted(names)


async def refresh(db: AsyncSession, row: Ioc, *, feed_index: dict | None = None, actor_list: list[dict] | None = None,
                  enrichment: dict | None = None) -> Ioc:
    row.enrichment = enrichment if enrichment is not None else await enrich(db, row.type, row.value, feed_index)
    if not row.verdict_override:
        row.verdict, row.score = verdict(row.enrichment)
    row.sightings = await sightings(db, row.tenant_id, row.type, row.value)
    _attribute(row, row.enrichment, actor_list if actor_list is not None else await actors_svc.all_actors(db, row.tenant_id))
    row.last_enriched_at = utcnow()
    return row


async def hunt(db: AsyncSession, tenant_id: str, text: str, *, actor: str | None, tags: list[str] | None = None) -> dict:
    items, rejected = parse_many(text)
    truncated = len(items) > MAX_HUNT
    items = items[:MAX_HUNT]
    index = await _feed_index(db) if any(t != "email" for t, _ in items) else {}
    actor_list = await actors_svc.all_actors(db, tenant_id)
    sem = asyncio.Semaphore(5)
    results = []

    async def enrich_only(t, v):
        async with sem:
            return t, v, await enrich(db, t, v, index)

    # Network lookups in parallel; database writes one at a time on this session.
    pre = {(t, v): e for t, v, e in await asyncio.gather(*(enrich_only(t, v) for t, v in items))}
    for t, v in items:
        row = await db.scalar(select(Ioc).where(Ioc.tenant_id == tenant_id, Ioc.type == t, Ioc.value == v))
        created = row is None
        if created:
            row = Ioc(tenant_id=tenant_id, type=t, value=v, created_by=actor, first_seen=utcnow(), tags=tags or [])
            db.add(row)
        elif tags:
            row.tags = sorted(set(row.tags or []) | set(tags))
        await refresh(db, row, actor_list=actor_list, enrichment=pre[(t, v)])
        await db.flush()
        results.append((row, created))
    await db.commit()
    return {"results": results, "rejected": rejected[:50], "truncated": truncated}


async def refresh_stale(db: AsyncSession, tenant_id: str, limit: int = 200) -> int:
    cutoff = utcnow() - STALE_AFTER
    rows = (await db.execute(select(Ioc).where(Ioc.tenant_id == tenant_id,
                                               (Ioc.last_enriched_at.is_(None)) | (Ioc.last_enriched_at < cutoff))
                             .limit(limit))).scalars().all()
    if not rows:
        return 0
    index = await _feed_index(db)
    actor_list = await actors_svc.all_actors(db, tenant_id)
    for row in rows:
        await refresh(db, row, feed_index=index, actor_list=actor_list)
        await db.commit()
    return len(rows)


# ── STIX 2.1 ─────────────────────────────────────────────────────────────────

# Standard TLP 1.0 marking definitions from the STIX 2.1 specification.
TLP_MARKINGS = {
    "clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
_NS = uuid.UUID("6f1d2c8e-5b7a-4c1e-9a0f-2b3c4d5e6f70")  # SecYourScan's namespace for deterministic STIX ids


def _sid(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, '|'.join(parts))}"


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def pattern(ioc_type: str, value: str) -> str:
    v = _esc(value)
    if ioc_type == "ip":
        return f"[{'ipv6-addr' if ':' in value else 'ipv4-addr'}:value = '{v}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{v}']"
    if ioc_type == "url":
        return f"[url:value = '{v}']"
    if ioc_type == "email":
        return f"[email-addr:value = '{v}']"
    return f"[file:hashes.'{_STIX_HASH[ioc_type]}' = '{v}']"


_STIX_HASH = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}


def _ts(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def stix_objects(tenant_id: str, tenant_name: str, rows: list[Ioc], actor_list: list[dict]) -> list[dict]:
    identity = {"type": "identity", "spec_version": "2.1", "id": _sid("identity", tenant_id),
                "created": "2024-01-01T00:00:00.000Z", "modified": "2024-01-01T00:00:00.000Z",
                "name": f"SecYourScan · {tenant_name}", "identity_class": "organization"}
    objs: list[dict] = [identity]
    actor_objs: dict[str, dict] = {}
    for r in rows:
        created = _ts(r.first_seen)
        modified = _ts(r.last_enriched_at or r.first_seen)
        ind_id = _sid("indicator", tenant_id, r.type, r.value)
        labels = sorted({*(r.tags or []), *(r.malware or [])})
        ind = {"type": "indicator", "spec_version": "2.1", "id": ind_id, "created": created, "modified": modified,
               "created_by_ref": identity["id"], "name": r.value[:250], "pattern": pattern(r.type, r.value),
               "pattern_type": "stix", "valid_from": created, "confidence": r.score,
               "indicator_types": ["malicious-activity"] if r.verdict == "malicious" else ["anomalous-activity"],
               "object_marking_refs": [TLP_MARKINGS.get(r.tlp, TLP_MARKINGS["amber"])]}
        if labels:
            ind["labels"] = labels[:20]
        if r.note:
            ind["description"] = r.note[:2000]
        objs.append(ind)
        for name in r.actors or []:
            a = next((x for x in actor_list if x["name"] == name), None)
            if name not in actor_objs:
                actor_objs[name] = {"type": "threat-actor", "spec_version": "2.1", "id": _sid("threat-actor", name),
                                    "created": "2024-01-01T00:00:00.000Z", "modified": "2024-01-01T00:00:00.000Z",
                                    "name": name, "aliases": (a or {}).get("aliases", [])[:20],
                                    "threat_actor_types": ["nation-state" if (a or {}).get("kind") == "apt" else "crime-syndicate"]}
                objs.append(actor_objs[name])
            objs.append({"type": "relationship", "spec_version": "2.1", "id": _sid("relationship", ind_id, name),
                         "created": created, "modified": modified, "relationship_type": "indicates",
                         "source_ref": ind_id, "target_ref": actor_objs[name]["id"]})
    return objs


def stix_bundle(objects: list[dict]) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
