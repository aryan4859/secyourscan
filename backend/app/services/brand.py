"""Brand protection: registered lookalikes of the tenant's domains.

Permutations in the spirit of dnstwist — omission, transposition, keyboard
replacement, homoglyphs, hyphenation, combosquatting, TLD swaps — are
generated for the registrable part of each watched domain, then checked in
DNS. Only domains that exist are stored. Risk rises with what an attacker
would need for phishing: a web server (A), mail (MX) and a certificate.

Lookalike sites are never fetched: visiting them from your network is the
attacker's goal, not ours.
"""

import asyncio
import logging

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import Lookalike, PhishingUrl, WatchItem, utcnow

logger = logging.getLogger("secyourscan.brand")

_SLDS = {"com", "co", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "mil"}
_KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl", "p": "ol",
    "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv", "h": "gyjb", "j": "hukn", "k": "jilm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
_GLYPHS = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"], "e": ["3"], "s": ["5"],
           "m": ["rn"], "w": ["vv"], "g": ["q"], "q": ["g"], "b": ["6"], "z": ["2"]}
_MULTI_GLYPHS = {"rn": "m", "vv": "w", "cl": "d", "nn": "m"}
_COMBO = ["login", "secure", "account", "verify", "support", "online", "portal", "mail", "pay", "auth", "my", "app"]
_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "xyz", "online", "site", "app", "shop", "top", "live", "me",
         "us", "uk", "in", "cc", "tk", "click", "link", "support", "help", "services"]
_VOWELS = "aeiou"


def split_domain(domain: str) -> tuple[str, str]:
    """('jbbl', 'com.np') for jbbl.com.np; ('example', 'com') for a.example.com."""
    labels = domain.lower().strip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLDS:
        return labels[-3], ".".join(labels[-2:])
    return (labels[-2], labels[-1]) if len(labels) >= 2 else (labels[0], "")


def _ok(label: str) -> bool:
    return 1 <= len(label) <= 63 and label[0] != "-" and label[-1] != "-" and all(c.isalnum() or c == "-" for c in label)


def permutations(domain: str) -> list[tuple[str, str]]:
    """[(candidate, technique)], most deceptive techniques first."""
    name, suffix = split_domain(domain)
    out: dict[str, str] = {}

    def add(label: str, tech: str, sfx: str = suffix):
        if _ok(label) and (label, sfx) != (name, suffix):
            out.setdefault(f"{label}.{sfx}", tech)

    for i, ch in enumerate(name):
        for g in _GLYPHS.get(ch, []):
            add(name[:i] + g + name[i + 1:], "homoglyph")
    for seq, rep in _MULTI_GLYPHS.items():
        if seq in name:
            add(name.replace(seq, rep, 1), "homoglyph")
    for i in range(len(name)):
        add(name[:i] + name[i + 1:], "omission")
    for i in range(len(name) - 1):
        add(name[:i] + name[i + 1] + name[i] + name[i + 2:], "transposition")
    for i, ch in enumerate(name):
        for k in _KEYBOARD.get(ch, ""):
            add(name[:i] + k + name[i + 1:], "replacement")
    for i, ch in enumerate(name):
        add(name[:i] + ch + name[i:], "repetition")
    for i, ch in enumerate(name):
        if ch in _VOWELS:
            for v in _VOWELS:
                add(name[:i] + v + name[i + 1:], "vowel-swap")
    for i in range(1, len(name)):
        add(name[:i] + "-" + name[i:], "hyphenation")
    for i, ch in enumerate(name):
        for k in _KEYBOARD.get(ch, ""):
            add(name[:i] + k + name[i:], "insertion")
    for w in _COMBO:
        add(f"{name}-{w}", "combosquatting")
        add(f"{w}-{name}", "combosquatting")
        add(f"{name}{w}", "combosquatting")
    for t in _TLDS:
        add(name, "tld-swap", t)
    if "." in suffix:
        add(name, "tld-swap", suffix.split(".")[-1])  # jbbl.np for jbbl.com.np
        add(name + suffix.split(".")[0], "tld-swap", suffix.split(".")[-1])
    for c in "abcdefghijklmnopqrstuvwxyz":
        add(name + c, "addition")
    return list(out.items())[: settings.LOOKALIKE_MAX_CANDIDATES]


# ── Network primitives (patched in tests) ────────────────────────────────────


async def dns_profile(domain: str) -> dict | None:
    """None if the domain does not exist; otherwise its A and MX records."""
    r = dns.asyncresolver.Resolver()
    r.lifetime = 5
    exists, ips, mx = False, [], False
    try:
        ips = sorted({a.to_text() for a in await r.resolve(domain, "A")})
        exists = True
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        exists = True
    except (dns.exception.DNSException, OSError):
        return None
    try:
        mx = bool(await r.resolve(domain, "MX"))
    except (dns.exception.DNSException, OSError):
        pass
    return {"ips": ips, "mx": mx} if exists else None


async def has_certificate(domain: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=40) as c:
            r = await c.get(settings.CRTSH_URL, params={"q": domain, "output": "json"})
            return r.status_code == 200 and bool(r.json())
    except (httpx.HTTPError, ValueError):
        return False


async def openphish_urls() -> list[str]:
    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as c:
        for attempt in range(2):  # the community feed drops the odd request
            try:
                r = await c.get(settings.OPENPHISH_URL)
                r.raise_for_status()
                return [u.strip() for u in r.text.splitlines() if u.strip().startswith("http")]
            except httpx.HTTPError:
                if attempt:
                    raise
                await asyncio.sleep(3)
    return []


async def phishstats_search(term: str) -> list[dict]:
    async with httpx.AsyncClient(timeout=40) as c:
        r = await c.get(settings.PHISHSTATS_URL, params={"_where": f"(url,like,~{term}~)", "_sort": "-date", "_size": 100})
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []


def mentions(url: str, term: str) -> bool:
    """The brand appears as its own word: a hostname label part (jbbl-login.xyz,
    jbbl.com.np.evil.top) or a path/query token — never inside a random token
    such as an auth string (...ALAegJBBlmT...)."""
    import re

    return re.search(rf"(?<![a-z0-9]){re.escape(term.lower())}(?![a-z0-9])", url.lower()) is not None


def _url_host(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


async def scan_phishing(db: AsyncSession, tenant_id: str, domains: list[str], lookalikes: set[str]) -> dict:
    """Phishing URLs in public feeds that name the brand, a watched domain, or
    one of its registered lookalikes. URLs on the real domains are skipped."""
    own = set()
    terms: dict[str, str] = {}
    for d in domains:
        name, suffix = split_domain(d)
        own.add(f"{name}.{suffix}")
        terms[f"{name}.{suffix}"] = f"{name}.{suffix}"
        if len(name) >= 4:
            terms[name] = f"{name}.{suffix}"
    for lk in lookalikes:
        terms[lk] = lk

    def legit(host):
        return any(host == o or host.endswith("." + o) for o in own)

    hits: dict[str, tuple[str, str, str | None]] = {}  # url -> (target, source, ip)
    feeds = {}
    try:
        feed = await openphish_urls()
        feeds["openphish"] = len(feed)
        for url in feed:
            low = url.lower()
            for term, target in terms.items():
                if mentions(url, term) and not legit(_url_host(url)):
                    hits.setdefault(url, (target, "openphish", None))
                    break
    except (httpx.HTTPError, ValueError) as exc:
        logger.info("OpenPhish failed: %s", exc)
        feeds["openphish"] = "error"
    searched = 0
    for term, target in list(terms.items())[:10]:
        if "." in term and term not in lookalikes:
            continue  # the brand label already covers the domain
        try:
            rows = await phishstats_search(term)
            searched += len(rows)
        except (httpx.HTTPError, ValueError) as exc:
            logger.info("PhishStats %r failed: %s", term, exc)
            feeds["phishstats"] = "error"
            continue
        for row in rows:
            url = str(row.get("url") or "")
            if url and mentions(url, term) and not legit(_url_host(url)):
                hits.setdefault(url, (target, "phishstats", row.get("ip")))
    feeds.setdefault("phishstats", searched)

    existing = {p.url: p for p in (await db.execute(select(PhishingUrl).where(PhishingUrl.tenant_id == tenant_id))).scalars()}
    now = utcnow()
    new = []
    for url, (target, source, ip) in hits.items():
        row = existing.get(url[:1024])
        if row is None:
            db.add(PhishingUrl(tenant_id=tenant_id, url=url[:1024], host=_url_host(url)[:255] or "?", target=target,
                               source=source, ip=ip, first_seen=now, last_seen=now))
            new.append(url)
        else:
            row.last_seen = now
    await db.commit()
    return {"phishing_found": len(hits), "new_phishing": new, "phishing_feeds": feeds}


# ── Scan ─────────────────────────────────────────────────────────────────────

_CLOSE = {"homoglyph", "omission", "transposition", "replacement", "repetition", "vowel-swap", "insertion", "hyphenation"}


def risk(technique: str, ips: list[str], mx: bool, cert: bool) -> int:
    score = 30 + (25 if ips else 0) + (20 if mx else 0) + (15 if cert else 0)
    score += 10 if technique in _CLOSE or technique == "combosquatting" else 0
    return min(score, 100)


async def scan_brand(db: AsyncSession, tenant_id: str) -> dict:
    from .domains import in_scope

    domains = await in_scope(db, tenant_id, (await db.execute(select(WatchItem.value).where(
        WatchItem.tenant_id == tenant_id, WatchItem.type == "domain", WatchItem.is_active.is_(True)))).scalars().all())
    own = {".".join(split_domain(d)) for d in domains} | set(domains)
    candidates: dict[str, tuple[str, str]] = {}
    for d in domains:
        target = ".".join(split_domain(d))
        for cand, tech in permutations(d):
            if cand not in own:
                candidates.setdefault(cand, (target, tech))

    sem = asyncio.Semaphore(40)

    async def check(name):
        async with sem:
            return name, await dns_profile(name)

    live = {n: p for n, p in await asyncio.gather(*(check(n) for n in candidates)) if p}
    cert_sem = asyncio.Semaphore(3)

    async def cert(name):
        async with cert_sem:
            return name, await has_certificate(name)

    # crt.sh is slow; only check the lookalikes that could actually host something.
    certs = dict(await asyncio.gather(*(cert(n) for n, p in list(live.items())[:40] if p["ips"])))

    existing = {x.domain: x for x in (await db.execute(select(Lookalike).where(Lookalike.tenant_id == tenant_id))).scalars()}
    now = utcnow()
    new_high = []
    for name, prof in live.items():
        target, tech = candidates[name]
        row = existing.get(name)
        if row is None:
            row = Lookalike(tenant_id=tenant_id, domain=name, target=target, technique=tech, first_seen=now)
            db.add(row)
        row.ips, row.has_mx = prof["ips"], prof["mx"]
        row.has_cert = certs.get(name, row.has_cert)
        score = risk(tech, prof["ips"], prof["mx"], row.has_cert)
        if score >= 70 and (name not in existing or existing[name].risk < 70):
            new_high.append(name)
        row.risk = score
        row.last_seen = now
    await db.commit()
    phishing = await scan_phishing(db, tenant_id, list(domains), set(live))
    return {"domains": len(domains), "checked": len(candidates), "registered": len(live), "new_high_risk": new_high,
            **phishing}
