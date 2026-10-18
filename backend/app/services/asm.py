"""Attack-surface monitoring beyond discovery: critical ports, TLS grading,
DNS posture with change tracking, and the change log itself.

Ports come from Shodan InternetDB (no scanning). TLS grading makes a few
handshakes per live host on 443 — the default one plus one each pinned to
TLS 1.0 and 1.1 to see whether legacy protocols are still accepted. DNS is
plain lookups of the watched domains.
"""

import asyncio
import logging
import ssl
from datetime import datetime

import dns.asyncresolver
import dns.exception
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DnsRecord, SurfaceEvent, TlsGrade, WatchItem, utcnow

logger = logging.getLogger("secyourscan.asm")

# ── Critical ports ───────────────────────────────────────────────────────────

# port: (service, risk, why it matters)
PORT_RISK = {
    21: ("FTP", "high", "Cleartext credentials; often anonymous or brute-forced"),
    22: ("SSH", "medium", "Remote shell; brute-force and key-theft target"),
    23: ("Telnet", "critical", "Cleartext remote shell"),
    25: ("SMTP", "low", "Mail transfer; check it is not an open relay"),
    53: ("DNS", "medium", "Open resolvers are abused for amplification"),
    80: ("HTTP", "info", "Web; should redirect to HTTPS"),
    110: ("POP3", "medium", "Cleartext mail login"),
    111: ("RPCbind", "high", "Exposes RPC services; reconnaissance and amplification"),
    135: ("MS-RPC", "high", "Windows RPC; lateral-movement surface"),
    137: ("NetBIOS", "high", "Windows name service; information leak"),
    139: ("NetBIOS-SSN", "high", "Windows file sharing"),
    143: ("IMAP", "medium", "Cleartext mail login"),
    161: ("SNMP", "high", "Default communities leak device configuration"),
    389: ("LDAP", "high", "Directory service; data leak and amplification"),
    443: ("HTTPS", "info", "Web"),
    445: ("SMB", "critical", "Windows file sharing; wormable exploits, ransomware entry"),
    500: ("IKE/IPsec", "low", "VPN key exchange; keep the VPN patched"),
    1194: ("OpenVPN", "low", "VPN endpoint; keep it patched"),
    1433: ("MS SQL", "critical", "Database exposed to the internet"),
    1521: ("Oracle DB", "critical", "Database exposed to the internet"),
    1723: ("PPTP", "high", "Obsolete, breakable VPN protocol"),
    2049: ("NFS", "critical", "Network file system exposed"),
    2375: ("Docker API", "critical", "Unauthenticated Docker daemon = host takeover"),
    2376: ("Docker API (TLS)", "high", "Docker daemon reachable from the internet"),
    3306: ("MySQL", "critical", "Database exposed to the internet"),
    3389: ("RDP", "critical", "Remote desktop; top ransomware entry point"),
    4500: ("IPsec NAT-T", "low", "VPN; keep it patched"),
    5432: ("PostgreSQL", "critical", "Database exposed to the internet"),
    5900: ("VNC", "critical", "Remote desktop, often weakly authenticated"),
    5985: ("WinRM", "critical", "Windows remote management"),
    5986: ("WinRM (TLS)", "high", "Windows remote management"),
    6379: ("Redis", "critical", "Usually unauthenticated; remote code execution"),
    8080: ("HTTP-alt", "low", "Secondary web service; often admin or staging"),
    8443: ("HTTPS-alt", "low", "Secondary web service; often admin or VPN portal"),
    9000: ("Admin/PHP-FPM", "medium", "Frequently an admin panel or app server"),
    9200: ("Elasticsearch", "critical", "Search cluster; frequent source of data leaks"),
    9300: ("Elasticsearch transport", "critical", "Cluster transport exposed"),
    11211: ("Memcached", "critical", "Amplification and data leak"),
    27017: ("MongoDB", "critical", "Database exposed to the internet"),
    50000: ("SAP/DB2", "high", "Enterprise application server"),
}
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def classify_port(port: int) -> dict:
    service, risk, why = PORT_RISK.get(port, (None, None, None))
    return {"port": port, "service": service or "unknown", "risk": risk or "info", "why": why or ""}


# ── TLS grading ──────────────────────────────────────────────────────────────


async def _handshake(host: str, *, verify: bool, version: ssl.TLSVersion | None = None):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        ctx.minimum_version = ctx.maximum_version = version
        ctx.set_ciphers("ALL:@SECLEVEL=0")  # let a legacy handshake be attempted, so we can report it
    _, w = await asyncio.wait_for(asyncio.open_connection(host, 443, ssl=ctx, server_hostname=host), 8)
    try:
        so = w.get_extra_info("ssl_object")
        return so.version(), (so.cipher() or [None])[0], so.getpeercert(binary_form=True)
    finally:
        w.close()


async def probe_tls(host: str) -> dict | None:
    """Raw facts about ``host``:443, or None if nothing answers TLS there."""
    try:
        proto, cipher, der = await _handshake(host, verify=False)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None
    facts = {"protocol": proto, "cipher": cipher, "chain_valid": True, "chain_error": None}
    try:
        await _handshake(host, verify=True)
    except ssl.SSLCertVerificationError as exc:
        facts["chain_valid"], facts["chain_error"] = False, exc.verify_message or str(exc)[:200]
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        pass  # network hiccup on the second try; don't call the chain bad
    for name, ver in (("tls10", ssl.TLSVersion.TLSv1), ("tls11", ssl.TLSVersion.TLSv1_1)):
        try:
            await _handshake(host, verify=False, version=ver)
            facts[name] = True
        except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError):
            facts[name] = False
    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()
    facts.update({
        "not_after": cert.not_valid_after_utc.replace(tzinfo=None).isoformat(),
        "issuer": cert.issuer.rfc4514_string()[:255],
        "subject": cert.subject.rfc4514_string()[:255],
        "self_signed": cert.issuer == cert.subject,
        "sig_alg": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
        "key_type": "RSA" if isinstance(key, rsa.RSAPublicKey) else "EC" if isinstance(key, ec.EllipticCurvePublicKey) else type(key).__name__,
        "key_bits": getattr(key, "key_size", None),
    })
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    facts["names"] = sans[:50]
    facts["hostname_match"] = any(host == n or (n.startswith("*.") and host.split(".", 1)[-1] == n[2:]) for n in sans)
    return facts


def grade(facts: dict) -> tuple[str, list[dict]]:
    """A–F with the reasons, worst first. Caps, not a sum: one serious flaw
    decides the grade the way the SSL Labs scale does."""
    issues, cap = [], "A"
    order = "ABCDF"

    def flag(level, text, worst):
        nonlocal cap
        issues.append({"level": level, "text": text})
        cap = max(cap, worst, key=order.index)

    days = (utcnow() - datetime.fromisoformat(facts["not_after"])).days if facts.get("not_after") else None
    if days is not None and days > 0:
        flag("critical", f"Certificate expired {days} day(s) ago", "F")
    if facts.get("self_signed"):
        flag("critical", "Self-signed certificate", "F")
    elif not facts.get("chain_valid", True):
        flag("critical", f"Untrusted chain: {facts.get('chain_error') or 'verification failed'}", "F")
    if not facts.get("hostname_match", True):
        flag("critical", "Certificate does not cover this hostname", "F")
    if facts.get("tls10"):
        flag("warning", "Accepts TLS 1.0 (deprecated)", "C")
    if facts.get("tls11"):
        flag("warning", "Accepts TLS 1.1 (deprecated)", "C")
    if facts.get("key_type") == "RSA" and (facts.get("key_bits") or 0) < 2048:
        flag("critical", f"Weak RSA key ({facts.get('key_bits')} bits)", "F")
    if facts.get("sig_alg") in ("sha1", "md5"):
        flag("critical", f"Weak signature algorithm ({facts['sig_alg']})", "F")
    if days is not None and -14 <= days <= 0:
        flag("warning", f"Certificate expires in {-days} day(s)", "B")
    if facts.get("protocol") not in ("TLSv1.3",) and not issues:
        flag("info", f"Negotiated {facts.get('protocol')}; TLS 1.3 not offered", "B")
    issues.sort(key=lambda i: ["critical", "warning", "info"].index(i["level"]))
    return cap, issues


async def grade_hosts(db: AsyncSession, tenant_id: str, hosts: list[str]) -> dict:
    sem = asyncio.Semaphore(10)

    async def one(h):
        async with sem:
            try:
                return h, await probe_tls(h)
            except Exception as exc:  # noqa: BLE001
                logger.info("TLS probe %s failed: %s", h, exc)
                return h, None

    results = dict(await asyncio.gather(*(one(h) for h in hosts)))
    existing = {g.hostname: g for g in (await db.execute(select(TlsGrade).where(TlsGrade.tenant_id == tenant_id))).scalars()}
    now = utcnow()
    worsened = []
    for h, facts in results.items():
        if facts is None:
            continue
        g, issues = grade(facts)
        row = existing.get(h)
        if row is None:
            row = TlsGrade(tenant_id=tenant_id, hostname=h)
            db.add(row)
        elif "ABCDF".index(g) > "ABCDF".index(row.grade) and g in ("D", "F"):
            worsened.append(f"{h}: {row.grade} → {g}")
        row.grade, row.issues, row.details, row.checked_at = g, issues, facts, now
    await db.commit()
    grades = [grade(f)[0] for f in results.values() if f]
    return {"graded": len(grades), "failing": sum(1 for x in grades if x in ("D", "F")), "worsened": worsened}


# ── DNS monitoring ───────────────────────────────────────────────────────────

RTYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
CRITICAL_CHANGE = {"NS", "MX"}  # a change here can mean hijack or mail interception


async def lookup(name: str, rtype: str) -> list[str]:
    r = dns.asyncresolver.Resolver()
    r.lifetime = 6
    try:
        return sorted({a.to_text().strip('"') if rtype != "TXT" else "".join(s.decode(errors="replace") for s in a.strings)
                       for a in await r.resolve(name, rtype)})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []


async def has_dnssec(domain: str) -> bool:
    return bool(await lookup(domain, "DNSKEY"))


def posture(records: dict[str, list[str]], dmarc: list[str], dnssec: bool) -> list[dict]:
    """Email and DNS security checks: (check, ok, detail, severity)."""
    spf = [t for t in records.get("TXT", []) if t.lower().startswith("v=spf1")]
    dm = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)
    policy = None
    if dm:
        for part in dm.split(";"):
            k, _, v = part.strip().partition("=")
            if k.lower() == "p":
                policy = v.strip().lower()
    checks = [
        {"check": "SPF record", "ok": len(spf) == 1,
         "detail": spf[0] if len(spf) == 1 else ("missing: anyone can send mail as this domain" if not spf else "more than one SPF record (invalid)"),
         "severity": "critical"},
        {"check": "SPF not permissive", "ok": bool(spf) and not any(t.rstrip().endswith(("+all", "?all")) for t in spf),
         "detail": "ends in -all or ~all" if spf and not any(t.rstrip().endswith(("+all", "?all")) for t in spf) else "+all/?all lets any server send as you",
         "severity": "critical"},
        {"check": "DMARC policy", "ok": policy in ("quarantine", "reject"),
         "detail": f"p={policy}" if policy else "no DMARC record: spoofed mail is not rejected",
         "severity": "critical" if not dm else "warning"},
        {"check": "DNSSEC", "ok": dnssec, "detail": "signed" if dnssec else "zone is not signed", "severity": "warning"},
        {"check": "CAA record", "ok": bool(records.get("CAA")),
         "detail": ", ".join(records.get("CAA", [])) or "any CA may issue certificates for this domain", "severity": "info"},
        {"check": "Redundant name servers", "ok": len(records.get("NS", [])) >= 2,
         "detail": f"{len(records.get('NS', []))} NS records", "severity": "warning"},
    ]
    return checks


async def monitor_dns(db: AsyncSession, tenant_id: str) -> dict:
    """Records and posture of each registrable domain behind the watchlist:
    a watched subdomain (vpn.example.com) is checked as example.com, since
    SPF, DMARC, NS and DNSSEC live at the zone, not on a host name."""
    from .brand import split_domain

    from .domains import in_scope

    watched = await in_scope(db, tenant_id, (await db.execute(select(WatchItem.value).where(
        WatchItem.tenant_id == tenant_id, WatchItem.type == "domain", WatchItem.is_active.is_(True)))).scalars().all())
    domains = sorted({".".join(split_domain(d)) for d in watched})
    existing = {}
    for r in (await db.execute(select(DnsRecord).where(DnsRecord.tenant_id == tenant_id))).scalars():
        if r.domain in domains:
            existing[(r.domain, r.rtype)] = r
        else:
            await db.delete(r)  # no longer watched, or recorded per-subdomain by an older version
    now = utcnow()
    changes, failing = [], 0
    out = {}
    for d in domains:
        records = {}
        for rt in RTYPES:
            try:
                records[rt] = await lookup(d, rt)
            except (dns.exception.DNSException, OSError) as exc:
                logger.info("DNS %s %s failed: %s", d, rt, exc)
                continue  # unknown, not empty: never record a lookup failure as a change
            row = existing.get((d, rt))
            if row is None:
                db.add(DnsRecord(tenant_id=tenant_id, domain=d, rtype=rt, values=records[rt], first_seen=now,
                                 changed_at=now, checked_at=now))
                continue
            if sorted(row.values or []) != records[rt]:
                sev = "critical" if rt in CRITICAL_CHANGE else "warning"
                detail = f"{rt}: {', '.join(row.values or []) or '(none)'} → {', '.join(records[rt]) or '(none)'}"
                db.add(SurfaceEvent(tenant_id=tenant_id, subject=d, kind="dns_changed", severity=sev, detail=detail[:2000], at=now))
                changes.append({"domain": d, "rtype": rt, "severity": sev, "detail": detail})
                row.values, row.changed_at = records[rt], now
            row.checked_at = now
        try:
            dmarc = await lookup(f"_dmarc.{d}", "TXT")
            dnssec = await has_dnssec(d)
        except (dns.exception.DNSException, OSError):
            dmarc, dnssec = [], False
        checks = posture(records, dmarc, dnssec)
        failing += sum(1 for c in checks if not c["ok"] and c["severity"] == "critical")
        out[d] = {"checks": checks, "dmarc": dmarc}
    await db.commit()
    return {"domains": len(domains), "changes": changes, "posture": out, "posture_failing": failing}


# ── Change log for hosts ─────────────────────────────────────────────────────


def host_events(tenant_id: str, name: str, before: dict | None, after: dict, now) -> list[SurfaceEvent]:
    """Events for one host given its state before and after a scan. ``before``
    is None for a host seen for the first time."""
    ev = []

    def add(kind, sev, detail):
        ev.append(SurfaceEvent(tenant_id=tenant_id, subject=name, kind=kind, severity=sev, detail=detail[:2000], at=now))

    if before is None:
        crit = [p for p in after["ports"] if classify_port(p)["risk"] == "critical"]
        add("host_added", "critical" if crit else "info",
            f"New host{' at ' + ', '.join(after['ips']) if after['ips'] else ''}"
            + (f"; critical ports open: {', '.join(map(str, crit))}" if crit else ""))
        return ev
    if before["resolves"] and not after["resolves"]:
        add("host_gone", "info", "No longer resolves")
    elif not before["resolves"] and after["resolves"]:
        add("host_added", "warning", f"Resolves again at {', '.join(after['ips'])}")
    # CDNs and SaaS (e.g. Microsoft 365 autodiscover) rotate through address
    # pools on every lookup; only a change of a small, stable set is news.
    pooled = len(before["ips"]) > 2 or len(after["ips"]) > 2
    if before["resolves"] and after["resolves"] and set(before["ips"]) != set(after["ips"]) and not pooled:
        add("ip_changed", "warning", f"{', '.join(before['ips'])} → {', '.join(after['ips'])}")
    for p in sorted(set(after["ports"]) - set(before["ports"])):
        c = classify_port(p)
        add("port_opened", "critical" if c["risk"] == "critical" else "warning" if c["risk"] == "high" else "info",
            f"Port {p} ({c['service']}) opened" + (f": {c['why']}" if c["why"] else ""))
    for p in sorted(set(before["ports"]) - set(after["ports"])):
        add("port_closed", "info", f"Port {p} ({classify_port(p)['service']}) closed")
    if before["tls_not_after"] and after["tls_not_after"] and before["tls_not_after"] != after["tls_not_after"]:
        add("cert_changed", "info", f"Certificate replaced; now valid until {after['tls_not_after']}")
    return ev
