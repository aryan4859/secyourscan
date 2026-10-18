from datetime import timedelta
from unittest.mock import patch

from app.models import utcnow
from app.services import asm, brand


def _net(cves_on_vpn=("CVE-2023-38408",), vpn_ports=(22, 443), mx="10 mx1.example.com."):
    """Patches for every outbound call the external-risk modules make."""

    async def ct_names(d):
        return {f"www.{d}", f"old.{d}"}

    async def hackertarget_hosts(d):
        return {f"www.{d}", f"vpn.{d}"}

    async def wayback_hosts(d):
        return {f"old.{d}"}

    async def otx_hosts(d):
        raise RuntimeError("no key")  # a failing source must not sink the scan

    async def dns_bruteforce(d):
        return {f"vpn.{d}"}

    async def urlhaus():
        return [{"feed": "urlhaus", "indicator": "http://www.example.com/x.exe", "host": "www.example.com", "threat": "malware_download"}]

    async def feodo():
        return [{"feed": "feodo", "indicator": "1.1.1.1", "host": "1.1.1.1", "malware": "QakBot", "threat": "botnet C2"},
                {"feed": "feodo", "indicator": "9.9.9.9", "host": "9.9.9.9", "malware": "Emotet", "threat": "botnet C2"}]

    async def threatfox():
        raise ValueError("feed down")

    async def openphish_urls():
        return ["https://example-secure-login.top/signin", "https://example.com/real-page", "https://other.top/x"]

    async def phishstats_search(term):
        return [{"url": "http://example.verify-account.xyz/", "ip": "203.0.113.9"}, {"url": "https://www.example.com/"}]

    async def ransomlook_recent():
        return [{"group": "QILIN", "victim": "a", "discovered": utcnow().isoformat(), "source": "ransomlook"},
                {"group": "play", "victim": "D", "discovered": utcnow().isoformat(), "source": "ransomlook"}]

    async def resolve_a(h):
        return {"www": ["93.184.216.34"], "vpn": ["1.1.1.1"]}.get(h.split(".")[0], ["93.184.216.34"] if h.count(".") == 1 else [])

    async def internetdb(ip):
        return {"ports": list(vpn_ports), "vulns": list(cves_on_vpn), "cpes": ["cpe:/a:openbsd:openssh"]} if ip == "1.1.1.1" else {"ports": [443]}

    async def tls_cert(h):
        return {"issuer": "Test CA", "not_after": utcnow() + timedelta(days=10)} if h.startswith("www.") else None

    async def probe_tls(h):
        base = {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "chain_valid": True, "tls10": False, "tls11": False,
                "not_after": (utcnow() + timedelta(days=200)).isoformat(), "self_signed": False, "sig_alg": "sha256",
                "key_type": "RSA", "key_bits": 2048, "hostname_match": True}
        if h.startswith("www."):
            return {**base, "tls10": True}
        if h.startswith("vpn."):
            return {**base, "self_signed": True, "chain_valid": False}
        return base

    async def lookup(name, rtype):
        if name.startswith("_dmarc."):
            return ["v=DMARC1; p=none; rua=mailto:d@example.com"]
        return {"A": ["93.184.216.34"], "NS": ["a.iana-servers.net.", "b.iana-servers.net."], "MX": [mx],
                "TXT": ["v=spf1 include:_spf.example.com ~all"]}.get(rtype, [])

    async def has_dnssec(d):
        return False

    async def kev_catalog():
        return {"CVE-2023-38408": {"added": "2023-08-01", "name": "OpenSSH agent RCE", "ransomware": True}}

    async def epss_scores(cves):
        return {c: (0.79, 0.99) for c in cves}

    async def dns_profile(d):
        return {"examp1e.com": {"ips": ["93.184.216.40"], "mx": True},
                "example-login.com": {"ips": [], "mx": False}}.get(d)

    async def has_certificate(d):
        return d == "examp1e.com"

    async def search_victims(term):
        return [{"group": "lockbit3", "victim": "Example Corp", "domain": "www.example.com", "country": "US",
                 "activity": "Technology", "attackdate": "2026-10-10T00:00:00+00:00", "description": "data posted"},
                {"group": "akira", "victim": "Unrelated Ltd", "domain": "unrelated.org"}]

    async def recent_victims():
        now = utcnow().isoformat()
        return [{"group": "qilin", "victim": "A", "country": "MY", "discovered": now, "source": "ransomware.live"},
                {"group": "qilin", "victim": "B", "country": "US", "discovered": now, "source": "ransomware.live"},
                {"group": "akira", "victim": "C", "country": "US", "discovered": now, "source": "ransomware.live"}]

    targets = {
        "app.services.easm.ct_names": ct_names, "app.services.easm.resolve_a": resolve_a,
        "app.services.asm.probe_tls": probe_tls, "app.services.asm.lookup": lookup, "app.services.asm.has_dnssec": has_dnssec,
        "app.services.easm.hackertarget_hosts": hackertarget_hosts, "app.services.easm.wayback_hosts": wayback_hosts,
        "app.services.easm.otx_hosts": otx_hosts, "app.services.easm.dns_bruteforce": dns_bruteforce,
        "app.services.reputation.urlhaus": urlhaus, "app.services.reputation.feodo": feodo,
        "app.services.reputation.threatfox": threatfox, "app.services.brand.openphish_urls": openphish_urls,
        "app.services.brand.phishstats_search": phishstats_search, "app.services.ransomware.ransomlook_recent": ransomlook_recent,
        "app.services.easm.internetdb": internetdb, "app.services.easm.tls_cert": tls_cert,
        "app.services.easm.kev_catalog": kev_catalog, "app.services.easm.epss_scores": epss_scores,
        "app.services.brand.dns_profile": dns_profile, "app.services.brand.has_certificate": has_certificate,
        "app.services.ransomware.search_victims": search_victims, "app.services.ransomware.recent_victims": recent_victims,
    }
    return [patch(t, f) for t, f in targets.items()]


class Net:
    def __init__(self, **kw):
        self.patches = _net(**kw)

    def __enter__(self):
        for p in self.patches:
            p.start()

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()


async def _scan(client, headers, module):
    r = await client.post(f"/intel/scan/{module}", headers=headers)
    assert r.status_code == 202, r.text


async def test_surface_then_vulns_ranks_kev_and_tracks_fixes(client, admin, other_tenant):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "example.com"})
    with Net():
        await _scan(client, admin, "surface")

    hosts = {h["hostname"]: h for h in (await client.get("/surface/hosts", headers=admin)).json()}
    assert set(hosts) == {"example.com", "www.example.com", "vpn.example.com", "old.example.com"}
    assert hosts["vpn.example.com"]["ports"] == [22, 443] and hosts["vpn.example.com"]["cves"] == ["CVE-2023-38408"]
    assert hosts["old.example.com"]["resolves"] is False
    assert 9 <= hosts["www.example.com"]["tls_days_left"] <= 10
    assert hosts["vpn.example.com"]["sources"] == ["dns", "hackertarget"]
    assert hosts["example.com"]["sources"] == ["watchlist"]
    # Listed by URLhaus (its own URL) and Feodo (its IP); ThreatFox was down.
    assert [t["feed"] for t in hosts["www.example.com"]["threats"]] == ["urlhaus"]
    assert [(t["feed"], t["malware"]) for t in hosts["vpn.example.com"]["threats"]] == [("feodo", "QakBot")]

    findings = (await client.get("/vulns", headers=admin)).json()
    assert len(findings) == 1
    f = findings[0]
    assert (f["host"], f["cve"], f["kev"], f["kev_ransomware"], f["priority"]) == ("vpn.example.com", "CVE-2023-38408", True, True, "critical")
    assert f["epss"] == 0.79

    notes = (await client.get("/notifications", headers=admin)).json()
    assert any(n["level"] == "critical" and "actively exploited" in n["title"] for n in notes)
    assert any("expire within" in n["title"] for n in notes)

    assert any("listed in threat feeds" in n["title"] for n in notes)
    status = (await client.get("/intel/status", headers=admin)).json()
    assert status["surface"]["status"] == "ok" and status["vulns"]["status"] == "ok"
    assert status["surface"]["result"]["sources"] == {"watchlist": 1, "crt.sh": 2, "hackertarget": 2, "wayback": 1, "dns": 1}
    assert status["surface"]["result"]["feeds"] == {"urlhaus": 1, "feodo": 2, "threatfox": "error"}
    # Every source reports its outcome, including zero and failure.
    assert status["surface"]["result"]["source_status"] == {"crt.sh": 2, "hackertarget": 2, "wayback": 1, "otx": "disabled", "dns": 1}
    assert status["surface"]["result"]["new"] == 0  # first scan does not call everything "new"

    # Patched: the CVE disappears, the finding is marked fixed.
    with Net(cves_on_vpn=()):
        await _scan(client, admin, "surface")
    assert (await client.get("/vulns", headers=admin)).json() == []
    assert (await client.get("/vulns", headers=admin, params={"status": "fixed"})).json()[0]["cve"] == "CVE-2023-38408"

    assert (await client.get("/surface/hosts", headers=other_tenant)).json() == []
    assert (await client.get("/vulns", headers=other_tenant)).json() == []


async def test_brand_scan_scores_registered_lookalikes(client, admin, other_tenant):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "www.example.com"})
    with Net():
        await _scan(client, admin, "brand")
    rows = {x["domain"]: x for x in (await client.get("/brand/lookalikes", headers=admin)).json()}
    assert set(rows) == {"examp1e.com", "example-login.com"}
    assert rows["examp1e.com"]["technique"] == "homoglyph" and rows["examp1e.com"]["risk"] == 100
    assert rows["examp1e.com"]["has_mx"] and rows["examp1e.com"]["has_cert"]
    assert rows["example-login.com"]["risk"] == 40

    notes = (await client.get("/notifications", headers=admin)).json()
    assert any("lookalike" in n["title"] and "examp1e.com" in n["body"] for n in notes)

    r = await client.patch(f"/brand/lookalikes/{rows['examp1e.com']['id']}", headers=admin, json={"status": "takedown"})
    assert r.json()["status"] == "takedown"
    assert (await client.patch(f"/brand/lookalikes/{rows['examp1e.com']['id']}", headers=other_tenant,
                               json={"status": "benign"})).status_code == 404
    phish = {p["url"]: p for p in (await client.get("/brand/phishing", headers=admin)).json()}
    # Matches on the brand label, never on the real domain.
    assert set(phish) == {"https://example-secure-login.top/signin", "http://example.verify-account.xyz/"}
    assert phish["http://example.verify-account.xyz/"]["source"] == "phishstats"
    assert any("live phishing URL" in n["title"] for n in notes)
    summary = (await client.get("/intel/summary", headers=admin)).json()
    assert summary["brand"] == {"lookalikes": 2, "high_risk": 1, "takedown": 1, "phishing": 2}


async def test_ransomware_scan_matches_only_your_terms(client, admin):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "example.com"})
    with Net():
        await _scan(client, admin, "ransomware")
        activity = (await client.get("/ransomware/activity", headers=admin)).json()
    hits = (await client.get("/ransomware/hits", headers=admin)).json()
    assert [(h["group"], h["victim"], h["matched"]) for h in hits] == [("lockbit3", "Example Corp", "example.com")]
    notes = (await client.get("/notifications", headers=admin)).json()
    assert any(n["title"] == "Named on a ransomware leak site" and "lockbit3" in n["body"] for n in notes)
    # RansomLook's duplicate of qilin/A is merged away; its play/D post is added.
    assert activity["groups"][0] == {"group": "qilin", "count": 2} and activity["posts"] == 4
    assert activity["sources"] == {"ransomware.live": 3, "ransomlook": 1}

    # Re-running does not duplicate or re-alert.
    with Net():
        await _scan(client, admin, "ransomware")
    assert len((await client.get("/ransomware/hits", headers=admin)).json()) == 1
    assert sum(n["title"] == "Named on a ransomware leak site" for n in (await client.get("/notifications", headers=admin)).json()) == 1


async def test_scan_requires_recon_scope_and_known_module(client, admin):
    assert (await client.post("/intel/scan/everything", headers=admin)).status_code == 422
    key = (await client.post("/api-keys", headers=admin, json={"name": "reader", "scopes": ["read"]})).json()
    r = await client.post("/intel/scan/brand", headers={"X-API-Key": key["key"]})
    assert r.status_code == 403


def test_permutations_cover_common_squatting_techniques():
    assert brand.split_domain("jbbl.com.np") == ("jbbl", "com.np")
    assert brand.split_domain("portal.example.com") == ("example", "com")
    perms = dict(brand.permutations("jbbl.com.np"))
    assert perms["jbb1.com.np"] == "homoglyph"
    assert perms["jbl.com.np"] == "omission"
    assert perms["jbbl-login.com.np"] == "combosquatting"
    assert perms["jbbl.np"] == "tld-swap"
    assert "jbbl.com.np" not in perms
    assert all(brand._ok(c.split(".")[0]) for c in perms)


def test_phishing_match_needs_the_brand_as_a_word():
    assert brand.mentions("https://jbbl-login.xyz/a", "jbbl")
    assert brand.mentions("http://jbbl.com.np.secure-check.top/", "jbbl.com.np")
    assert brand.mentions("http://203.0.113.9/jbbl/ebanking", "jbbl")
    assert not brand.mentions("http://49.51.43.12/signin?ifkv=AWa2PavALAegJBBlmTPnLu", "jbbl")
    assert not brand.mentions("https://www.dropbox.com/paper/doc/x?auth_token=cd.AFjbblQx", "jbbl")


async def test_asm_ports_tls_dns_and_change_log(client, admin):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "example.com"})
    with Net():
        await _scan(client, admin, "surface")

    ports = (await client.get("/surface/ports", headers=admin)).json()
    assert ports[0]["risk"] in ("medium", "low") and {p["port"] for p in ports} == {22, 443}

    tls = {g["hostname"]: g for g in (await client.get("/surface/tls", headers=admin)).json()}
    assert tls["vpn.example.com"]["grade"] == "F" and "Self-signed" in tls["vpn.example.com"]["issues"][0]["text"]
    assert tls["www.example.com"]["grade"] == "C"
    assert tls["example.com"]["grade"] == "A"

    dns = (await client.get("/surface/dns", headers=admin)).json()[0]
    assert dns["domain"] == "example.com" and dns["records"]["MX"]["values"] == ["10 mx1.example.com."]
    checks = {c["check"]: c for c in dns["checks"]}
    assert checks["SPF record"]["ok"] and checks["SPF not permissive"]["ok"]
    assert not checks["DMARC policy"]["ok"] and checks["DMARC policy"]["detail"] == "p=none"
    assert not checks["DNSSEC"]["ok"] and checks["Redundant name servers"]["ok"]
    assert (await client.get("/surface/events", headers=admin)).json() == []  # first scan: baseline only

    # RDP opens on the VPN host and the MX record moves: both are critical.
    with Net(vpn_ports=(22, 443, 3389), mx="10 mail.attacker.example."):
        await _scan(client, admin, "surface")
    events = (await client.get("/surface/events", headers=admin)).json()
    kinds = {(e["kind"], e["severity"]) for e in events}
    assert ("port_opened", "critical") in kinds and ("dns_changed", "critical") in kinds
    assert any("3389" in e["detail"] and "RDP" in e["detail"] for e in events)
    notes = (await client.get("/notifications", headers=admin)).json()
    assert any("critical change(s) on your attack surface" in n["title"] for n in notes)
    assert any(n["title"] == "Name-server or mail DNS records changed" for n in notes)
    summary = (await client.get("/intel/summary", headers=admin)).json()["surface"]
    # p=none DMARC is a warning, not a critical posture failure.
    assert summary["critical_ports"] == 1 and summary["tls_failing"] == 1 and summary["dns_failing"] == 0


async def test_dns_posture_is_checked_at_the_zone(client, admin):
    # Only a subdomain is watched; SPF/DMARC/NS belong to its registrable domain.
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "vpn.example.com"})
    with Net():
        await _scan(client, admin, "surface")
    assert [d["domain"] for d in (await client.get("/surface/dns", headers=admin)).json()] == ["example.com"]


def test_tls_grade_and_dns_posture_rules():
    ok = {"protocol": "TLSv1.3", "chain_valid": True, "hostname_match": True, "self_signed": False, "sig_alg": "sha256",
          "key_type": "RSA", "key_bits": 4096, "tls10": False, "tls11": False,
          "not_after": (utcnow() + timedelta(days=90)).isoformat()}
    assert asm.grade(ok) == ("A", [])
    assert asm.grade({**ok, "protocol": "TLSv1.2"})[0] == "B"
    assert asm.grade({**ok, "tls11": True})[0] == "C"
    assert asm.grade({**ok, "hostname_match": False})[0] == "F"
    assert asm.grade({**ok, "not_after": (utcnow() - timedelta(days=3)).isoformat()})[0] == "F"
    assert asm.grade({**ok, "key_bits": 1024})[0] == "F"

    checks = {c["check"]: c["ok"] for c in asm.posture({"TXT": ["v=spf1 +all"], "NS": ["a."]}, [], False)}
    assert checks == {"SPF record": True, "SPF not permissive": False, "DMARC policy": False, "DNSSEC": False,
                      "CAA record": False, "Redundant name servers": False}
    assert asm.classify_port(3389)["risk"] == "critical" and asm.classify_port(12345)["risk"] == "info"
    assert asm.classify_port(443)["service"] == "HTTPS"

    now = utcnow()
    state = lambda ips: {"resolves": True, "ips": ips, "ports": [443], "tls_not_after": None}  # noqa: E731
    moved = asm.host_events("t", "vpn", state(["1.1.1.1"]), state(["2.2.2.2"]), now)
    assert [e.kind for e in moved] == ["ip_changed"]
    # A rotating pool (CDN / SaaS) is not news.
    assert asm.host_events("t", "autodiscover", state(["1.0.0.1", "1.0.0.2", "1.0.0.3"]),
                           state(["1.0.0.4", "1.0.0.5", "1.0.0.6"]), now) == []
