"""Incidents, threat actors, IOC hunting and supply-chain risk."""

from unittest.mock import patch

from app.services import actors, incidents, ioc
from app.services.actors_data import ACTORS, TACTICS, TECHNIQUES

from .test_intel import Net
from .test_pipeline import COMBO, _ingest


async def _scan(client, headers, module):
    r = await client.post(f"/intel/scan/{module}", headers=headers)
    assert r.status_code == 202, r.text


async def _internetdb(ip):
    return {"found": True, "ports": [22, 443], "tags": ["cloud"], "vulns": []} if ip == "1.1.1.1" else {"ip": ip, "found": False}


class Hunt(Net):
    """Net plus the keyless IOC sources that Net does not cover."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.patches.append(patch("app.services.cti.shodan_internetdb", _internetdb))


# ── Incidents ────────────────────────────────────────────────────────────────


async def test_findings_open_incidents_once_and_workflow_writes_back(client, admin, other_tenant):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "example.com"})
    with Net():
        await _scan(client, admin, "ransomware")
    rows = (await client.get("/incidents", headers=admin)).json()
    assert [(r["category"], r["severity"], r["actor"], r["status"]) for r in rows] == [("ransomware", "critical", "lockbit3", "open")]
    inc = rows[0]
    assert inc["ref"] == "INC-0001" and inc["sla_state"] == "on_track" and inc["assignee"] is None

    # A second scan and a manual sync do not duplicate it.
    with Net():
        await _scan(client, admin, "ransomware")
    assert (await client.post("/incidents/sync", headers=admin)).json()["opened"] == 0
    assert len((await client.get("/incidents", headers=admin)).json()) == 1

    me = (await client.get("/users/me", headers=admin)).json()
    r = await client.patch(f"/incidents/{inc['id']}", headers=admin,
                           json={"status": "investigating", "assignee_id": me["id"], "note": "calling the CISO"})
    d = r.json()
    assert d["status"] == "investigating" and d["assignee"]["email"] == me["email"] and d["acknowledged_at"]
    assert [e["kind"] for e in d["events"]] == ["created", "status", "assignee", "comment"]
    assert (await client.get("/ransomware/hits", headers=admin)).json()[0]["status"] == "acknowledged"

    d = (await client.post(f"/incidents/{inc['id']}/comments", headers=admin, json={"body": "evidence attached"})).json()
    assert d["events"][-1]["body"] == "evidence attached"

    # Closing as a false positive marks the hit "not us", and it stays closed.
    d = (await client.patch(f"/incidents/{inc['id']}", headers=admin, json={"status": "false_positive"})).json()
    assert d["resolved_at"] and d["sla_state"] == "met"
    assert (await client.get("/ransomware/hits", headers=admin)).json()[0]["status"] == "false_positive"
    assert (await client.get("/incidents", headers=admin)).json() == []
    assert len((await client.get("/incidents", headers=admin, params={"status": "closed"})).json()) == 1

    stats = (await client.get("/incidents/stats", headers=admin)).json()
    assert stats["total"] == 1 and stats["open"] == 0 and stats["mtta_minutes"] == 0 and stats["sla_met_pct"] == 100

    # Another tenant sees none of it and cannot touch it.
    assert (await client.get("/incidents", headers=other_tenant, params={"status": "all"})).json() == []
    assert (await client.get(f"/incidents/{inc['id']}", headers=other_tenant)).status_code == 404
    assert (await client.patch(f"/incidents/{inc['id']}", headers=other_tenant, json={"status": "open"})).status_code == 404


async def test_manual_incident_validates_assignee_and_reprices_sla(client, admin, other_tenant):
    them = (await client.get("/users/me", headers=other_tenant)).json()
    bad = await client.post("/incidents", headers=admin, json={"title": "Suspicious login", "assignee_id": them["id"]})
    assert bad.status_code == 422

    r = await client.post("/incidents", headers=admin, json={"title": "Suspicious login", "severity": "low"})
    assert r.status_code == 201
    inc = r.json()
    assert inc["category"] == "manual" and inc["created_by"] == "admin@acme.example.com"
    d = (await client.patch(f"/incidents/{inc['id']}", headers=admin, json={"severity": "critical"})).json()
    assert d["severity"] == "critical" and d["sla_due_at"] < inc["sla_due_at"]
    assert (await client.patch(f"/incidents/{inc['id']}", headers=admin, json={"assignee_id": them["id"]})).status_code == 422

    key = (await client.post("/api-keys", headers=admin, json={"name": "reader", "scopes": ["read"]})).json()
    ro = {"X-API-Key": key["key"]}
    assert (await client.get("/incidents", headers=ro)).status_code == 200
    assert (await client.post("/incidents", headers=ro, json={"title": "nope"})).status_code == 403


async def test_critical_leak_opens_an_incident(client, admin):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "acme.example.com"})
    res = await _ingest(client, admin, COMBO, source="paste")
    rows = (await client.get("/incidents", headers=admin)).json()
    assert len(rows) == 1 and rows[0]["category"] == "leak" and rows[0]["source_id"] == res["id"]
    assert "acme.example.com" in (await client.get(f"/incidents/{rows[0]['id']}", headers=admin)).json()["description"]
    # Resolving the incident resolves the leak.
    await client.patch(f"/incidents/{rows[0]['id']}", headers=admin, json={"status": "resolved"})
    assert (await client.get(f"/leaks/{res['id']}", headers=admin)).json()["status"] == "resolved"


def test_sla_states():
    from datetime import timedelta

    from app.models import Incident, utcnow

    now = utcnow()
    inc = Incident(severity="critical", status="open", created_at=now - timedelta(hours=1), sla_due_at=now + timedelta(hours=3))
    assert incidents.sla_state(inc, now) == "on_track"
    assert incidents.sla_state(inc, now + timedelta(hours=2, minutes=30)) == "at_risk"
    assert incidents.sla_state(inc, now + timedelta(hours=4)) == "overdue"
    inc.status, inc.resolved_at = "resolved", now + timedelta(hours=5)
    assert incidents.sla_state(inc, now) == "breached"


# ── Threat actors ────────────────────────────────────────────────────────────


def test_catalogue_is_consistent():
    tactics = {t for t, _ in TACTICS}
    assert all(tac in tactics for _, tac, _ in TECHNIQUES.values())
    slugs = [a["slug"] for a in ACTORS]
    assert len(slugs) == len(set(slugs))
    for a in ACTORS:
        unknown = [t for t in a["techniques"] if t not in TECHNIQUES]
        assert not unknown, f"{a['name']} uses uncatalogued techniques {unknown}"
    # Leak-site group names resolve to profiles.
    built = [{**a, "id": a["slug"]} for a in ACTORS]
    assert actors.find_by_group(built, "lockbit3")["name"] == "LockBit"
    assert actors.find_by_group(built, "ALPHV")["name"] == "ALPHV / BlackCat"


async def test_actor_relevance_profile_and_attack_matrix(client, admin, other_tenant):
    ranked = (await client.get("/actors", headers=admin)).json()
    assert len(ranked) == len(ACTORS) and all(a["relevance"] == 0 for a in ranked)
    m = (await client.get("/actors/attack-matrix", headers=admin)).json()
    assert m["basis"] == "all" and [c["tactic"] for c in m["columns"]][0] == "reconnaissance"

    prof = (await client.put("/threat-intel/profile", headers=admin,
                             json={"sectors": ["Healthcare", "Bogus"], "countries": ["us", "xx1"]})).json()
    assert prof["sectors"] == ["Healthcare"] and prof["countries"] == ["US"]

    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "example.com"})
    with Net():
        await _scan(client, admin, "ransomware")
    ranked = (await client.get("/actors", headers=admin)).json()
    top = ranked[0]
    assert top["name"] == "LockBit" and top["observed"] and top["relevance"] >= 85
    assert any("listed you" in r for r in top["reasons"]) and any("Healthcare" in r for r in top["reasons"])
    assert next(a for a in ranked if a["name"] == "Qilin")["posts_30d"] >= 1  # active in the cached feed

    d = (await client.get(f"/actors/{top['id']}", headers=admin)).json()
    assert d["your_hits"][0]["victim"] == "Example Corp" and d["your_incidents"][0]["status"] == "open"
    assert {t["tactic"] for t in d["techniques_detail"]} >= {"initial-access", "impact"}
    m = (await client.get("/actors/attack-matrix", headers=admin)).json()
    assert m["basis"] == "relevant" and any(t["id"] == "T1486" for t in m["top"])

    # Custom actors: tenant-private, name/alias collisions refused, built-ins protected.
    assert (await client.post("/actors", headers=admin, json={"name": "Some Crew", "aliases": ["x"], "techniques": ["T1486", "bad"]})).status_code == 422
    assert (await client.post("/actors", headers=admin, json={"name": "lock bit"})).status_code == 409
    r = await client.post("/actors", headers=admin, json={"name": "Local Crew", "kind": "hacktivist", "sectors": ["Healthcare"],
                                                          "countries": ["US"], "techniques": ["T1190"]})
    assert r.status_code == 201 and r.json()["relevance"] == 45
    assert not any(a["name"] == "Local Crew" for a in (await client.get("/actors", headers=other_tenant)).json())
    assert (await client.delete("/actors/builtin:lockbit", headers=admin)).status_code == 403
    assert (await client.delete(f"/actors/{r.json()['id']}", headers=other_tenant)).status_code == 404
    assert (await client.delete(f"/actors/{r.json()['id']}", headers=admin)).status_code == 204


# ── IOC hunting ──────────────────────────────────────────────────────────────


def test_classify_refang_and_verdict():
    assert ioc.classify("1[.]1[.]1[.]1") == ("ip", "1.1.1.1")
    assert ioc.classify("hxxps://Evil[.]example/x") == ("url", "https://Evil.example/x")
    assert ioc.classify("EVIL.Example.") == ("domain", "evil.example")
    assert ioc.classify("44D88612FEA8A8F36DE82E1278ABB02F") == ("md5", "44d88612fea8a8f36de82e1278abb02f")
    assert ioc.classify("a" * 64)[0] == "sha256"
    assert ioc.classify("bob[@]corp.example") == ("email", "bob@corp.example")
    assert ioc.classify("hello") is None and ioc.classify("1.2.3") is None
    items, bad = ioc.parse_many("1.1.1.1, 1.1.1.1\nnope evil.example")
    assert items == [("ip", "1.1.1.1"), ("domain", "evil.example")] and bad == ["nope"]

    assert ioc.verdict({"abuse.ch feeds": {"found": True, "score": 90}}) == ("malicious", 90)
    assert ioc.verdict({"abuse.ch feeds": {"found": False, "score": 0}}) == ("unknown", 0)  # not listed ≠ clean
    assert ioc.verdict({"otx": {"found": False, "score": 0}, "x": {"error": "down"}}) == ("clean", 0)
    assert ioc.verdict({"otx": {"found": True, "score": 0, "allowlisted": True}, "vt": {"score": 90}}) == ("clean", 0)
    assert ioc.pattern("url", "http://x/it's") == "[url:value = 'http://x/it\\'s']"
    assert ioc.pattern("sha1", "ab" * 20) == f"[file:hashes.'SHA-1' = '{'ab' * 20}']"


async def test_hunt_enriches_retro_hunts_and_shares(client, admin, other_tenant):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "example.com"})
    with Hunt():
        await _scan(client, admin, "surface")  # vpn.example.com resolves to 1.1.1.1
        text = "1[.]1[.]1[.]1, hxxp://www.example[.]com/x.exe\n10.0.0.5 not-an-ioc!! 9.9.9.9 8.8.8.8"
        r = await client.post("/iocs/hunt", headers=admin, json={"text": text, "tags": ["case-42"]})
    assert r.status_code == 200, r.text
    out = r.json()
    res = {x["value"]: x for x in out["results"]}
    assert out["rejected"] == ["not-an-ioc!!"]
    assert res["1.1.1.1"]["verdict"] == "malicious" and res["1.1.1.1"]["malware"] == ["QakBot"]
    assert res["1.1.1.1"]["asset_sightings"] == 1 and res["1.1.1.1"]["tags"] == ["case-42"]
    assert res["http://www.example.com/x.exe"]["verdict"] == "malicious"
    assert res["10.0.0.5"]["verdict"] == "unknown" and list(res["10.0.0.5"]["sources"]) == ["_note"]
    assert res["8.8.8.8"]["verdict"] == "unknown"  # nothing listed it, and no broad source is configured
    # A feed that could not be downloaded is named, never silently counted as "not listed".
    assert res["8.8.8.8"]["sources"]["abuse.ch feeds"] == "not in URLhaus, Feodo Tracker (ThreatFox unavailable)"
    assert res["9.9.9.9"]["actors"] == [] and res["9.9.9.9"]["malware"] == ["Emotet"]
    assert out["results"][0]["verdict"] == "malicious"

    # Malicious indicators on our own assets are incidents: a C2-listed IP on a
    # surface host, and a malware URL served from our own web server. The
    # unsighted 9.9.9.9 is not.
    assert out["incidents_opened"] == 2
    incs = (await client.get("/incidents", headers=admin, params={"category": "ioc"})).json()
    assert sorted(i["title"] for i in incs) == ["Malicious ip seen in your data: 1.1.1.1",
                                                "Malicious url seen in your data: http://www.example.com/x.exe"]

    full = (await client.get(f"/iocs/{res['1.1.1.1']['id']}", headers=admin)).json()
    assert full["sightings_detail"][0]["where"] == "attack surface host vpn.example.com"
    assert full["enrichment"]["internetdb"]["ports"] == [22, 443]

    # Analyst override survives re-enrichment; clearing it restores the computed verdict.
    r = await client.patch(f"/iocs/{res['8.8.8.8']['id']}", headers=admin, json={"verdict": "clean", "tlp": "clear", "note": "resolver"})
    assert r.json()["verdict"] == "clean" and r.json()["verdict_override"]
    with Hunt():
        assert (await client.post(f"/iocs/{res['8.8.8.8']['id']}/enrich", headers=admin)).json()["verdict"] == "clean"
    assert (await client.patch(f"/iocs/{res['8.8.8.8']['id']}", headers=admin, json={"clear_override": True})).json()["verdict"] == "unknown"

    # Sharing: STIX bundle, blocklist, TAXII 2.1 — TLP respected.
    await client.patch(f"/iocs/{res['9.9.9.9']['id']}", headers=admin, json={"tlp": "red"})
    stix = (await client.get("/iocs/export/stix", headers=admin)).json()
    patterns = {o["pattern"]: o for o in stix["objects"] if o["type"] == "indicator"}
    assert set(patterns) == {"[ipv4-addr:value = '1.1.1.1']", "[url:value = 'http://www.example.com/x.exe']"}
    assert patterns["[ipv4-addr:value = '1.1.1.1']"]["object_marking_refs"] == [ioc.TLP_MARKINGS["amber"]]
    assert stix["objects"][0]["type"] == "identity"
    red = (await client.get("/iocs/export/stix", headers=admin, params={"max_tlp": "red"})).json()
    assert "[ipv4-addr:value = '9.9.9.9']" in {o.get("pattern") for o in red["objects"]}
    # The blocklist feeds your own firewall: internal use, so TLP:RED is included.
    assert (await client.get("/iocs/export/blocklist.txt", headers=admin, params={"type": "ip"})).text == "1.1.1.1\n9.9.9.9\n"

    key = (await client.post("/api-keys", headers=admin, json={"name": "siem", "scopes": ["read"]})).json()
    siem = {"Authorization": f"Bearer {key['key']}"}
    disc = await client.get("/taxii2/", headers=siem)
    assert disc.headers["content-type"].startswith("application/taxii+json") and disc.json()["api_roots"] == ["/taxii2/api/"]
    col = (await client.get("/taxii2/api/collections/", headers=siem)).json()["collections"][0]
    objs = (await client.get(f"/taxii2/api/collections/{col['id']}/objects/", headers=siem)).json()
    assert {o.get("pattern") for o in objs["objects"]} >= {"[ipv4-addr:value = '1.1.1.1']"} and objs["more"] is False
    assert (await client.post("/iocs/hunt", headers=siem, json={"text": "1.1.1.1"})).status_code == 403

    stats = (await client.get("/iocs/stats", headers=admin)).json()
    assert stats["total"] == 5 and stats["by_verdict"]["malicious"] == 3 and stats["sighted_malicious"] == 2
    assert (await client.get("/iocs", headers=other_tenant)).json() == []
    assert (await client.get(f"/iocs/{res['1.1.1.1']['id']}", headers=other_tenant)).status_code == 404
    other_objs = (await client.get(f"/taxii2/api/collections/{col['id']}/objects/", headers=other_tenant)).json()
    assert [o["type"] for o in other_objs["objects"]] == ["identity"]

    assert (await client.post("/iocs/hunt", headers=admin, json={"text": "nothing here"})).status_code == 422


# ── Supply chain ─────────────────────────────────────────────────────────────


async def test_vendor_rating_breach_alert_and_incident(client, admin, other_tenant):
    assert (await client.post("/vendors", headers=admin, json={"name": "Bad", "domain": "not a domain"})).status_code == 422
    r = await client.post("/vendors", headers=admin, json={"name": "Example Corp", "domain": "https://www.Example.com/login",
                                                           "criticality": "critical"})
    assert r.status_code == 201 and r.json()["domain"] == "example.com"
    assert (await client.post("/vendors", headers=admin, json={"name": "Dup", "domain": "example.com"})).status_code == 409
    imp = (await client.post("/vendors/import", headers=admin,
                             json={"csv": "name,domain,criticality\nGlobex Supplies,globexsupplies.com,low\nbroken\nX,example.com"})).json()
    assert imp["added"] == 1 and len(imp["skipped"]) == 2

    with Net():
        await _scan(client, admin, "vendors")
    vendors = {v["domain"]: v for v in (await client.get("/vendors", headers=admin)).json()}
    ex, gl = vendors["example.com"], vendors["globexsupplies.com"]
    # DMARC p=none and no DNSSEC cost a little; a fresh leak-site post costs a lot.
    assert ex["breaches"] == 1 and ex["grade"] == "F" and ex["score"] == 52
    assert gl["breaches"] == 0 and gl["grade"] == "A" and gl["score"] == 92
    assert list(vendors) == ["example.com", "globexsupplies.com"]  # worst first

    d = (await client.get(f"/vendors/{ex['id']}", headers=admin)).json()
    assert d["breach_posts"][0]["group"] == "lockbit3" and d["facts"]["tls_grade"] == "A"
    assert {f["area"] for f in d["findings"]} == {"breach", "email"}

    notes = (await client.get("/notifications", headers=admin)).json()
    assert sum(n["title"] == "A vendor was named on a ransomware leak site" for n in notes) == 1
    incs = (await client.get("/incidents", headers=admin, params={"category": "vendor"})).json()
    assert len(incs) == 1 and incs[0]["severity"] == "critical" and incs[0]["actor"] == "lockbit3"

    summary = (await client.get("/vendors/summary", headers=admin)).json()
    assert summary == {"vendors": 2, "rated": 2, "average": 72, "by_grade": {"A": 1, "B": 0, "C": 0, "D": 0, "F": 1},
                       "breached": 1, "critical_at_risk": 1}

    # Re-scan: no duplicate alert or incident; history grows.
    with Net():
        await _scan(client, admin, "vendors")
    notes = (await client.get("/notifications", headers=admin)).json()
    assert sum(n["title"] == "A vendor was named on a ransomware leak site" for n in notes) == 1
    assert len((await client.get("/incidents", headers=admin, params={"category": "vendor"})).json()) == 1
    assert len((await client.get(f"/vendors/{ex['id']}", headers=admin)).json()["history"]) == 2

    # The vendor's leak-site group now ranks as observed among threat actors.
    top = (await client.get("/actors", headers=admin)).json()[0]
    assert top["name"] == "LockBit" and any("vendor Example Corp" in r for r in top["reasons"])

    assert (await client.patch(f"/vendors/{ex['id']}", headers=admin, json={"criticality": "low", "name": None})).json()["name"] == "Example Corp"
    assert (await client.get(f"/vendors/{ex['id']}", headers=other_tenant)).status_code == 404
    assert (await client.get("/vendors", headers=other_tenant)).json() == []
    assert (await client.delete(f"/vendors/{gl['id']}", headers=admin)).status_code == 204


async def test_vendor_scan_with_no_vendors_is_a_no_op(client, admin):
    with Net():
        await _scan(client, admin, "vendors")
    st = (await client.get("/intel/status", headers=admin)).json()["vendors"]
    assert st["status"] == "ok" and st["result"]["vendors"] == 0
