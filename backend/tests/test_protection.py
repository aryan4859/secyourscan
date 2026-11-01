"""Identity intelligence, vulnerability intelligence, executive protection, takedowns."""

from unittest.mock import patch

from app.services import stealer, vulnintel

from .test_pipeline import _ingest

LOG = """Lumma stealer log
HWID: 7781-ABCD
Computer Name: FIN-LAPTOP-07
IP: 198.51.100.7
Country: US

URL: https://vpn.acme.example.com/login
USER: j.doe@acme.example.com
PASS: Winter$2025

URL: https://mail.acme.example.com/owa
USER: j.doe@acme.example.com
PASS: Winter$2025

URL: https://www.netflix.example/login
USER: j.doe@gmail.example
PASS: netflix123
"""

ULP = "https://portal.acme.example.com/sso:admin:Adm1nPass!\nhttps://shop.other.example/login:someone@other.example:xyz12345"


# ── Stealer parsing ──────────────────────────────────────────────────────────


def test_parse_blocks_and_ulp_without_keeping_passwords():
    out = stealer.parse(LOG)
    assert out["family"] == "Lumma"
    assert [r["host"] for r in out["records"]] == ["vpn.acme.example.com", "mail.acme.example.com", "www.netflix.example"]
    r = out["records"][0]
    assert r["login"] == "j.doe@acme.example.com" and r["hwid"] == "7781-ABCD" and r["password_length"] == 11
    assert "Winter" not in str(out) and r["password_masked"].startswith("W*")
    # Same password, same fingerprint; different password, different one.
    assert out["records"][0]["password_fp"] == out["records"][1]["password_fp"] != out["records"][2]["password_fp"]
    assert out["machines"] == [{"hwid": "7781-ABCD", "computer": "FIN-LAPTOP-07", "ip": "198.51.100.7", "country": "US"}]

    ulp = stealer.parse(ULP)["records"]
    assert [(r["host"], r["login"], r["format"]) for r in ulp] == [
        ("portal.acme.example.com", "admin", "ulp"), ("shop.other.example", "someone@other.example", "ulp")]


def test_masked_snippet_still_parses_without_fingerprints():
    rec = stealer.parse("URL: https://vpn.acme.example.com\nUSER: a@acme.example.com\nPASS: W*********5")["records"][0]
    assert rec["password_masked"] == "W*********5" and rec["password_fp"] is None


# ── Identity intelligence ────────────────────────────────────────────────────


async def test_identity_view_from_stealer_log(client, admin, other_tenant):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "acme.example.com"})
    res = await _ingest(client, admin, LOG, source="telegram", title="Lumma log")
    leak = (await client.get(f"/leaks/{res['id']}", headers=admin)).json()
    assert leak["category"] == "CREDENTIALS" and leak["severity"] >= 80
    await _ingest(client, admin, ULP, source="paste")

    s = (await client.get("/identity/summary", headers=admin)).json()
    # j.doe (email on the watched domain) and "admin" (an account on our SSO portal).
    # The netflix / other.example accounts are not ours.
    assert s["identities"] == 2 and s["stealer_infected"] == 2 and s["corporate_app_accounts"] == 2
    assert s["machines"] == 1 and s["families"] == [{"family": "Lumma", "logs": 1}]

    rows = (await client.get("/identity/identities", headers=admin, params={"kind": "stealer"})).json()
    jd = next(r for r in rows if r["login"] == "j.doe@acme.example.com")
    assert jd["corporate_apps"] == ["mail.acme.example.com", "vpn.acme.example.com"] and jd["machines"] == 1
    assert jd["families"] == ["Lumma"] and jd["risk"] >= 70

    d = (await client.get("/identity/identity", headers=admin, params={"login": "J.Doe@acme.example.com"})).json()
    assert d["distinct_passwords"] == 1 and d["passwords"] == ["W*********5"]
    assert any("compromised" in a for a in d["actions"]) and d["timeline"][0]["kind"] == "stealer"

    m = (await client.get("/identity/machines", headers=admin)).json()
    assert m[0]["computer"] == "FIN-LAPTOP-07" and m[0]["corporate_apps"] == ["mail.acme.example.com", "vpn.acme.example.com"]

    # Tenant isolation.
    assert (await client.get("/identity/summary", headers=other_tenant)).json()["identities"] == 0
    assert (await client.get("/identity/identity", headers=other_tenant, params={"login": "j.doe@acme.example.com"})).status_code == 404


# ── Vulnerability intelligence ───────────────────────────────────────────────


async def _kev():
    return {
        "CVE-2026-1001": {"added": "2099-01-01", "name": "Fortinet FortiOS auth bypass", "ransomware": True,
                          "vendor": "Fortinet", "product": "FortiOS", "description": "Auth bypass", "due": "2099-01-21",
                          "action": "Apply updates"},
        "CVE-2026-1002": {"added": "2099-01-01", "name": "Other product bug", "ransomware": False,
                          "vendor": "Nobody", "product": "Widget", "description": "", "due": None, "action": ""},
    }


async def _nvd(days=30):
    return [{"cve": "CVE-2026-2001", "published": "2099-01-02", "description": "nginx heap overflow", "cvss": 9.8,
             "severity": "critical", "vector": "NETWORK", "products": ["f5:nginx"]},
            {"cve": "CVE-2026-1001", "published": "2099-01-01", "description": "FortiOS", "cvss": 9.6,
             "severity": "critical", "vector": "NETWORK", "products": ["fortinet:fortios"]}]


async def _epss(cves):
    return {"CVE-2026-1001": (0.92, 0.99), "CVE-2026-2001": (0.04, 0.8)}


def test_cpe_and_product_matching():
    assert vulnintel.parse_cpe("cpe:/a:nginx:nginx:1.18.0") == {"vendor": "nginx", "product": "nginx", "version": "1.18.0"}
    assert vulnintel.parse_cpe("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*")["version"] == ""
    assert vulnintel._matches("Microsoft", "Exchange", "microsoft", "exchange_server")
    assert not vulnintel._matches("", "go", "golang", "go_ethereum")  # short tokens must be exact
    assert not vulnintel._matches("Apache", "Tomcat", "microsoft", "tomcat_server")


async def test_feed_matches_stack_and_opens_incidents(client, admin):
    r = await client.put("/vuln-intel/stack", headers=admin, json={"items": [
        {"vendor": "Fortinet", "product": "FortiOS", "version": "7.2"}, {"vendor": "F5", "product": "nginx"}]})
    assert len(r.json()["declared"]) == 2

    with patch("app.services.easm.kev_catalog", _kev), patch("app.services.vulnintel.fetch_nvd", _nvd), \
            patch("app.services.easm.epss_scores", _epss):
        assert (await client.post("/vuln-intel/refresh", headers=admin)).status_code == 202

    feed = (await client.get("/vuln-intel/feed", headers=admin, params={"days": 120})).json()
    assert feed["refresh"]["status"] == "ok" and feed["refresh"]["result"]["incidents"] == 2
    by = {i["cve"]: i for i in feed["items"]}
    assert by["CVE-2026-1001"]["priority"] == "critical" and by["CVE-2026-1001"]["kev"] and by["CVE-2026-1001"]["cvss"] == 9.6
    assert by["CVE-2026-2001"]["priority"] == "high" and by["CVE-2026-2001"]["affects"][0]["product"] == "nginx"
    assert by["CVE-2026-1002"]["affects"] == [] and by["CVE-2026-1002"]["priority"] == "low"
    assert feed["stats"]["affecting"] == 2 and feed["stats"]["kev_affecting"] == 1

    only = (await client.get("/vuln-intel/feed", headers=admin, params={"days": 120, "affecting": True})).json()
    assert {i["cve"] for i in only["items"]} == {"CVE-2026-1001", "CVE-2026-2001"}
    incs = (await client.get("/incidents", headers=admin)).json()
    assert sorted(i["severity"] for i in incs if "vuln-intel" in i["tags"]) == ["critical", "high"]


# ── Executives ───────────────────────────────────────────────────────────────


async def test_executive_profile_watchlist_and_mentions(client, admin, other_tenant):
    r = await client.post("/executives", headers=admin, json={
        "name": "Jane Doe", "title": "CFO", "emails": ["J.Doe@acme.example.com"], "usernames": ["@janedoe_cfo"]})
    assert r.status_code == 201, r.text
    x = r.json()
    watch = {(w["type"], w["value"]): w["is_vip"] for w in (await client.get("/watchlist", headers=admin)).json()}
    assert watch[("email", "j.doe@acme.example.com")] is True and watch[("keyword", "jane doe")] is True

    await _ingest(client, admin, LOG, source="telegram")
    await _ingest(client, admin, "selling dox on jane doe, ping @janedoe_cfo for proof", source="telegram",
                  source_url="https://t.me/s/demo/1")
    p = (await client.get(f"/executives/{x['id']}", headers=admin)).json()
    assert p["counts"]["mentions"] == 2 and p["counts"]["stealer"] == 1 and p["counts"]["impersonation"] == 1
    assert p["accounts"][0]["login"] == "j.doe@acme.example.com" and p["band"] in ("high", "critical")
    assert any("handle @janedoe_cfo" in m["matched"] for m in p["mentions"])

    assert (await client.post("/executives", headers=admin, json={"name": "Jane Doe"})).status_code == 409
    assert (await client.get(f"/executives/{x['id']}", headers=other_tenant)).status_code == 404
    assert (await client.post("/executives", headers=admin, json={"name": "Bad", "emails": ["nope"]})).status_code == 422


# ── Takedowns ────────────────────────────────────────────────────────────────


async def _lookup(target):
    return {"host": "evil.example", "registrar": "Example Registrar, Inc.", "hosting": "EXAMPLE-NET",
            "ips": ["203.0.113.9"], "errors": [],
            "contacts": [{"role": "registrar abuse", "name": None, "email": "abuse@registrar.example", "source": "rdap"}]}


async def test_takedown_lifecycle_and_write_back(client, admin, other_tenant):
    res = await _ingest(client, admin, "phishing kit for acme at https://evil.example/login", source="paste",
                        source_url="https://paste.example/raw/1")
    with patch("app.services.takedown.lookup", _lookup):
        r = await client.post("/takedowns", headers=admin, json={"source_type": "leak", "source_id": res["id"],
                                                                 "target": "https://evil.example/login", "reason": "phishing"})
    assert r.status_code == 201, r.text
    td = r.json()
    assert td["ref"] == "TD-0001" and td["status"] == "draft" and td["registrar"] == "Example Registrar, Inc."
    assert td["contacts"][0]["email"] == "abuse@registrar.example"
    assert "https://evil.example/login" in td["notice"] and "TD-0001" in td["notice"]

    # One open request per finding.
    with patch("app.services.takedown.lookup", _lookup):
        dup = await client.post("/takedowns", headers=admin, json={"source_type": "leak", "source_id": res["id"]})
    assert dup.status_code == 409

    await client.patch(f"/takedowns/{td['id']}", headers=admin, json={"status": "submitted", "note": "sent to registrar"})
    done = (await client.patch(f"/takedowns/{td['id']}", headers=admin, json={"status": "taken_down"})).json()
    assert done["submitted_at"] and done["resolved_at"] and [h["status"] for h in done["history"]] == ["draft", "submitted", "taken_down"]
    assert (await client.get(f"/leaks/{res['id']}", headers=admin)).json()["status"] == "resolved"

    st = (await client.get("/takedowns/stats", headers=admin)).json()
    assert st["by_status"]["taken_down"] == 1 and st["success_rate"] == 100 and st["open"] == 0
    bad = await client.patch(f"/takedowns/{td['id']}", headers=admin, json={"contacts": [{"email": "not-an-email"}]})
    assert bad.status_code == 422
    assert (await client.get(f"/takedowns/{td['id']}", headers=other_tenant)).status_code == 404
    assert (await client.get("/takedowns", headers=other_tenant)).json() == []
