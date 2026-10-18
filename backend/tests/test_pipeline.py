import base64
import hashlib
from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from app.services import massive
from app.services.babel import extract, mask_text
from app.services.triage import parse_verdict

COMBO = "\n".join(f"user{i}@acme.example.com:Secr3tPass{i}!" for i in range(6)) + "\nfresh dump, full db"


async def _ingest(client, headers, content, source="test", **extra):
    r = await client.post("/leaks/ingest/webhook", headers=headers, json={"source": source, "content": content, **extra})
    assert r.status_code == 202, r.text
    return r.json()["result"]


async def test_combo_list_on_watched_domain_is_scored_masked_and_alerted(client, admin):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "acme.example.com", "is_vip": True})
    res = await _ingest(client, admin, COMBO, source="paste")
    assert res["created"] is True
    leak = (await client.get(f"/leaks/{res['id']}", headers=admin)).json()

    assert leak["severity"] >= 80
    assert leak["category"] == "CREDENTIALS"
    assert {m["rule"] for m in leak["yara_matches"]} >= {"combo_list", "leak_marketplace_language"}
    assert leak["watch_matches"][0]["value"] == "acme.example.com" and leak["watch_matches"][0]["vip"]
    assert leak["entities"]["credential_count"] == 6
    # No plaintext secret anywhere in what the API returns.
    assert "Secr3tPass" not in str(leak)
    assert leak["sha256"] == hashlib.sha256(COMBO.encode()).hexdigest()

    notes = (await client.get("/notifications", headers=admin)).json()
    assert notes and notes[0]["level"] == "critical"


async def test_exact_and_near_duplicates_collapse(client, admin):
    first = await _ingest(client, admin, COMBO)
    again = await _ingest(client, admin, COMBO, source="mirror")
    near = await _ingest(client, admin, COMBO.replace("\n", "\r\n  ") + "  ")
    assert again["id"] == first["id"] and again["created"] is False
    assert near["id"] == first["id"]
    leak = (await client.get(f"/leaks/{first['id']}", headers=admin)).json()
    assert leak["seen_count"] == 3


async def test_unrelated_noise_scores_low(client, admin):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "acme.example.com"})
    res = await _ingest(client, admin, "Welcome to my blog about gardening and tomatoes.")
    leak = (await client.get(f"/leaks/{res['id']}", headers=admin)).json()
    assert leak["severity"] < 30 and leak["watch_matches"] == []


async def test_ai_can_raise_but_not_lower_severity(client, admin, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "AI_ENDPOINT", "http://ai.invalid/v1")

    async def say_no(_masked):
        return {"is_valid": False, "severity": 5, "category": "OTHER", "rationale": "looks fake", "thought": "", "raw": ""}

    with patch("app.services.pipeline.triage", say_no):
        res = await _ingest(client, admin, COMBO)
    leak = (await client.get(f"/leaks/{res['id']}", headers=admin)).json()
    assert leak["severity"] >= 60  # rule-based evidence stands
    assert leak["ai_analysis"]["is_valid"] is False


async def test_custom_yara_rule_applies_only_to_its_tenant(client, admin, other_tenant):
    rule = 'rule acme_project { meta: score = 70 strings: $a = "PROJECT-ZEPHYR" condition: $a }'
    assert (await client.post("/yara/rules", headers=admin, json={"name": "acme_project", "content": rule})).status_code == 201
    assert (await client.post("/yara/rules", headers=admin, json={"name": "broken", "content": "rule x { condition: nope }"})).status_code == 422

    mine = await _ingest(client, admin, "internal notes PROJECT-ZEPHYR roadmap")
    theirs = await _ingest(client, other_tenant, "internal notes PROJECT-ZEPHYR roadmap")
    assert "acme_project" in (await client.get(f"/leaks/{mine['id']}", headers=admin)).json()["yara_rules"]
    assert "acme_project" not in (await client.get(f"/leaks/{theirs['id']}", headers=other_tenant)).json()["yara_rules"]


async def test_sql_search_fallback_escapes_wildcards(client, admin):
    await _ingest(client, admin, "token leak for acme_backup server")
    await _ingest(client, admin, "something else entirely here")
    r = (await client.get("/leaks/search", headers=admin, params={"q": "acme_backup"})).json()
    assert r["engine"] == "sql" and r["total"] == 1
    assert (await client.get("/leaks/search", headers=admin, params={"q": "%"})).json()["total"] == 0


async def test_triage_status_and_ack_all_are_audited(client, admin):
    res = await _ingest(client, admin, COMBO)
    r = await client.patch(f"/leaks/{res['id']}/status", headers=admin, json={"status": "escalated"})
    assert r.json()["status"] == "escalated"
    assert (await client.post("/leaks/ack-all", headers=admin, params={"min_severity": 0})).json()["acknowledged"] == 1
    actions = {a["action"] for a in (await client.get("/system/audit", headers=admin)).json()}
    assert {"UPDATE_LEAK_STATUS", "ACKNOWLEDGE_ALL_CRITICAL"} <= actions


async def test_audit_chain_detects_tampering(client, admin):
    await client.post("/watchlist", headers=admin, json={"type": "keyword", "value": "acme"})
    assert (await client.get("/system/audit/verify", headers=admin)).json()["valid"] is True

    from sqlalchemy import update

    from app.database import SessionLocal
    from app.models import AuditLog

    async with SessionLocal() as db:
        await db.execute(update(AuditLog).where(AuditLog.action == "CREATE_WATCH_ITEM").values(details={"value": "forged"}))
        await db.commit()
    result = (await client.get("/system/audit/verify", headers=admin)).json()
    assert result["valid"] is False and result["reason"] == "content"


async def test_dossier_signature_verifies(client, admin):
    await _ingest(client, admin, COMBO)
    r = await client.get("/leaks/export/dossier", headers=admin)
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    digest = hashlib.sha256(r.content).digest()
    assert digest.hex() == r.headers["x-dossier-sha256"]
    pem = (await client.get("/leaks/export/public-key", headers=admin)).content
    load_pem_public_key(pem).verify(base64.b64decode(r.headers["x-dossier-signature"]), digest)  # raises if invalid


async def test_csv_export_neutralises_formulas(client, admin):
    await _ingest(client, admin, "some content here", source="=cmd|' /c calc'!A1")
    body = (await client.get("/leaks/export/csv", headers=admin)).text
    assert "'=cmd" in body


async def test_webhook_validation(client, admin):
    assert (await client.post("/leaks/ingest/webhook", headers=admin, content=b"not json")).status_code == 400
    r = await client.post("/leaks/ingest/webhook", headers=admin, json={"content": "", "metadata": None})
    assert r.status_code == 422 and "input" not in str(r.json())


# ── Unit-level ───────────────────────────────────────────────────────────────


def test_extraction_and_masking():
    text = ("alice@acme.example.com:SuperSecret99\npassword = hunter2hunter2\n"
            "card 4111 1111 1111 1111 and 1234 5678 9012 3456\nwallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n"
            "-----BEGIN PRIVATE KEY-----\nMIIEv\n-----END PRIVATE KEY-----")
    ents = extract(text)
    assert ents["emails"] == ["alice@acme.example.com"]
    assert ents["cards"] == ["411111******1111"]  # the second number fails Luhn
    assert ents["btc_wallets"] and ents["has_private_key"]
    masked = mask_text(text)
    for secret in ("SuperSecret99", "hunter2hunter2", "4111 1111 1111 1111", "MIIEv"):
        assert secret not in masked


def test_verdict_parsing():
    v = parse_verdict("VALID: YES\nSEVERITY: 85\nCATEGORY: credentials\nRATIONALE: real combo list.")
    assert v == {"is_valid": True, "severity": 85, "category": "CREDENTIALS", "rationale": "real combo list."}
    assert parse_verdict("I cannot tell")["is_valid"] is False


def test_massive_prefilter_keeps_only_watched_lines():
    lines = ["noise line"] * 1000 + ["bob@acme.example.com:pw12345"] * 3 + ["x@other.example:pw"]
    keep = massive.build_filter(["acme.example.com"])
    chunks = list(massive.chunk_matching(lines, keep))
    assert len(chunks) == 1
    content, stats = chunks[0]
    assert stats["scanned"] == 1004 and stats["matched"] == 3 and "other.example" not in content


async def test_near_duplicate_with_new_watched_address_alerts(client, admin):
    base = "\n".join(f"someone{i}@other.example.org:pw{i}xyz9" for i in range(8))
    first = await _ingest(client, admin, base)
    await client.post("/watchlist", headers=admin, json={"type": "email", "value": "cfo@acme.example.com", "is_vip": True})
    again = await _ingest(client, admin, base + "\ncfo@acme.example.com:newpass99")
    assert again["id"] == first["id"] and again["created"] is False
    leak = (await client.get(f"/leaks/{first['id']}", headers=admin)).json()
    assert [m["value"] for m in leak["watch_matches"]] == ["cfo@acme.example.com"]
    assert any("Re-posted" in n["title"] for n in (await client.get("/notifications", headers=admin)).json())


async def test_gmail_watch_item_matches_dotted_variant(client, admin):
    await client.post("/watchlist", headers=admin, json={"type": "email", "value": "john.doe+news@gmail.com"})
    res = await _ingest(client, admin, "dump\nJohn.Doe@gmail.com:hunter22")
    leak = (await client.get(f"/leaks/{res['id']}", headers=admin)).json()
    assert leak["watch_matches"]


async def test_internal_urls_are_refused(client, admin):
    for url in ("http://127.0.0.1:9200/", "http://localhost/x", "http://169.254.169.254/latest/meta-data/"):
        r = await client.post("/leaks/ingest/bulk", headers=admin, data={"url": url})
        assert r.status_code == 422, (url, r.text)
        r = await client.post("/sources", headers=admin, json={"kind": "feed", "target": url})
        assert r.status_code == 422, (url, r.text)


async def test_yara_include_is_rejected(client, admin):
    rule = 'include "/etc/passwd"\nrule x { condition: true }'
    r = await client.post("/yara/rules", headers=admin, json={"name": "inc", "content": rule})
    assert r.status_code == 422


async def test_insights_summarises_window_assets_and_callouts(client, admin, other_tenant):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "acme.example.com", "is_vip": True})
    await _ingest(client, admin, COMBO, source="paste")
    await _ingest(client, other_tenant, COMBO + " other tenant", source="paste")

    r = await client.get("/leaks/insights", headers=admin, params={"days": 7})
    assert r.status_code == 200, r.text
    ins = r.json()
    assert ins["days"] == 7 and len(ins["daily"]) == 7
    assert ins["kpis"]["leaks"] == {"value": 1, "prev": 0}
    assert ins["kpis"]["critical"]["value"] == 1
    assert ins["kpis"]["awaiting_triage"]["value"] == 1
    assert ins["severity"]["critical"] == 1 and sum(ins["daily"][-1][b] for b in ins["severity"]) == 1
    assert ins["by_source"] == [{"source": "paste", "count": 1, "prev": 0}]
    top = ins["top_assets"][0]
    assert top["value"] == "acme.example.com" and top["vip"] and top["exposure"] >= 80 and top["open"] == 1
    assert {c["kind"] for c in ins["callouts"]} == {"vip_at_risk"}

    assert (await client.get("/leaks/insights", headers=admin, params={"days": 5})).status_code == 422
    other = (await client.get("/leaks/insights", headers=other_tenant)).json()
    assert other["kpis"]["leaks"]["value"] == 1 and other["top_assets"] == []


async def test_topology_links_leaks_to_watched_assets_only(client, admin, other_tenant):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "acme.example.com", "is_vip": True})
    await client.post("/watchlist", headers=admin, json={"type": "keyword", "value": "nothing-matches-this"})
    leak = await _ingest(client, admin, COMBO, source="paste")
    await _ingest(client, admin, "unrelated chatter about the weather", source="paste")
    await _ingest(client, other_tenant, COMBO + " other tenant", source="paste")

    g = (await client.get("/leaks/topology", headers=admin)).json()
    by_kind = {}
    for n in g["nodes"]:
        by_kind.setdefault(n["kind"], []).append(n)
    # Both watched assets appear (one isolated); only the matching leak does.
    assert sorted(a["label"] for a in by_kind["asset"]) == ["acme.example.com", "nothing-matches-this"]
    assert [l["id"] for l in by_kind["leak"]] == [f"l:{leak['id']}"]
    vip = next(a for a in by_kind["asset"] if a["vip"])
    assert vip["hits"] == 1 and vip["exposure"] >= 80
    assert g["links"] == [{"source": f"l:{leak['id']}", "target": vip["id"]}]
    # Extracted entities (the combo's email addresses) never become nodes.
    assert not any("user0@" in (n["label"] or "") for n in g["nodes"])

    assert (await client.get("/leaks/topology", headers=admin, params={"min_severity": 101})).status_code == 422
    other = (await client.get("/leaks/topology", headers=other_tenant)).json()
    assert other["links"] == [] and all(n["kind"] == "leak" for n in other["nodes"]) is True


async def test_watch_exposure_ranks_assets_and_explains_one(client, admin, other_tenant):
    hot = (await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "acme.example.com", "is_vip": True})).json()
    cold = (await client.post("/watchlist", headers=admin, json={"type": "keyword", "value": "nothing-matches-this"})).json()
    leak = await _ingest(client, admin, COMBO, source="paste")

    rows = (await client.get("/watchlist/exposure", headers=admin)).json()
    assert [r["id"] for r in rows] == [hot["id"], cold["id"]]
    assert rows[0]["exposure"] >= 80 and rows[0]["hits"] == 1 and rows[0]["unacked_critical"] == 1
    assert rows[1]["exposure"] == 0 and rows[1]["hits"] == 0 and rows[1]["last_seen"] is None

    # Resolving the leak drops exposure to zero but keeps the history.
    await client.patch(f"/leaks/{leak['id']}/status", headers=admin, json={"status": "resolved"})
    ins = (await client.get(f"/watchlist/{hot['id']}/insights", headers=admin)).json()
    assert ins["exposure"] == 0 and ins["max_severity"] >= 80 and ins["hits"] == 1
    assert len(ins["daily"]) == 90 and ins["daily"][-1]["count"] == 1
    assert ins["sources"] == {"paste": 1} and ins["leaks"][0]["id"] == leak["id"]

    assert (await client.get(f"/watchlist/{hot['id']}/insights", headers=other_tenant)).status_code == 404
    assert (await client.get("/watchlist/exposure", headers=other_tenant)).json() == []


async def test_darkweb_probe_returns_a_pollable_run(client, admin, other_tenant):
    report = {"query": "acme.example.com", "via_tor": False, "count": 1, "total_hits": 1, "results": [
        {"title": "acme dump", "url": "http://abcdefghijklmnop.onion/x", "description": "acme.example.com combo",
         "page": 0, "via_tor": False, "fetched_at": "2026-10-18T00:00:00"}]}

    async def fake_search(query):
        return report

    with patch("app.services.recon.ahmia_search", fake_search):
        r = await client.get("/recon/darkweb", headers=admin, params={"q": "acme.example.com"})
    assert r.status_code == 202, r.text
    run_id = r.json()["run_id"]

    run = (await client.get(f"/sources/runs/{run_id}", headers=admin)).json()
    assert run["status"] == "ok", run["error"]
    assert run["kind"] == "ahmia" and run["results"] == 1
    assert run["report"]["results"][0]["url"].endswith(".onion/x")

    # Exactly one run: the worker reused the one the API created.
    history = (await client.get("/sources/runs", headers=admin, params={"adhoc": True, "kind": ["ahmia", "telegram"]})).json()
    assert [h["id"] for h in history] == [run_id]
    assert (await client.get("/sources/runs", headers=admin, params={"kind": "telegram"})).json() == []
    assert (await client.get(f"/sources/runs/{run_id}", headers=other_tenant)).status_code == 404


async def test_darkweb_overview_groups_by_channel(client, admin, other_tenant):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "acme.example.com", "is_vip": True})
    await _ingest(client, admin, COMBO, source="onion", source_url="http://abcdefghijklmnop.onion/thread/1")
    await _ingest(client, admin, "chatter about acme.example.com staff", source="telegram", source_url="https://t.me/s/somechan/5")
    await _ingest(client, admin, "unrelated text", source="feed")

    d = (await client.get("/leaks/darkweb", headers=admin, params={"days": 7})).json()
    ch = {c["channel"]: c for c in d["channels"]}
    assert ch["Tor / onion"]["count"] == 1 and ch["Tor / onion"]["critical"] == 1
    assert ch["Telegram"]["matched"] == 1 and ch["Feeds"]["matched"] == 0
    assert d["totals"] == {"mentions": 3, "prev": 0, "matched": 2, "critical": 1, "sites": 2}
    assert d["sites"][0]["site"] == "abcdefghijklmnop.onion"
    assert d["terms"][0]["term"] == "acme.example.com" and d["terms"][0]["count"] == 2
    assert [x["channel"] for x in d["latest"]] == ["Tor / onion", "Telegram"]
    assert "Secr3tPass" not in str(d)
    assert len(d["daily"]) == 7
    assert (await client.get("/leaks/darkweb", headers=other_tenant)).json()["totals"]["mentions"] == 0
