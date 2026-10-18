"""Row → JSON. Kept explicit so a new column is never exposed by accident."""


def iso(dt):
    return dt.isoformat() if dt else None


def leak_summary(lk) -> dict:
    ents = lk.entities or {}
    return {
        "id": lk.id,
        "source": lk.source,
        "source_url": lk.source_url,
        "title": lk.title,
        "snippet": (lk.snippet or "")[:300],
        "severity": lk.severity,
        "category": lk.category,
        "status": lk.status,
        "watch_matches": lk.watch_matches or [],
        "yara_rules": [m["rule"] for m in lk.yara_matches or []],
        "email_count": len(ents.get("emails", [])),
        "credential_count": ents.get("credential_count", 0),
        "seen_count": lk.seen_count,
        "discovered_at": iso(lk.discovered_at),
        "last_seen_at": iso(lk.last_seen_at),
        "acknowledged_at": iso(lk.acknowledged_at),
        "has_evidence": bool(lk.storage_path),
    }


def leak_detail(lk) -> dict:
    return {
        **leak_summary(lk),
        "snippet": lk.snippet,
        "sha256": lk.sha256,
        "entities": lk.entities or {},
        "yara_matches": lk.yara_matches or [],
        "ai_analysis": lk.ai_analysis,
        "cti": lk.cti or {},
        "metadata": lk.metadata_json or {},
    }


def watch_item(w) -> dict:
    return {"id": w.id, "type": w.type, "value": w.value, "is_vip": w.is_vip, "is_active": w.is_active,
            "created_at": iso(w.created_at)}


def source(s) -> dict:
    return {"id": s.id, "kind": s.kind, "target": s.target, "interval_minutes": s.interval_minutes,
            "max_pages": s.max_pages, "is_active": s.is_active, "last_run_at": iso(s.last_run_at),
            "created_at": iso(s.created_at)}


def source_run(r, *, with_report: bool = False) -> dict:
    out = {"id": r.id, "source_id": r.source_id, "kind": r.kind, "query": r.query, "status": r.status,
           "results": r.results, "new_leaks": r.queued, "via_tor": r.via_tor, "error": r.error,
           "started_at": iso(r.started_at), "finished_at": iso(r.finished_at)}
    if with_report:
        out["report"] = r.report or {}
    return out


def user(u) -> dict:
    return {"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role, "tenant_id": u.tenant_id,
            "is_platform_admin": u.is_platform_admin,
            "is_active": u.is_active, "created_at": iso(u.created_at)}


def api_key(k) -> dict:
    return {"id": k.id, "name": k.name, "prefix": k.prefix, "scopes": k.scopes, "created_at": iso(k.created_at),
            "last_used_at": iso(k.last_used_at), "revoked_at": iso(k.revoked_at)}


def yara_rule(r) -> dict:
    return {"id": r.id, "name": r.name, "content": r.content, "is_active": r.is_active, "scope": "tenant" if r.tenant_id else "global",
            "created_at": iso(r.created_at)}


def notification(n) -> dict:
    return {"id": n.id, "leak_id": n.leak_id, "level": n.level, "title": n.title, "body": n.body,
            "created_at": iso(n.created_at), "acknowledged_at": iso(n.acknowledged_at)}


def audit(a) -> dict:
    return {"id": a.id, "user_id": a.user_id, "action": a.action, "resource_type": a.resource_type,
            "resource_id": a.resource_id, "details": a.details, "ip_address": a.ip_address,
            "timestamp": iso(a.timestamp), "row_hash": a.row_hash}


def plan(p) -> dict:
    return {"id": p.id, "title": p.title, "description": p.description, "status": p.status,
            "created_at": iso(p.created_at),
            "tasks": [{"id": t.id, "title": t.title, "status": t.status, "created_by": t.created_by,
                       "created_at": iso(t.created_at)} for t in p.tasks]}
