"""The leak pipeline. One call per candidate leak, from any source.

    sha256 ─► exact dedup ─► SimHash near-dup ─► Babel extraction ─► YARA
      ─► watchlist match ─► score ─► LLM triage (optional, can only raise)
      ─► raw evidence to MinIO ─► row in PostgreSQL ─► masked text to ES
      ─► notification / SOAR webhook

Runs inside a Celery worker in production and in-process when no broker is
configured. Each optional stage degrades: no MinIO means no raw evidence, no
ES means SQL search, no AI means rule-based severity.
"""

import hashlib
import logging
import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import Leak, Notification, WatchItem, YaraRule, utcnow
from . import cti, incidents, search_index, soar, storage
from .analyzer import analyzer
from .babel import extract, mask_text
from .normalization import hamming_distance, normalize_content, normalize_identifier, simhash64
from .triage import triage

logger = logging.getLogger("secyourscan.pipeline")

MAX_CONTENT_BYTES = 5 * 1024 * 1024
SNIPPET_CHARS = 4000
_YARA_REFRESH_SECONDS = 60.0
_last_yara_refresh = 0.0


async def _refresh_yara(db: AsyncSession) -> None:
    global _last_yara_refresh
    now = time.monotonic()
    if now - _last_yara_refresh < _YARA_REFRESH_SECONDS:
        return
    rows = (await db.execute(select(YaraRule).where(YaraRule.is_active.is_(True)))).scalars().all()
    analyzer.refresh([(r.tenant_id, r.name, r.content) for r in rows])
    _last_yara_refresh = now


def force_yara_refresh() -> None:
    global _last_yara_refresh
    _last_yara_refresh = 0.0


async def _find_duplicate(db: AsyncSession, tenant_id: str, sha: str, fingerprint: int) -> Leak | None:
    exact = await db.scalar(select(Leak).where(Leak.tenant_id == tenant_id, Leak.sha256 == sha).limit(1))
    if exact or not fingerprint:
        return exact
    # O(n) over the tenant's fingerprints. Fine for thousands of leaks; bucket
    # the fingerprint into 16-bit bands for an LSH index beyond that.
    rows = await db.execute(
        select(Leak.id, Leak.simhash64).where(Leak.tenant_id == tenant_id, Leak.simhash64.is_not(None))
    )
    for leak_id, fp in rows:
        if fp and hamming_distance(fp, fingerprint) <= settings.NEAR_DUP_THRESHOLD:
            return await db.get(Leak, leak_id)
    return None


def match_watchlist(items: list[WatchItem], entities: dict, content_lower: str) -> list[dict]:
    emails = {normalize_identifier(e, "email") for e in entities.get("emails", [])}
    domains = set(entities.get("domains", []))
    ips = set(entities.get("ips", []))
    wallets = set(entities.get("btc_wallets", []) + entities.get("xmr_wallets", []))
    cred_idents = {normalize_identifier(c["identifier"], "email") if "@" in c["identifier"] else c["identifier"]
                   for c in entities.get("credentials", [])}
    matches = []
    for item in items:
        value = normalize_identifier(item.value, item.type if item.type != "keyword" else "generic")
        hit_on: list[str] = []
        if item.type == "domain":
            hit_on = sorted(e for e in emails if e.endswith("@" + value) or e.endswith("." + value))[:20]
            if not hit_on and (value in domains or any(d.endswith("." + value) for d in domains)):
                hit_on = [value]
        elif item.type == "email":
            hit_on = [value] if value in emails or value in cred_idents else []
        elif item.type == "ip":
            hit_on = [value] if value in ips else []
        elif item.type == "wallet":
            hit_on = [item.value] if item.value in wallets else []
        elif item.type == "keyword":
            hit_on = [value] if value and value in content_lower else []
        if hit_on:
            matches.append({"id": item.id, "type": item.type, "value": item.value, "vip": item.is_vip, "hits": hit_on})
    return matches


def score(yara_score: int, entities: dict, watch_matches: list[dict]) -> int:
    s = yara_score
    if entities.get("credential_count"):
        s += min(40, 10 + entities["credential_count"])
    if entities.get("cards"):
        s += 30
    if watch_matches:
        s += 25
        if any(m["vip"] for m in watch_matches):
            s += 15
    return max(0, min(100, s))


def category_for(entities: dict, yara_matches: list[dict]) -> str:
    if entities.get("credential_count"):
        return "CREDENTIALS"
    if entities.get("cards"):
        return "FINANCIAL"
    by_score = sorted((m for m in yara_matches if m.get("category")), key=lambda m: -m["score"])
    return by_score[0]["category"] if by_score else "OTHER"


async def _rematch_near_duplicate(db: AsyncSession, dup: Leak, content: str, tenant_id: str) -> None:
    await _refresh_yara(db)
    entities = extract(content)
    yara_matches, yara_score = analyzer.analyze(content, tenant_id)
    watch = (
        await db.execute(select(WatchItem).where(WatchItem.tenant_id == tenant_id, WatchItem.is_active.is_(True)))
    ).scalars().all()
    known = {m["id"] for m in dup.watch_matches or []}
    new_matches = [m for m in match_watchlist(watch, entities, content.lower()) if m["id"] not in known]
    new_severity = max(dup.severity, score(yara_score, entities, (dup.watch_matches or []) + new_matches))
    if not new_matches and new_severity == dup.severity:
        return
    dup.watch_matches = (dup.watch_matches or []) + new_matches
    raised = new_severity > dup.severity
    dup.severity = new_severity
    vip = any(m["vip"] for m in new_matches)
    if new_matches and (dup.severity >= settings.CRITICAL_THRESHOLD or vip):
        db.add(Notification(tenant_id=tenant_id, leak_id=dup.id, level="critical" if dup.severity >= settings.CRITICAL_THRESHOLD else "vip",
                            title=f"Re-posted leak now matches {', '.join(m['value'] for m in new_matches)}",
                            body=f"severity {dup.severity}"))
    await search_index.update_fields(dup.id, {"severity": dup.severity,
                                              "watch_matches": [m["value"] for m in dup.watch_matches]})
    logger.info("near-duplicate %s re-matched: +%d watch matches, severity raised=%s", dup.id, len(new_matches), raised)


async def process_leak(
    db: AsyncSession,
    *,
    tenant_id: str,
    source: str,
    content: str,
    source_url: str | None = None,
    title: str | None = None,
    metadata: dict | None = None,
    use_ai: bool = True,
) -> tuple[Leak, bool]:
    """Return ``(leak, created)``. ``created`` is False for a duplicate."""
    if not content or not content.strip():
        raise ValueError("empty content")
    content = content[:MAX_CONTENT_BYTES]
    sha = hashlib.sha256(content.encode("utf-8", "ignore")).hexdigest()
    fingerprint = simhash64(normalize_content(content))

    dup = await _find_duplicate(db, tenant_id, sha, fingerprint)
    if dup is not None:
        dup.seen_count += 1
        dup.last_seen_at = utcnow()
        sightings = dup.metadata_json.get("sightings", [])
        if len(sightings) < 50:
            dup.metadata_json = {**dup.metadata_json, "sightings": [*sightings, {"source": source, "url": source_url, "at": utcnow().isoformat()}]}
        if dup.sha256 != sha:
            await _rematch_near_duplicate(db, dup, content, tenant_id)
        await db.commit()
        return dup, False

    await _refresh_yara(db)
    entities = extract(content)
    yara_matches, yara_score = analyzer.analyze(content, tenant_id)
    watch = (
        await db.execute(select(WatchItem).where(WatchItem.tenant_id == tenant_id, WatchItem.is_active.is_(True)))
    ).scalars().all()
    watch_matches = match_watchlist(watch, entities, content.lower())

    severity = score(yara_score, entities, watch_matches)
    category = category_for(entities, yara_matches)
    masked = mask_text(content)

    ai = await triage(masked) if use_ai and settings.ai_enabled else None
    if ai:
        if ai["is_valid"]:
            severity = max(severity, ai["severity"] or 0, 60)
            category = ai["category"] or category

    leak = Leak(
        tenant_id=tenant_id,
        source=source[:64],
        source_url=source_url,
        title=(title or "")[:512] or None,
        snippet=masked[:SNIPPET_CHARS],
        sha256=sha,
        simhash64=fingerprint,
        severity=severity,
        category=category,
        entities=entities,
        yara_matches=yara_matches,
        watch_matches=watch_matches,
        ai_analysis=ai,
        cti=await cti.enrich(entities),
        metadata_json={**(metadata or {}), "content_length": len(content)},
    )

    try:
        leak.storage_path = await storage.put_bytes(tenant_id, f"leaks/{sha}.txt", content.encode("utf-8", "ignore"), "text/plain; charset=utf-8")
    except Exception as exc:
        logger.warning("Evidence storage failed (%s); continuing without raw copy", exc)

    db.add(leak)
    await db.flush()
    vip = any(m["vip"] for m in watch_matches)

    if severity >= settings.CRITICAL_THRESHOLD:
        db.add(Notification(tenant_id=tenant_id, leak_id=leak.id, level="critical",
                            title=f"Critical exposure ({severity}) from {leak.source}",
                            body=", ".join(m["value"] for m in watch_matches) or (title or "")))
    elif vip:
        db.add(Notification(tenant_id=tenant_id, leak_id=leak.id, level="vip",
                            title=f"[VIP] exposure ({severity}) from {leak.source}",
                            body=", ".join(m["value"] for m in watch_matches if m["vip"])))
    await db.commit()

    try:
        await search_index.index_leak(leak, masked)
    except Exception as exc:
        logger.warning("Indexing %s failed (%s); SQL search still finds it", leak.id, exc)

    if severity >= settings.SOAR_THRESHOLD or vip:
        await soar.fire(leak, vip=vip and severity < settings.SOAR_THRESHOLD)

    if severity >= settings.CRITICAL_THRESHOLD:
        try:
            await incidents.sync(db, tenant_id)
        except Exception as exc:  # noqa: BLE001 — the leak is stored; the next sync opens its incident
            leak_id = leak.id
            await db.rollback()
            await db.refresh(leak)  # rollback expired it; the caller still reads its fields
            logger.warning("Incident sync for leak %s failed: %s", leak_id, exc)

    logger.info("leak processed tenant=%s source=%s severity=%s id=%s", tenant_id, source, severity, leak.id)
    return leak, True
