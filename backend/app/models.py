"""Relational model.

Every row that holds monitoring data carries ``tenant_id``, and every query
that reads it filters on it (see ``deps.tenant_scope``). Ids are UUID strings
so the same schema runs on PostgreSQL and on SQLite for tests.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


# ── Tenancy & access ─────────────────────────────────────────────────────────


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class VerifiedDomain(Base):
    """A root domain the tenant has proven it controls with a DNS TXT record.
    External-risk scans and domain reports only cover verified domains when
    ``REQUIRE_DOMAIN_VERIFICATION`` is on."""

    __tablename__ = "verified_domains"
    __table_args__ = (UniqueConstraint("tenant_id", "domain"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(255))
    token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(255), nullable=True)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="analyst")  # admin | analyst
    # Platform operator: may create, list and delete *other* tenants. A tenant
    # admin manages only their own tenant's users and keys.
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ApiKey(Base):
    """Tenant-bound key for scrapers posting to the ingest webhook and for the
    MCP server. Only a SHA-256 of the key is stored."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(16))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scopes: Mapped[list] = mapped_column(JSON, default=lambda: ["ingest"])
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class RevokedToken(Base):
    """JWT ``jti`` denylist, written on logout."""

    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


# ── Monitoring configuration ─────────────────────────────────────────────────


class WatchItem(Base):
    """Something the tenant wants to know about: a domain, an email, a
    keyword, a brand. Sources are queried for these, and every leak is
    matched against them."""

    __tablename__ = "watch_items"
    __table_args__ = (UniqueConstraint("tenant_id", "type", "value"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(16))  # domain | email | keyword | ip | wallet
    value: Mapped[str] = mapped_column(String(255))
    is_vip: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Source(Base):
    """A recurring collector: an onion seed to crawl, a Telegram channel, a
    feed URL, or a scheduled Ahmia / GitHub / HIBP sweep over the watchlist."""

    __tablename__ = "sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # ahmia | onion | telegram | feed | github | hibp
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=360)
    max_pages: Mapped[int] = mapped_column(Integer, default=10)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SourceRun(Base):
    """Provenance for every collection: what was asked, what came back."""

    __tablename__ = "source_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    source_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(16))
    query: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running | ok | error
    results: Mapped[int] = mapped_column(Integer, default=0)
    queued: Mapped[int] = mapped_column(Integer, default=0)
    via_tor: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    report: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class YaraRule(Base):
    __tablename__ = "yara_rules"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)  # None = global
    name: Mapped[str] = mapped_column(String(120))
    content: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ── Intelligence ─────────────────────────────────────────────────────────────

class Leak(Base):
    __tablename__ = "leaks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    source_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Display text: secrets masked. The unmasked original is in object storage.
    snippet: Mapped[str] = mapped_column(Text, default="")
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    simhash64: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    severity: Mapped[int] = mapped_column(Integer, default=0, index=True)
    category: Mapped[str | None] = mapped_column(String(32), nullable=True)  # CREDENTIALS | FINANCIAL | PII | SOURCE | OTHER
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)  # new | reviewing | escalated | resolved | false_positive
    entities: Mapped[dict] = mapped_column(JSON, default=dict)
    yara_matches: Mapped[list] = mapped_column(JSON, default=list)
    watch_matches: Mapped[list] = mapped_column(JSON, default=list)
    ai_analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    cti: Mapped[dict] = mapped_column(JSON, default=dict)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    storage_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    seen_count: Mapped[int] = mapped_column(Integer, default=1)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    leak_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    level: Mapped[str] = mapped_column(String(16))  # critical | vip | info
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


# ── External risk (attack surface, brand, ransomware, vulnerabilities) ───────


class SurfaceHost(Base):
    """A hostname under one of the tenant's watched domains, found in
    certificate-transparency logs, plus what is publicly visible about it."""

    __tablename__ = "surface_hosts"
    __table_args__ = (UniqueConstraint("tenant_id", "hostname"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    root_domain: Mapped[str] = mapped_column(String(255), index=True)
    ips: Mapped[list] = mapped_column(JSON, default=list)
    ports: Mapped[list] = mapped_column(JSON, default=list)
    cves: Mapped[list] = mapped_column(JSON, default=list)
    cpes: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    sources: Mapped[list | None] = mapped_column(JSON, nullable=True)  # which discovery sources found it
    threats: Mapped[list | None] = mapped_column(JSON, nullable=True)  # threat-feed listings of it or its IPs
    tls_issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tls_not_after: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolves: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Lookalike(Base):
    """A registered domain that imitates one of the tenant's domains."""

    __tablename__ = "lookalikes"
    __table_args__ = (UniqueConstraint("tenant_id", "domain"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(255))
    target: Mapped[str] = mapped_column(String(255), index=True)
    technique: Mapped[str] = mapped_column(String(32))
    ips: Mapped[list] = mapped_column(JSON, default=list)
    has_mx: Mapped[bool] = mapped_column(Boolean, default=False)
    has_cert: Mapped[bool] = mapped_column(Boolean, default=False)
    risk: Mapped[int] = mapped_column(Integer, default=0, index=True)
    status: Mapped[str] = mapped_column(String(16), default="new")  # new | reviewing | takedown | benign
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RansomwareHit(Base):
    """A ransomware leak-site post that names one of the tenant's terms."""

    __tablename__ = "ransomware_hits"
    __table_args__ = (UniqueConstraint("tenant_id", "group", "victim"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    group: Mapped[str] = mapped_column(String(64))
    victim: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    activity: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    matched: Mapped[str] = mapped_column(String(255))
    url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    attack_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="new")  # new | acknowledged | false_positive
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class VulnFinding(Base):
    """A CVE on one of the tenant's exposed hosts, ranked by real-world
    exploitation (CISA KEV) and likelihood (FIRST EPSS)."""

    __tablename__ = "vuln_findings"
    __table_args__ = (UniqueConstraint("tenant_id", "host", "cve"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    host: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cve: Mapped[str] = mapped_column(String(32), index=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_added: Mapped[str | None] = mapped_column(String(16), nullable=True)
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    epss: Mapped[float | None] = mapped_column(nullable=True)
    percentile: Mapped[float | None] = mapped_column(nullable=True)
    priority: Mapped[str] = mapped_column(String(16), default="low")  # critical | high | medium | low
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | fixed | accepted
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TlsGrade(Base):
    """How well a surface host's TLS endpoint is configured, graded A–F."""

    __tablename__ = "tls_grades"
    __table_args__ = (UniqueConstraint("tenant_id", "hostname"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    grade: Mapped[str] = mapped_column(String(2))
    issues: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DnsRecord(Base):
    """Current answer for one record type of a watched domain."""

    __tablename__ = "dns_records"
    __table_args__ = (UniqueConstraint("tenant_id", "domain", "rtype"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(255))
    rtype: Mapped[str] = mapped_column(String(16))
    values: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    changed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SurfaceEvent(Base):
    """Something changed on the attack surface: the asset-monitoring log."""

    __tablename__ = "surface_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    subject: Mapped[str] = mapped_column(String(255))  # hostname or domain
    kind: Mapped[str] = mapped_column(String(32))  # host_added | host_gone | ip_changed | port_opened | port_closed | cert_changed | dns_changed
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info | warning | critical
    detail: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class PhishingUrl(Base):
    """A live phishing URL from a public feed that targets the tenant's brand."""

    __tablename__ = "phishing_urls"
    __table_args__ = (UniqueConstraint("tenant_id", "url"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(1024))
    host: Mapped[str] = mapped_column(String(255))
    target: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(32))
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="new")  # new | reported | down | benign
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class IntelCache(Base):
    """Small key/value store: shared feeds (KEV catalogue, recent ransomware
    victims) and per-tenant scan status (``scan:<tenant>:<module>``)."""

    __tablename__ = "intel_cache"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ── Investigations (AI Co-Analyst) ───────────────────────────────────────────


class InvestigationPlan(Base):
    __tablename__ = "investigation_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | closed
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    tasks: Mapped[list["InvestigationTask"]] = relationship(
        back_populates="plan", cascade="all, delete-orphan", order_by="InvestigationTask.created_at"
    )


class InvestigationTask(Base):
    __tablename__ = "investigation_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    plan_id: Mapped[str] = mapped_column(ForeignKey("investigation_plans.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="todo")  # todo | doing | done
    created_by: Mapped[str] = mapped_column(String(16), default="human")  # human | ai
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    plan: Mapped[InvestigationPlan] = relationship(back_populates="tasks")


# ── Audit ────────────────────────────────────────────────────────────────────


class AuditLog(Base):
    """Tamper-evident: each row hashes its content plus the previous row's
    hash (per tenant). An edit or deletion breaks the chain at a position the
    verifier reports. It detects tampering; it does not prevent it."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    prev_hash: Mapped[str] = mapped_column(String(64), default="0" * 64)
    row_hash: Mapped[str] = mapped_column(String(64))
