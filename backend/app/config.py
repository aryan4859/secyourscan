"""Every setting in one place.

Values come from the environment (or ``.env``). Docker secrets mounted under
``/run/secrets`` are read too, so a password never has to sit in an env var.
Optional backing services are switched off by leaving their credentials unset;
``/system/health`` then reports them ``disabled`` rather than broken.
"""

import os
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

_SECRETS_DIR = "/run/secrets"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        secrets_dir=_SECRETS_DIR if os.path.isdir(_SECRETS_DIR) else None,
    )

    ENV: str = "development"  # development | production
    PROJECT_NAME: str = "SecYourScan"

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./secyourscan.db"
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10

    # Auth — EdDSA (Ed25519) JWTs. Keys are PEM strings or paths to PEM files.
    JWT_PRIVATE_KEY: str | None = None
    JWT_PUBLIC_KEY: str | None = None
    JWT_ISSUER: str = "secyourscan"
    JWT_AUDIENCE: str = "secyourscan-api"
    JWT_LEEWAY_SECONDS: int = 30
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    COOKIE_SECURE: bool = False  # True behind HTTPS
    ADMIN_EMAIL: str | None = None
    ADMIN_PASSWORD: str | None = None

    # Network
    CORS_ORIGINS: str = "http://localhost:5173"
    ALLOWED_HOSTS: str = "*"

    # Broker. When unset (or PIPELINE_INLINE=true) the pipeline runs in-process,
    # which is how the tests and a laptop without RabbitMQ work.
    RABBITMQ_URL: str | None = None
    PIPELINE_INLINE: bool = False

    # Elasticsearch (optional)
    ES_URL: str | None = None
    ES_USER: str = "elastic"
    ES_PASSWORD: str | None = None
    ES_VERIFY_CERTS: bool = True
    ES_INDEX: str = "secyourscan-leaks"

    # MinIO / S3 (optional)
    MINIO_ENDPOINT: str | None = None
    MINIO_ACCESS_KEY: str | None = None
    MINIO_SECRET_KEY: str | None = None
    MINIO_SECURE: bool = False

    # Tor — HAProxy in front of the Tor pool, SOCKS5 with remote DNS.
    TOR_PROXY: str | None = None  # e.g. socks5h://tor-lb:9050
    AHMIA_URL: str = "https://ahmia.fi/search/"
    CRAWL_MAX_PAGES: int = 10
    CRAWL_MAX_BYTES: int = 1_048_576

    # AI — any OpenAI-compatible server (Ollama, LM Studio, vLLM). Unset = off.
    AI_ENDPOINT: str | None = None
    AI_MODEL: str = "llama3.1:8b"
    AI_API_KEY: str | None = None
    AI_TIMEOUT_SECONDS: float = 90.0
    AI_MAX_ITERATIONS: int = 5

    # Scans and domain reports cover only root domains proven with a DNS TXT
    # record. Turn off only for labs and demos.
    REQUIRE_DOMAIN_VERIFICATION: bool = True

    # Licensing (on-prem builds). With no public key, licensing is off.
    LICENSE_PUBLIC_KEY: str | None = None  # vendor's Ed25519 public key, base64url
    LICENSE_KEY: str | None = None  # SYS1.<payload>.<signature> issued to this customer

    # External risk feeds (all keyless). Override to point at a mirror.
    CRTSH_URL: str = "https://crt.sh/"
    CERTSPOTTER_URL: str = "https://api.certspotter.com/v1/issuances"
    RANSOMWARE_LIVE_URL: str = "https://api.ransomware.live/v2"
    KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL: str = "https://api.first.org/data/v1/epss"
    HACKERTARGET_URL: str = "https://api.hackertarget.com/hostsearch/"
    WAYBACK_CDX_URL: str = "https://web.archive.org/cdx/search/cdx"
    OTX_API_KEY: str | None = None  # free at otx.alienvault.com; enables OTX passive DNS
    SURFACE_DNS_BRUTEFORCE: bool = True  # resolve ~170 common subdomain names
    URLHAUS_RECENT_URL: str = "https://urlhaus.abuse.ch/downloads/text_recent/"
    FEODO_URL: str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    THREATFOX_RECENT_URL: str = "https://threatfox.abuse.ch/export/json/recent/"
    OPENPHISH_URL: str = "https://openphish.com/feed.txt"
    PHISHSTATS_URL: str = "https://api.phishstats.info/api/phishing"
    RANSOMLOOK_URL: str = "https://www.ransomlook.io/api"
    INTEL_SWEEP_HOURS: int = 6
    SURFACE_MAX_HOSTS: int = 300  # per root domain
    LOOKALIKE_MAX_CANDIDATES: int = 400  # permutations checked per domain

    # Integrations
    SOAR_WEBHOOK_URL: str | None = None
    THREATFOX_AUTH_KEY: str | None = None
    # IOC Hunting enrichment (all optional; free tiers exist for each).
    ABUSECH_AUTH_KEY: str | None = None  # auth.abuse.ch: ThreatFox + MalwareBazaar APIs; falls back to THREATFOX_AUTH_KEY
    ABUSEIPDB_API_KEY: str | None = None
    VIRUSTOTAL_API_KEY: str | None = None
    GITHUB_TOKEN: str | None = None
    HIBP_API_KEY: str | None = None

    # Scoring
    SOAR_THRESHOLD: int = 90
    CRITICAL_THRESHOLD: int = 80
    NEAR_DUP_THRESHOLD: int = 3

    # Dossier signing (Ed25519). Falls back to the JWT key.
    DOSSIER_SIGNING_KEY: str | None = None

    @property
    def is_production(self) -> bool:
        return self.ENV == "production"

    @property
    def inline_pipeline(self) -> bool:
        return self.PIPELINE_INLINE or not self.RABBITMQ_URL

    @property
    def es_enabled(self) -> bool:
        return bool(self.ES_URL and self.ES_PASSWORD)

    @property
    def minio_enabled(self) -> bool:
        return bool(self.MINIO_ENDPOINT and self.MINIO_ACCESS_KEY and self.MINIO_SECRET_KEY)

    @property
    def ai_enabled(self) -> bool:
        return bool(self.AI_ENDPOINT)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
