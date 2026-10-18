"""Passwords, tokens and API keys."""

import hashlib
import logging
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache

import bcrypt
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .config import settings

logger = logging.getLogger("secyourscan.security")

API_KEY_PREFIX = "sys_"


# ── Passwords ────────────────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    # bcrypt reads at most 72 bytes; longer inputs are pre-hashed so the tail
    # of a long passphrase still counts.
    raw = password.encode()
    if len(raw) > 72:
        raw = hashlib.sha256(raw).hexdigest().encode()
    return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    raw = password.encode()
    if len(raw) > 72:
        raw = hashlib.sha256(raw).hexdigest().encode()
    try:
        return bcrypt.checkpw(raw, password_hash.encode())
    except ValueError:
        return False


# A real hash to compare against when the user does not exist, so a login for
# an unknown email costs the same as one with a wrong password.
_DUMMY_HASH = bcrypt.hashpw(b"timing-equaliser", bcrypt.gensalt(rounds=12)).decode()


def dummy_verify() -> None:
    verify_password("x", _DUMMY_HASH)


# ── Signing keys ─────────────────────────────────────────────────────────────


def _read_pem(value: str | None) -> bytes | None:
    if not value:
        return None
    if value.strip().startswith("-----BEGIN"):
        return value.encode()
    if os.path.isfile(value):
        with open(value, "rb") as f:
            return f.read()
    raise ValueError("key is neither a PEM string nor a readable file path")


@lru_cache
def signing_keys() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv_pem = _read_pem(settings.JWT_PRIVATE_KEY)
    if priv_pem:
        private = serialization.load_pem_private_key(priv_pem, password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError("JWT_PRIVATE_KEY must be an Ed25519 key")
        return private, private.public_key()
    if settings.is_production:
        raise RuntimeError("JWT_PRIVATE_KEY is required in production (run scripts/gen_secrets.py)")
    logger.warning("No JWT_PRIVATE_KEY set: using an ephemeral key; sessions end on restart")
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def public_key_pem() -> str:
    _, public = signing_keys()
    return public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


# ── JWT ──────────────────────────────────────────────────────────────────────


def create_access_token(user_id: str, tenant_id: str, role: str) -> tuple[str, str, datetime]:
    private, _ = signing_keys()
    now = datetime.now(UTC)
    expires = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = uuid.uuid4().hex
    claims = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "sub": user_id,
        "tid": tenant_id,
        "role": role,
        "iat": now,
        "nbf": now,
        "exp": expires,
        "jti": jti,
    }
    return jwt.encode(claims, private, algorithm="EdDSA"), jti, expires


def decode_access_token(token: str) -> dict:
    _, public = signing_keys()
    return jwt.decode(
        token,
        public,
        algorithms=["EdDSA"],
        audience=settings.JWT_AUDIENCE,
        issuer=settings.JWT_ISSUER,
        leeway=settings.JWT_LEEWAY_SECONDS,
        options={"require": ["iss", "aud", "sub", "iat", "nbf", "exp", "jti"]},
    )


# ── API keys ─────────────────────────────────────────────────────────────────


def generate_api_key() -> tuple[str, str, str]:
    """Return ``(plaintext, prefix, sha256)``. The plaintext is shown once."""
    plaintext = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return plaintext, plaintext[:10], hash_api_key(plaintext)


def hash_api_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()
