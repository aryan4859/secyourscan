"""Identifier normalisation and near-duplicate fingerprinting.

The same leak arrives in many shapes — a Telegram forward, a paste mirror,
re-encoded whitespace. SHA-256 only catches byte-identical copies, so content
is also normalised and fingerprinted with a 64-bit SimHash over word trigrams;
two leaks within ``NEAR_DUP_THRESHOLD`` bits are treated as the same leak.
"""

import re
import unicodedata
from hashlib import blake2b

_WORD_RE = re.compile(r"\w+", re.UNICODE)
_WS_RE = re.compile(r"\s+")
_PHONE_STRIP_RE = re.compile(r"[^\d+]")


def normalize_identifier(value: str, type_: str) -> str:
    s = unicodedata.normalize("NFKC", value).strip()
    if type_ == "email":
        s = s.lower()
        local, _, domain = s.partition("@")
        # Gmail ignores dots and +tags; folding them stops one person becoming
        # three identities.
        if domain in {"gmail.com", "googlemail.com"}:
            local = local.split("+", 1)[0].replace(".", "")
            domain = "gmail.com"
        return f"{local}@{domain}"
    if type_ == "domain":
        s = s.lower().rstrip(".")
        return s[4:] if s.startswith("www.") else s
    if type_ == "phone":
        return _PHONE_STRIP_RE.sub("", s)
    if type_ in {"btc", "xmr"}:
        return s  # case-sensitive encodings
    return s.lower()


def normalize_content(raw: str) -> str:
    if not raw:
        return ""
    s = unicodedata.normalize("NFKC", raw).lower()
    s = re.sub(r"[^\w@.\-+\s]", " ", s)
    return _WS_RE.sub(" ", s).strip()


def _feature_hash(feature: str) -> int:
    return int.from_bytes(blake2b(feature.encode(), digest_size=8).digest(), "big")


def _to_signed(u: int) -> int:
    return u - (1 << 64) if u >= (1 << 63) else u


def _to_unsigned(s: int) -> int:
    return s + (1 << 64) if s < 0 else s


def simhash64(text: str, n_gram: int = 3) -> int:
    """Charikar SimHash. Signed so it fits a BIGINT column."""
    tokens = _WORD_RE.findall(text.lower()) if text else []
    if not tokens:
        return 0
    if len(tokens) >= n_gram:
        features = [" ".join(tokens[i : i + n_gram]) for i in range(len(tokens) - n_gram + 1)]
    else:
        features = tokens
    weights = [0] * 64
    for feat in features:
        h = _feature_hash(feat)
        for bit in range(64):
            weights[bit] += 1 if (h >> bit) & 1 else -1
    value = 0
    for bit in range(64):
        if weights[bit] > 0:
            value |= 1 << bit
    return _to_signed(value)


def hamming_distance(a: int, b: int) -> int:
    return (_to_unsigned(a) ^ _to_unsigned(b)).bit_count()
