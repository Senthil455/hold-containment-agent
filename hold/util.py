"""Small shared utilities: canonical hashing, time, text normalisation.

Deliberately dependency-free so the reference implementation runs anywhere
Python 3.11+ is available (including a locked-down build box).
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8 safe."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any, *, prefix: str = "sha256:") -> str:
    return prefix + sha256_hex(canonical_json(obj))


def short_hash(value: str, n: int = 12) -> str:
    return value[:n]


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or utcnow()).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# Text normalisation (used by the injection scanner and the output guard)
# ---------------------------------------------------------------------------

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)

# A deliberately small confusable map. The goal is detection of obfuscation,
# not a general-purpose Unicode security library.
_CONFUSABLES = str.maketrans(
    {
        "\u0430": "a",  # cyrillic a
        "\u0435": "e",  # cyrillic e
        "\u043e": "o",  # cyrillic o
        "\u0440": "p",  # cyrillic er
        "\u0441": "c",  # cyrillic es
        "\u0443": "y",  # cyrillic u
        "\u0456": "i",  # cyrillic i
        "\u04bb": "h",
        "\u0501": "d",
        "\u0261": "g",
        "\uFF41": "a",
    }
)


def normalize_text(text: str) -> str:
    """NFKC + strip invisible characters + fold common homoglyphs + lowercase.

    Used only for pattern matching. Never used to rewrite content that is
    shown to a human, so evidence is preserved verbatim in the ledger.
    """
    folded = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return folded.translate(_CONFUSABLES).replace("\r\n", "\n").lower()


def collapse_ws(text: str) -> str:
    return re.sub(r"[ \t\u00a0]+", " ", text).strip()


def clip(text: str, limit: int) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "\u2026"


# ---------------------------------------------------------------------------
# Output redaction
# ---------------------------------------------------------------------------

_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")
_PHONE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")


def redact_pii(text: str) -> str:
    """Defence in depth for the output path.

    The system is designed so that recipient contact data never reaches the
    model in the first place. This is the belt to that braces: if anything
    contact-shaped shows up in model output, it is masked before a human sees
    it.
    """
    text = _CARD.sub("[redacted:card]", text)
    text = _EMAIL.sub("[redacted:email]", text)
    text = _PHONE.sub("[redacted:phone]", text)
    return text


def mask_contact(value: str) -> str:
    if "@" in value:
        local, _, domain = value.partition("@")
        head = local[:2] if len(local) > 2 else local[:1]
        return f"{head}***@{domain}"
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        return "***-***-" + digits[-4:]
    return "***"
