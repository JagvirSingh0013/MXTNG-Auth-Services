"""Password hashing (bcrypt) and opaque-token hashing helpers."""
from __future__ import annotations

import hashlib
import hmac
import secrets

import bcrypt


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def new_opaque_token() -> str:
    """A high-entropy, URL-safe secret. Only its hash is ever persisted."""
    return secrets.token_urlsafe(48)


def hash_opaque_token(raw: str) -> str:
    """Deterministic SHA-256 so a presented token can be looked up by hash."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
