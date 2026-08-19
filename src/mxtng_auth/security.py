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


def new_sign_in_code(length: int = 6) -> str:
    """A zero-padded numeric Sign-in Code, uniformly random over the whole space."""
    upper = 10**length
    return str(secrets.randbelow(upper)).zfill(length)


def hash_sign_in_code(code: str) -> str:
    """bcrypt, not SHA-256. A six-digit code has only a million possibilities, so a
    plain digest is reversible in seconds; the work factor is the only protection
    a leaked table has."""
    return hash_password(code)


def verify_sign_in_code(code: str, code_hash: str | None) -> bool:
    return verify_password(code, code_hash)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
