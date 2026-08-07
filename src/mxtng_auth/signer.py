"""RS256 signing behind a `Signer` seam (KMS-ready), plus JWKS publication (ADR-0006).

`LocalRSASigner` holds the private key in-process (dev/simple prod via secret
manager PEM injection). The `Signer` interface is the seam where a KMS-backed
signer slots in later without changing token issuance or the JWKS endpoint.
"""
from __future__ import annotations

import base64
import hashlib
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

from mxtng_auth.settings import settings

ALGORITHM = "RS256"


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


def _derive_kid(public_pem: bytes) -> str:
    return hashlib.sha256(public_pem).hexdigest()[:16]


class Signer(ABC):
    """Signs access-token claims and publishes verification keys as a JWKS."""

    @abstractmethod
    def sign(self, claims: dict) -> str: ...

    @abstractmethod
    def jwks(self) -> dict: ...


class LocalRSASigner(Signer):
    def __init__(self, private_key: rsa.RSAPrivateKey, kid: str) -> None:
        self._private_key = private_key
        self._private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        self.kid = kid

    # --- construction -------------------------------------------------------
    @classmethod
    def from_settings(cls) -> "LocalRSASigner":
        """Load the PEM from env, else from a file path, generating one in dev."""
        pem: str | None = settings.PRIVATE_KEY_PEM
        if not pem:
            path = Path(settings.PRIVATE_KEY_PATH)
            if path.exists():
                pem = path.read_text()
            else:
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                pem = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode("ascii")
                # Dev convenience only; prod injects PRIVATE_KEY_PEM from a secret manager.
                if settings.ENVIRONMENT != "production":
                    path.write_text(pem)

        private_key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Signing key must be RSA")
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        kid = settings.KEY_ID or _derive_kid(public_pem)
        return cls(private_key, kid)

    # --- Signer -------------------------------------------------------------
    def sign(self, claims: dict) -> str:
        return jwt.encode(
            claims, self._private_pem, algorithm=ALGORITHM, headers={"kid": self.kid}
        )

    def jwks(self) -> dict:
        numbers = self._private_key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": ALGORITHM,
                    "kid": self.kid,
                    "n": _b64url_uint(numbers.n),
                    "e": _b64url_uint(numbers.e),
                }
            ]
        }


# Process-wide signer, initialised at startup (see main.lifespan).
_signer: Signer | None = None


def get_signer() -> Signer:
    global _signer
    if _signer is None:
        _signer = LocalRSASigner.from_settings()
    return _signer


def set_signer(signer: Signer) -> None:
    global _signer
    _signer = signer
