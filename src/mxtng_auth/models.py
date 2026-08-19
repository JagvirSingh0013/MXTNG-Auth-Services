"""Auth domain tables. Identity only — no product concepts (ADR-0005)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from mxtng_auth.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Credential(Base):
    """A human's identity: the global Auth User Id plus login means (password/Google).

    `auth_user_id` is the canonical, product-neutral UUID and the `sub` of every
    issued token. A Credential is NOT a product account (ADR-0007).
    """

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    auth_user_id: Mapped[str] = mapped_column(
        String(36), unique=True, index=True, default=_uuid, nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    google_sub: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)

    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="credential", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    """One rotating, single-use refresh token. Reuse of a rotated/revoked token is
    treated as theft and revokes the whole `family_id` (ADR-0006)."""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    credential_id: Mapped[int] = mapped_column(
        ForeignKey("credentials.id"), index=True, nullable=False
    )
    family_id: Mapped[str] = mapped_column(String(36), index=True, default=_uuid, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    audience: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Set when this token has been rotated (consumed) into a successor.
    rotated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    credential: Mapped["Credential"] = relationship(back_populates="refresh_tokens")


class PasswordResetToken(Base):
    """Single-use, short-TTL password reset token (hash stored, never the raw)."""

    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    credential_id: Mapped[int] = mapped_column(
        ForeignKey("credentials.id"), index=True, nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)


class SignInChallenge(Base):
    """A pending second factor: the first factor passed, tokens are withheld until
    the emailed Sign-in Code is presented (ADR-0011).

    Also carries the Google hand-off — a challenge id is useless without the code
    in the mailbox, so it can ride in a redirect URL where a token never could.
    That is why `oauth_exchange_codes` no longer exists.
    """

    __tablename__ = "sign_in_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    challenge_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, default=_uuid, nullable=False
    )
    credential_id: Mapped[int] = mapped_column(
        ForeignKey("credentials.id"), index=True, nullable=False
    )
    # bcrypt over the code: a 6-digit secret is trivially reversible from a plain
    # digest, so the cost factor is what makes a leaked table useless.
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    audience: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sends: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    last_sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    consumed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)


class AuthAuditLog(Base):
    """Append-only record of security-relevant events (login, signup, reset, …)."""

    __tablename__ = "auth_audit_log"
    __table_args__ = (UniqueConstraint("id", name="uq_auth_audit_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    credential_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    event: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)


class Session(Base):
    """One sign-in on one device. The `sid` claim in every access token points here.

    Access tokens are verified offline (ADR-0006), so before this table existed
    nothing could shorten a token's life below its `exp` — revoking a refresh
    family was invisible to a product that never refreshes. A session id in the
    token gives products something cheap to ask about, which is what makes
    "one session per account" enforceable rather than merely intended.

    `family_id` ties the session to its refresh chain so revoking one revokes both.
    """

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(
        String(36), unique=True, index=True, default=_uuid, nullable=False
    )
    credential_id: Mapped[int] = mapped_column(
        ForeignKey("credentials.id"), index=True, nullable=False
    )
    audience: Mapped[str] = mapped_column(String(64), nullable=False)
    # Set once the session's first refresh token exists; null for a session whose
    # product never took a refresh cookie.
    family_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)

    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # "superseded" (another device signed in), "logout", "logout_all",
    # "password_reset", "account_disabled". Kept for the audit trail and for
    # telling a user why they were signed out, should a product want to.
    revoked_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
