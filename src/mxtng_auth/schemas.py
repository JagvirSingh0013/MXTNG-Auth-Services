"""Request/response models. Responses carry identity only — no product fields."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


# --- Credentials / signup ---------------------------------------------------
class CredentialCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=256)
    audience: str | None = None


class CredentialRead(BaseModel):
    auth_user_id: str
    email: EmailStr


# --- Login / tokens ---------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    audience: str | None = None


class TokenResponse(BaseModel):
    """Product-generic identity token. Products fetch their own domain data
    (workspace, agency, role) from their own `/users/me`, never from here."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int


# --- Password reset ---------------------------------------------------------
class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=256)


# --- Google -----------------------------------------------------------------
class GoogleAuthStart(BaseModel):
    authorization_url: str


class GoogleExchangeRequest(BaseModel):
    code: str
    state: str | None = None
    audience: str | None = None


# --- Admin identity mutations (service-to-service) --------------------------
class EmailChange(BaseModel):
    email: EmailStr


class MessageResponse(BaseModel):
    message: str
