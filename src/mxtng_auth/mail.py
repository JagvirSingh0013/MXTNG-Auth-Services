"""Outbound mail for identity messages (ADR-0011).

Two paths, one message. The primary path posts a fully-rendered message to the
ATS platform-mail relay, which owns the only SMTP configuration a Super Admin has
set up (ADR-0010). The break-glass path talks SMTP directly from environment
variables, and exists because the primary path is circular at bootstrap: you
cannot log in to configure the mail that logging in requires.

Bodies are rendered here, in source, rather than from ADR-0010's operator-editable
templates. An operator who deactivates a template or drops `{{ code }}` while
tidying wording would otherwise lock every user out of the platform.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import json
import logging
import smtplib
import time
from datetime import datetime, timezone
from email.message import EmailMessage

import httpx

from mxtng_auth.settings import settings

logger = logging.getLogger(__name__)

PURPOSE_SIGN_IN_CODE = "sign_in_code"
PURPOSE_PASSWORD_RESET = "password_reset"

# The relay sends inline for messages a human is actively waiting on, and through
# ADR-0010's durable outbox for everything else.
MODE_INLINE = "inline"
MODE_QUEUED = "queued"


class MailUndeliverable(Exception):
    """Neither the relay nor the fallback could hand the message to a mail server."""


class RenderedMessage:
    __slots__ = ("subject", "html_body", "text_body")

    def __init__(self, subject: str, html_body: str, text_body: str) -> None:
        self.subject = subject
        self.html_body = html_body
        self.text_body = text_body


# --- Templates --------------------------------------------------------------
def _shell(heading: str, body_html: str) -> str:
    return (
        '<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;'
        'max-width:480px;margin:0 auto;padding:24px;color:#111">'
        f'<h1 style="font-size:18px;margin:0 0 16px">{heading}</h1>'
        f"{body_html}"
        '<p style="font-size:12px;color:#666;margin-top:24px">'
        "If you did not request this, you can safely ignore this email."
        "</p></div>"
    )


def render_sign_in_code(*, code: str, ttl_seconds: int, requested_at: datetime) -> RenderedMessage:
    """The requested-at stamp is load-bearing: a resend invalidates the previous
    code, so two live emails must be distinguishable at a glance."""
    minutes = max(1, ttl_seconds // 60)
    stamp = requested_at.astimezone(timezone.utc).strftime("%H:%M UTC on %d %b %Y")
    body = (
        '<p style="font-size:14px;margin:0 0 16px">Enter this code to finish signing in:</p>'
        f'<p style="font-size:32px;letter-spacing:6px;font-weight:600;margin:0 0 16px">'
        f"{html.escape(code)}</p>"
        f'<p style="font-size:14px;margin:0 0 8px">It expires in {minutes} minutes.</p>'
        f'<p style="font-size:13px;color:#666;margin:0">Requested at {html.escape(stamp)}. '
        "If you asked for a new code, only the most recent one works.</p>"
    )
    text = (
        f"Your sign-in code is {code}.\n\n"
        f"It expires in {minutes} minutes.\n"
        f"Requested at {stamp}. If you asked for a new code, only the most recent one works.\n\n"
        "If you did not request this, you can safely ignore this email."
    )
    return RenderedMessage("Your sign-in code", _shell("Your sign-in code", body), text)


def render_password_reset(*, token: str, ttl_seconds: int, reset_url: str | None) -> RenderedMessage:
    minutes = max(1, ttl_seconds // 60)
    if reset_url:
        sep = "&" if "?" in reset_url else "?"
        link = f"{reset_url}{sep}token={token}"
        body = (
            '<p style="font-size:14px;margin:0 0 16px">Use this link to choose a new password:</p>'
            f'<p style="margin:0 0 16px"><a href="{html.escape(link, quote=True)}">'
            "Reset your password</a></p>"
            f'<p style="font-size:14px;margin:0">The link expires in {minutes} minutes and '
            "can be used once.</p>"
        )
        text = (
            f"Use this link to choose a new password:\n{link}\n\n"
            f"The link expires in {minutes} minutes and can be used once."
        )
    else:
        body = (
            '<p style="font-size:14px;margin:0 0 16px">Use this token to choose a new password:</p>'
            f'<p style="font-size:14px;font-family:monospace;word-break:break-all;margin:0 0 16px">'
            f"{html.escape(token)}</p>"
            f'<p style="font-size:14px;margin:0">It expires in {minutes} minutes and can be '
            "used once.</p>"
        )
        text = (
            f"Use this token to choose a new password:\n{token}\n\n"
            f"It expires in {minutes} minutes and can be used once."
        )
    return RenderedMessage("Reset your password", _shell("Reset your password", body), text)


# --- Relay ------------------------------------------------------------------
def _sign(body: bytes, timestamp: str) -> str:
    payload = timestamp.encode("utf-8") + b"." + body
    digest = hmac.new(settings.MAIL_RELAY_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def _send_via_relay(*, to_email: str, message: RenderedMessage, purpose: str, mode: str) -> None:
    if not settings.MAIL_RELAY_URL:
        raise MailUndeliverable("No mail relay configured")

    body = json.dumps(
        {
            "to_email": to_email,
            "subject": message.subject,
            "html_body": message.html_body,
            "text_body": message.text_body,
            "purpose": purpose,
            "mode": mode,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    timestamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "X-MXTNG-Timestamp": timestamp,
        "X-MXTNG-Signature": _sign(body, timestamp),
    }
    async with httpx.AsyncClient(timeout=settings.MAIL_RELAY_TIMEOUT_SECONDS) as client:
        resp = await client.post(settings.MAIL_RELAY_URL, content=body, headers=headers)
    if resp.status_code >= 300:
        raise MailUndeliverable(f"Relay returned HTTP {resp.status_code}: {resp.text[:200]}")


# --- Fallback SMTP ----------------------------------------------------------
def _send_smtp_blocking(*, to_email: str, message: RenderedMessage) -> None:
    email = EmailMessage()
    email["Subject"] = message.subject
    email["From"] = f"{settings.MAIL_FROM_NAME} <{settings.MAIL_FROM_EMAIL}>"
    email["To"] = to_email
    email.set_content(message.text_body)
    email.add_alternative(message.html_body, subtype="html")

    with smtplib.SMTP(
        settings.FALLBACK_SMTP_HOST,
        settings.FALLBACK_SMTP_PORT,
        timeout=settings.FALLBACK_SMTP_TIMEOUT_SECONDS,
    ) as smtp:
        if settings.FALLBACK_SMTP_USE_TLS:
            smtp.starttls()
        if settings.FALLBACK_SMTP_USERNAME:
            smtp.login(settings.FALLBACK_SMTP_USERNAME, settings.FALLBACK_SMTP_PASSWORD or "")
        smtp.send_message(email)


async def _send_via_fallback(*, to_email: str, message: RenderedMessage) -> None:
    if not settings.fallback_smtp_enabled:
        raise MailUndeliverable("No fallback SMTP configured")
    try:
        await asyncio.to_thread(_send_smtp_blocking, to_email=to_email, message=message)
    except (smtplib.SMTPException, OSError) as exc:
        raise MailUndeliverable(f"Fallback SMTP failed: {exc}") from exc


# --- Public API -------------------------------------------------------------
async def send(*, to_email: str, message: RenderedMessage, purpose: str, mode: str) -> str:
    """Deliver via the relay, falling back to direct SMTP. Returns the path used.

    Raises MailUndeliverable when both paths fail, so a sign-in whose code was
    never sent fails loudly instead of leaving someone waiting on an email that
    is not coming.
    """
    try:
        await _send_via_relay(to_email=to_email, message=message, purpose=purpose, mode=mode)
        return "relay"
    except (MailUndeliverable, httpx.HTTPError) as exc:
        logger.warning("Mail relay unavailable for %s (%s); trying fallback SMTP", purpose, exc)

    await _send_via_fallback(to_email=to_email, message=message)
    return "fallback"
