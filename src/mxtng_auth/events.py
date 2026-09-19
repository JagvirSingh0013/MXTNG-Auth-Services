"""IdentityEvent emitter: signed, typed webhooks to product receivers (ADR-0007).

Auth→product identity changes (`email.changed`, `account.disabled`, …) are
delivered as best-effort, HMAC-signed POSTs. The transport is intentionally
simple and swappable for a durable event bus later; receivers must be idempotent
(each event carries a stable `id`).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timezone

import httpx

from mxtng_auth.settings import reveal, settings

logger = logging.getLogger(__name__)

EMAIL_CHANGED = "email.changed"
ACCOUNT_DISABLED = "account.disabled"


def _sign(body: bytes, timestamp: str) -> str:
    """HMAC over `timestamp . body`, matching the mail relay's scheme.

    Signing the body alone made every delivered event an indefinitely replayable
    artefact: one captured `account.disabled` could be re-posted forever
    (SECURITY_AUDIT M-14). Binding the timestamp into the signature lets a
    receiver reject anything outside a narrow window.
    """
    secret = reveal(settings.WEBHOOK_SECRET)
    if not secret:
        raise RuntimeError("WEBHOOK_SECRET is not configured")
    payload = timestamp.encode("utf-8") + b"." + body
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def emit(event_type: str, *, auth_user_id: str, data: dict) -> None:
    """Fan out one IdentityEvent to every registered endpoint. Never raises."""
    if not settings.WEBHOOK_ENDPOINTS:
        return
    if not reveal(settings.WEBHOOK_SECRET):
        # Unsigned identity events are worse than undelivered ones: a receiver
        # that accepts them accepts anyone's.
        logger.error(
            "Refusing to emit IdentityEvent %s: WEBHOOK_ENDPOINTS is configured but "
            "WEBHOOK_SECRET is not.",
            event_type,
        )
        return
    event = {
        "id": str(uuid.uuid4()),
        "type": event_type,
        "auth_user_id": auth_user_id,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    body = json.dumps(event, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "X-MXTNG-Timestamp": timestamp,
        "X-MXTNG-Signature": _sign(body, timestamp),
        "X-MXTNG-Event": event_type,
        "X-MXTNG-Event-Id": event["id"],
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        for url in settings.WEBHOOK_ENDPOINTS:
            for attempt in range(3):  # best-effort retry
                try:
                    resp = await client.post(url, content=body, headers=headers)
                    if resp.status_code < 300:
                        break
                    logger.warning("IdentityEvent %s -> %s HTTP %s", event_type, url, resp.status_code)
                except httpx.HTTPError as exc:
                    logger.warning("IdentityEvent %s -> %s attempt %s failed: %s", event_type, url, attempt + 1, exc)
