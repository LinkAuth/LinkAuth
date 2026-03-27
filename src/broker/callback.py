from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from uuid import uuid4

import httpx

try:
    import drawbridge
except ImportError:
    drawbridge = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_BASE = 4  # 1s, 4s, 16s


async def deliver_callback(
    callback_url: str,
    session_id: str,
    ciphertext: str,
    algorithm: str | None = None,
    callback_secret: str | None = None,
) -> bool:
    """POST encrypted credentials to the agent's callback URL.

    Returns True if delivery succeeded (2xx), False otherwise.
    Includes HMAC-SHA256 signature, idempotent delivery ID, and retry with
    exponential backoff. Uses drawbridge for SSRF protection when available.
    """
    payload = {
        "session_id": session_id,
        "status": "ready",
        "ciphertext": ciphertext,
    }
    if algorithm:
        payload["algorithm"] = algorithm

    body_bytes = json.dumps(payload, separators=(",", ":")).encode()
    delivery_id = str(uuid4())

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "X-LinkAuth-Delivery-Id": delivery_id,
    }
    if callback_secret:
        sig = hmac.new(callback_secret.encode(), body_bytes, hashlib.sha256).hexdigest()
        headers["X-LinkAuth-Signature"] = f"sha256={sig}"

    try:
        client_cm = drawbridge.Client() if drawbridge is not None else httpx.AsyncClient(timeout=10.0)
        async with client_cm as client:
            for attempt in range(_MAX_RETRIES):
                try:
                    if drawbridge is not None:
                        resp = await client.post(
                            callback_url, content=body_bytes, headers=headers,
                            timeout=10.0, max_redirects=0,
                        )
                    else:
                        resp = await client.post(
                            callback_url, content=body_bytes, headers=headers,
                        )

                    if resp.is_success:
                        logger.info(
                            "Callback delivered to %s (delivery_id=%s, attempt=%d)",
                            callback_url, delivery_id, attempt + 1,
                        )
                        return True

                    if resp.status_code < 500:
                        logger.warning(
                            "Callback to %s returned %d (non-retryable, delivery_id=%s)",
                            callback_url, resp.status_code, delivery_id,
                        )
                        return False

                    logger.warning(
                        "Callback to %s returned %d (attempt %d/%d, delivery_id=%s)",
                        callback_url, resp.status_code, attempt + 1, _MAX_RETRIES, delivery_id,
                    )

                except Exception as exc:
                    if drawbridge is not None and isinstance(exc, drawbridge.DrawbridgeError):
                        logger.error("Callback to %s blocked by SSRF protection: %s", callback_url, exc)
                        return False
                    logger.warning(
                        "Callback to %s failed (attempt %d/%d, delivery_id=%s): %s",
                        callback_url, attempt + 1, _MAX_RETRIES, delivery_id, exc,
                    )

                if attempt < _MAX_RETRIES - 1:
                    backoff = _BACKOFF_BASE ** attempt
                    await asyncio.sleep(backoff)
    except Exception as exc:
        logger.error("Callback client creation failed for %s: %s", callback_url, exc)
        return False

    logger.error(
        "Callback to %s failed after %d attempts (delivery_id=%s)",
        callback_url, _MAX_RETRIES, delivery_id,
    )
    return False
