from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from uuid import uuid4


import httpx
import structlog

try:
    import drawbridge
except ImportError:
    drawbridge = None  # type: ignore[assignment]

logger = structlog.get_logger(__name__)

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
        if drawbridge is not None:
            policy = drawbridge.Policy(max_redirects=0, timeout=10.0)
            client_cm = drawbridge.Client(policy)
        else:
            client_cm = httpx.AsyncClient(timeout=10.0)
        async with client_cm as client:
            for attempt in range(_MAX_RETRIES):
                try:
                    resp = await client.post(
                        callback_url, content=body_bytes, headers=headers,
                    )

                    if resp.is_success:
                        logger.info("callback.delivered",
                                    callback_url=callback_url, delivery_id=delivery_id,
                                    attempt=attempt + 1)
                        return True

                    if resp.status_code < 500:
                        logger.warning("callback.non_retryable",
                                       callback_url=callback_url, status_code=resp.status_code,
                                       delivery_id=delivery_id)
                        return False

                    logger.warning("callback.retry",
                                   callback_url=callback_url, status_code=resp.status_code,
                                   attempt=attempt + 1, max_retries=_MAX_RETRIES,
                                   delivery_id=delivery_id)

                except Exception as exc:
                    if drawbridge is not None and isinstance(exc, drawbridge.DrawbridgeError):
                        logger.error("callback.ssrf_blocked",
                                     callback_url=callback_url, error=str(exc))
                        return False
                    logger.warning("callback.attempt_failed",
                                   callback_url=callback_url, attempt=attempt + 1,
                                   max_retries=_MAX_RETRIES, delivery_id=delivery_id,
                                   error=str(exc))

                if attempt < _MAX_RETRIES - 1:
                    backoff = _BACKOFF_BASE ** attempt
                    await asyncio.sleep(backoff)
    except Exception as exc:
        logger.error("callback.client_error", callback_url=callback_url, error=str(exc))
        return False

    logger.error("callback.exhausted",
                 callback_url=callback_url, max_retries=_MAX_RETRIES,
                 delivery_id=delivery_id)
    return False
