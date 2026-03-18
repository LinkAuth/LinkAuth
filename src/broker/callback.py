from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


async def deliver_callback(
    callback_url: str,
    session_id: str,
    ciphertext: str,
) -> bool:
    """POST encrypted credentials to the agent's callback URL.

    Returns True if delivery succeeded (2xx), False otherwise.
    """
    payload = {
        "session_id": session_id,
        "status": "ready",
        "ciphertext": ciphertext,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(callback_url, json=payload)
            if resp.is_success:
                logger.info("Callback delivered to %s", callback_url)
                return True
            logger.warning(
                "Callback to %s returned %d", callback_url, resp.status_code
            )
            return False
    except httpx.HTTPError as exc:
        logger.error("Callback to %s failed: %s", callback_url, exc)
        return False
