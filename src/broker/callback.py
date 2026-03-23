from __future__ import annotations

import httpx
import structlog

logger = structlog.get_logger(__name__)


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
                logger.info("callback.delivered",
                            session_id=session_id, callback_url=callback_url)
                return True
            logger.warning("callback.failed",
                           session_id=session_id, callback_url=callback_url,
                           status_code=resp.status_code)
            return False
    except httpx.HTTPError as exc:
        logger.error("callback.error",
                      session_id=session_id, callback_url=callback_url,
                      error=str(exc))
        return False
