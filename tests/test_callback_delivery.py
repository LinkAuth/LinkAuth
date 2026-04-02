"""Tests for callback delivery (`broker.callback.deliver_callback`)."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from unittest.mock import AsyncMock, patch

import httpx
import pytest

import broker.callback as callback_mod
from broker.callback import deliver_callback


@pytest.fixture(autouse=True)
def no_drawbridge() -> None:
    """Force httpx path (no drawbridge SSRF client)."""
    saved = callback_mod.drawbridge
    callback_mod.drawbridge = None
    yield
    callback_mod.drawbridge = saved


def _httpx_client_mock(
    *,
    post_return: httpx.Response | None = None,
    post_side_effect: list[httpx.Response] | None = None,
) -> AsyncMock:
    """Build mock AsyncClient usable as async context manager."""
    instance = AsyncMock()
    if post_side_effect is not None:
        instance.post = AsyncMock(side_effect=post_side_effect)
    else:
        instance.post = AsyncMock(return_value=post_return)
    instance.__aenter__ = AsyncMock(return_value=instance)
    instance.__aexit__ = AsyncMock(return_value=None)
    return instance


@pytest.mark.asyncio
async def test_callback_success() -> None:
    mock_instance = _httpx_client_mock(post_return=httpx.Response(200))
    with (
        patch("broker.callback.httpx.AsyncClient", return_value=mock_instance),
        patch("broker.callback.asyncio.sleep", new_callable=AsyncMock),
    ):
        ok = await deliver_callback(
            "https://agent.example/hook",
            session_id="sess-1",
            ciphertext="ct",
        )
    assert ok is True
    mock_instance.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_callback_hmac_signature() -> None:
    secret = "shared-secret"
    session_id = "sid-hmac"
    ciphertext = "enc-payload"
    algorithm = "aes-256-gcm"
    mock_instance = _httpx_client_mock(post_return=httpx.Response(200))

    with (
        patch("broker.callback.httpx.AsyncClient", return_value=mock_instance),
        patch("broker.callback.asyncio.sleep", new_callable=AsyncMock),
    ):
        await deliver_callback(
            "https://cb.example/x",
            session_id=session_id,
            ciphertext=ciphertext,
            algorithm=algorithm,
            callback_secret=secret,
        )

    mock_instance.post.assert_awaited_once()
    _url, kwargs = mock_instance.post.call_args
    body = kwargs["content"]
    headers = kwargs["headers"]
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert headers["X-LinkAuth-Signature"] == f"sha256={expected}"


@pytest.mark.asyncio
async def test_callback_delivery_id() -> None:
    mock_instance = _httpx_client_mock(post_return=httpx.Response(204))

    with (
        patch("broker.callback.httpx.AsyncClient", return_value=mock_instance),
        patch("broker.callback.asyncio.sleep", new_callable=AsyncMock),
    ):
        await deliver_callback(
            "https://cb.example/y",
            session_id="s",
            ciphertext="c",
        )

    _url, kwargs = mock_instance.post.call_args
    delivery_id = kwargs["headers"]["X-LinkAuth-Delivery-Id"]
    parsed = uuid.UUID(delivery_id)
    assert str(parsed) == delivery_id


@pytest.mark.asyncio
async def test_callback_retry_on_5xx() -> None:
    responses = [
        httpx.Response(500),
        httpx.Response(500),
        httpx.Response(200),
    ]
    mock_instance = _httpx_client_mock(post_side_effect=responses)
    mock_sleep = AsyncMock()

    with (
        patch("broker.callback.httpx.AsyncClient", return_value=mock_instance),
        patch("broker.callback.asyncio.sleep", mock_sleep),
    ):
        ok = await deliver_callback(
            "https://cb.example/retry",
            session_id="s",
            ciphertext="c",
        )

    assert ok is True
    assert mock_instance.post.await_count == 3
    mock_sleep.assert_awaited()
    assert [c.args[0] for c in mock_sleep.await_args_list] == [1, 4]


@pytest.mark.asyncio
async def test_callback_no_retry_on_4xx() -> None:
    mock_instance = _httpx_client_mock(post_return=httpx.Response(400))
    mock_sleep = AsyncMock()

    with (
        patch("broker.callback.httpx.AsyncClient", return_value=mock_instance),
        patch("broker.callback.asyncio.sleep", mock_sleep),
    ):
        ok = await deliver_callback(
            "https://cb.example/4xx",
            session_id="s",
            ciphertext="c",
        )

    assert ok is False
    mock_instance.post.assert_awaited_once()
    mock_sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_callback_payload_includes_algorithm() -> None:
    algo = "chacha20-poly1305"
    mock_instance = _httpx_client_mock(post_return=httpx.Response(200))

    with (
        patch("broker.callback.httpx.AsyncClient", return_value=mock_instance),
        patch("broker.callback.asyncio.sleep", new_callable=AsyncMock),
    ):
        await deliver_callback(
            "https://cb.example/z",
            session_id="sess-algo",
            ciphertext="blob",
            algorithm=algo,
        )

    _url, kwargs = mock_instance.post.call_args
    payload = json.loads(kwargs["content"].decode())
    assert payload["algorithm"] == algo
    assert payload["session_id"] == "sess-algo"
    assert payload["status"] == "ready"
    assert payload["ciphertext"] == "blob"


@pytest.mark.asyncio
async def test_callback_no_signature_without_secret() -> None:
    mock_instance = _httpx_client_mock(post_return=httpx.Response(200))

    with (
        patch("broker.callback.httpx.AsyncClient", return_value=mock_instance),
        patch("broker.callback.asyncio.sleep", new_callable=AsyncMock),
    ):
        await deliver_callback(
            "https://cb.example/nosig",
            session_id="s",
            ciphertext="c",
            callback_secret=None,
        )

    _url, kwargs = mock_instance.post.call_args
    assert "X-LinkAuth-Signature" not in kwargs["headers"]
