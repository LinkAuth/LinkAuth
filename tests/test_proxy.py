"""Tests for the generic HTTP proxy endpoint (POST /v1/proxy)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from conftest import build_test_app

# Ensure drawbridge fallback path is used in tests
import broker.api
broker.api.drawbridge = None


@pytest.fixture()
def app():
    return build_test_app(api_keys=["test-key"])


@pytest.fixture()
def client(app):
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


HEADERS = {"X-API-Key": "test-key"}


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_post_success(client: AsyncClient):
    """Proxy forwards a POST and returns upstream status + body."""
    upstream_resp = httpx.Response(
        status_code=200,
        json={"connect_uri": "https://example.com/connect", "ticket": "t1"},
    )

    with patch("broker.api.httpx.AsyncClient") as MockClient:
        mock_instance = AsyncMock()
        mock_instance.request = AsyncMock(return_value=upstream_resp)
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_instance

        resp = await client.post(
            "/v1/proxy",
            headers=HEADERS,
            json={
                "method": "POST",
                "url": "https://api.example.com/connect",
                "headers": {"Authorization": "Bearer ma-token"},
                "body": json.dumps({"connection": "google-oauth2"}),
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status_code"] == 200
    assert "connect_uri" in data["body"]


@pytest.mark.asyncio
async def test_proxy_get_success(client: AsyncClient):
    """Proxy forwards a GET request."""
    upstream_resp = httpx.Response(status_code=200, text="OK")

    with patch("broker.api.httpx.AsyncClient") as MockClient:
        mock_instance = AsyncMock()
        mock_instance.request = AsyncMock(return_value=upstream_resp)
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_instance

        resp = await client.post(
            "/v1/proxy",
            headers=HEADERS,
            json={"method": "GET", "url": "https://api.example.com/status"},
        )

    assert resp.status_code == 200
    assert resp.json()["status_code"] == 200


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_requires_api_key(client: AsyncClient):
    """Missing API key -> 401."""
    resp = await client.post(
        "/v1/proxy",
        json={"method": "GET", "url": "https://api.example.com"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_proxy_rejects_bad_api_key(client: AsyncClient):
    """Invalid API key -> 403."""
    resp = await client.post(
        "/v1/proxy",
        headers={"X-API-Key": "wrong-key"},
        json={"method": "GET", "url": "https://api.example.com"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Domain allowlist
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_allowlist_blocks_unlisted_domain():
    """Domain not on the allowlist -> 403."""
    app = build_test_app(
        api_keys=["k"],
        proxy_allowed_domains=["*.auth0.com"],
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post(
            "/v1/proxy",
            headers={"X-API-Key": "k"},
            json={"method": "GET", "url": "https://evil.com/steal"},
        )
    assert resp.status_code == 403
    assert "not on the proxy allowlist" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_proxy_allowlist_permits_matching_domain():
    """Domain matching a wildcard pattern is allowed."""
    app = build_test_app(
        api_keys=["k"],
        proxy_allowed_domains=["*.auth0.com"],
    )
    upstream_resp = httpx.Response(status_code=200, text="{}")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        with patch("broker.api.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=upstream_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            resp = await c.post(
                "/v1/proxy",
                headers={"X-API-Key": "k"},
                json={
                    "method": "POST",
                    "url": "https://dev-tenant.auth0.com/me/v1/connected-accounts/connect",
                },
            )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Proxy disabled
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_disabled():
    """When proxy.enabled=false, endpoint returns 403."""
    app = build_test_app(api_keys=["k"], proxy_enabled=False)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post(
            "/v1/proxy",
            headers={"X-API-Key": "k"},
            json={"method": "GET", "url": "https://example.com"},
        )
    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Error forwarding
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_forwards_upstream_errors(client: AsyncClient):
    """Non-2xx from upstream is forwarded, not turned into a broker error."""
    upstream_resp = httpx.Response(
        status_code=401,
        text='{"error": "invalid_token"}',
    )

    with patch("broker.api.httpx.AsyncClient") as MockClient:
        mock_instance = AsyncMock()
        mock_instance.request = AsyncMock(return_value=upstream_resp)
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_instance

        resp = await client.post(
            "/v1/proxy",
            headers=HEADERS,
            json={"method": "POST", "url": "https://api.example.com/token"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status_code"] == 401
    assert "invalid_token" in data["body"]


# ---------------------------------------------------------------------------
# Timeout handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_timeout(client: AsyncClient):
    """Upstream timeout -> 504 Gateway Timeout."""
    with patch("broker.api.httpx.AsyncClient") as MockClient:
        mock_instance = AsyncMock()
        mock_instance.request = AsyncMock(
            side_effect=httpx.ReadTimeout("timed out"),
        )
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_instance

        resp = await client.post(
            "/v1/proxy",
            headers=HEADERS,
            json={
                "method": "GET",
                "url": "https://slow.example.com",
                "timeout": 5,
            },
        )

    assert resp.status_code == 504


# ---------------------------------------------------------------------------
# Connection errors
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_connection_error(client: AsyncClient):
    """Upstream unreachable -> 502 Bad Gateway."""
    with patch("broker.api.httpx.AsyncClient") as MockClient:
        mock_instance = AsyncMock()
        mock_instance.request = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused"),
        )
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_instance

        resp = await client.post(
            "/v1/proxy",
            headers=HEADERS,
            json={"method": "GET", "url": "https://unreachable.example.com"},
        )

    assert resp.status_code == 502


# ---------------------------------------------------------------------------
# Invalid method
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_rejects_invalid_method(client: AsyncClient):
    """Invalid HTTP method -> 422 validation error."""
    resp = await client.post(
        "/v1/proxy",
        headers=HEADERS,
        json={"method": "HACK", "url": "https://example.com"},
    )
    assert resp.status_code == 422
