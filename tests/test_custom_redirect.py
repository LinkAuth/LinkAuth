"""Tests for the custom redirect (passthrough) flow in oauth_authorize + oauth_callback."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from broker.models import (
    CredentialTemplate,
    Session,
    SessionStatus,
    TemplateType,
)
from conftest import InMemorySessionDAO, build_test_app


def _make_session(
    *,
    custom_authorize_url: str | None = None,
    custom_callback_params: list[str] | None = None,
    custom_state: str | None = None,
) -> Session:
    code = "TEST-1234"
    return Session(
        session_id=Session.hash_code(code),
        code=code,
        public_key=_TEST_PUBLIC_KEY_B64,
        template=CredentialTemplate(
            template_id="oauth_custom",
            display_name="Test OAuth",
            template_type=TemplateType.OAUTH,
            oauth_provider="google",
        ),
        status=SessionStatus.CONFIRMED,
        poll_token="pt_test",
        connect_token="ct_test",
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        custom_authorize_url=custom_authorize_url,
        custom_callback_params=custom_callback_params,
        custom_state=custom_state,
    )


# Minimal RSA key for encryption tests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

_TEST_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_TEST_PUBLIC_KEY_B64 = base64.b64encode(
    _TEST_PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
).decode()


@pytest.fixture()
def app():
    return build_test_app(api_keys=["k"])


@pytest.fixture()
def client(app):
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_oauth_authorize_passthrough_redirect(app, client: AsyncClient):
    """When session has custom_authorize_url, oauth_authorize redirects there."""
    session = _make_session(
        custom_authorize_url="https://auth0.example.com/connect?ticket=abc",
        custom_callback_params=["connect_code"],
        custom_state="xyz",
    )
    dao: InMemorySessionDAO = app.state.session_dao
    await dao.create(session)

    resp = await client.get(
        f"/v1/oauth/authorize/{session.code}",
        params={"connect_token": "ct_test"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://auth0.example.com/connect?ticket=abc"


@pytest.mark.asyncio
async def test_oauth_callback_passthrough_captures_params(app, client: AsyncClient):
    """Passthrough callback extracts custom_callback_params, encrypts, stores."""
    session = _make_session(
        custom_authorize_url="https://auth0.example.com/connect",
        custom_callback_params=["connect_code"],
        custom_state="my-external-state",
    )
    dao: InMemorySessionDAO = app.state.session_dao
    await dao.create(session)

    # Simulate what oauth_authorize does: store OAuth state in DB
    await dao.store_oauth_state(session.session_id, "")

    resp = await client.get(
        "/v1/oauth/callback",
        params={
            "state": session.session_id,
            "connect_code": "cc-test-123",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "status=success" in resp.headers["location"]

    # Verify ciphertext was stored
    stored = await dao.get(session.session_id)
    assert stored is not None
    assert stored.status == SessionStatus.READY
    assert stored.ciphertext is not None


@pytest.mark.asyncio
async def test_oauth_callback_passthrough_by_custom_state(app, client: AsyncClient):
    """Callback with external state (not session_id) is matched via custom_state."""
    session = _make_session(
        custom_authorize_url="https://auth0.example.com/connect",
        custom_callback_params=["connect_code"],
        custom_state="external-csrf-token",
    )
    dao: InMemorySessionDAO = app.state.session_dao
    await dao.create(session)

    # Simulate oauth_authorize storing state in DB
    await dao.store_oauth_state(session.session_id, "")

    # Callback comes with the EXTERNAL state, not the session_id
    resp = await client.get(
        "/v1/oauth/callback",
        params={
            "state": "external-csrf-token",
            "connect_code": "cc-456",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "status=success" in resp.headers["location"]

    stored = await dao.get(session.session_id)
    assert stored.status == SessionStatus.READY
