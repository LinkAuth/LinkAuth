"""Tests for POST /v1/sessions/{session_id}/webhook (webhook relay)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from broker.config import SessionsConfig
from broker.models import CredentialTemplate, Session, SessionStatus
from conftest import build_test_app

WEBHOOK_TOKEN = "wt_test_token"
WRONG_TOKEN = "wt_wrong_token"


def _webhook_session(
    *,
    session_id: str = "test-session-id",
    webhook_token: str | None = WEBHOOK_TOKEN,
    status: SessionStatus = SessionStatus.CONFIRMED,
) -> Session:
    now = datetime.now(timezone.utc)
    return Session(
        session_id=session_id,
        code="ABCD-1234",
        public_key="fake-key",
        template=CredentialTemplate(template_id="test", display_name="Test"),
        status=status,
        poll_token="pt_test",
        webhook_token=webhook_token,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )


@pytest.mark.asyncio
async def test_webhook_happy_path():
    app = build_test_app()
    dao = app.state.session_dao
    session = _webhook_session()
    await dao.create(session)

    transport = ASGITransport(app=app)
    with patch("broker.api.encrypt_for_agent", return_value="encrypted_data") as enc:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/v1/sessions/{session.session_id}/webhook",
                params={"token": WEBHOOK_TOKEN},
                content=b'{"event":"ping"}',
            )

    assert resp.status_code == 200
    assert resp.json() == {
        "status": "accepted",
        "session_id": session.session_id,
    }
    enc.assert_called_once()
    stored = await dao.get(session.session_id)
    assert stored is not None
    assert stored.ciphertext == "encrypted_data"
    assert stored.status == SessionStatus.READY


@pytest.mark.asyncio
async def test_webhook_missing_token():
    app = build_test_app()
    dao = app.state.session_dao
    await dao.create(_webhook_session())

    transport = ASGITransport(app=app)
    with patch("broker.api.encrypt_for_agent", return_value="encrypted_data"):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/sessions/test-session-id/webhook",
                content=b"{}",
            )

    assert resp.status_code == 403
    body = resp.json()
    assert body["title"] == "Invalid Webhook Token"


@pytest.mark.asyncio
async def test_webhook_wrong_token():
    app = build_test_app()
    dao = app.state.session_dao
    await dao.create(_webhook_session())

    transport = ASGITransport(app=app)
    with patch("broker.api.encrypt_for_agent", return_value="encrypted_data"):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/sessions/test-session-id/webhook",
                params={"token": WRONG_TOKEN},
                content=b"{}",
            )

    assert resp.status_code == 403
    assert resp.json()["title"] == "Invalid Webhook Token"


@pytest.mark.asyncio
async def test_webhook_not_enabled():
    app = build_test_app()
    dao = app.state.session_dao
    await dao.create(_webhook_session(webhook_token=None))

    transport = ASGITransport(app=app)
    with patch("broker.api.encrypt_for_agent", return_value="encrypted_data"):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/sessions/test-session-id/webhook",
                params={"token": "any-token"},
                content=b"{}",
            )

    assert resp.status_code == 403
    assert resp.json()["title"] == "Webhook Not Enabled"


@pytest.mark.asyncio
async def test_webhook_expired_session():
    """Unknown session_id yields 404 (same response shape as expired for clients)."""
    app = build_test_app()
    transport = ASGITransport(app=app)

    with patch("broker.api.encrypt_for_agent", return_value="encrypted_data"):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/sessions/nonexistent-session/webhook",
                params={"token": WEBHOOK_TOKEN},
                content=b"{}",
            )

    assert resp.status_code == 404
    assert resp.json()["title"] == "Session Not Found"


@pytest.mark.asyncio
async def test_webhook_payload_too_large():
    app = build_test_app(sessions_config=SessionsConfig(max_webhook_payload=10))
    dao = app.state.session_dao
    await dao.create(_webhook_session())

    transport = ASGITransport(app=app)
    with patch("broker.api.encrypt_for_agent", return_value="encrypted_data"):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/sessions/test-session-id/webhook",
                params={"token": WEBHOOK_TOKEN},
                content=b"x" * 11,
            )

    assert resp.status_code == 413
    assert resp.json()["title"] == "Payload Too Large"


@pytest.mark.asyncio
async def test_webhook_overwrites_ciphertext():
    app = build_test_app()
    dao = app.state.session_dao
    await dao.create(_webhook_session())

    transport = ASGITransport(app=app)
    with patch("broker.api.encrypt_for_agent", side_effect=["first_cipher", "second_cipher"]) as enc:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r1 = await client.post(
                "/v1/sessions/test-session-id/webhook",
                params={"token": WEBHOOK_TOKEN},
                content=b"one",
            )
            r2 = await client.post(
                "/v1/sessions/test-session-id/webhook",
                params={"token": WEBHOOK_TOKEN},
                content=b"two",
            )

    assert r1.status_code == 200
    assert r1.json()["status"] == "accepted"
    assert r2.status_code == 200
    assert r2.json()["status"] == "accepted"
    assert enc.call_count == 2
    stored = await dao.get("test-session-id")
    assert stored is not None
    assert stored.ciphertext == "second_cipher"
    assert stored.status == SessionStatus.READY
