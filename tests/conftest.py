"""Shared fixtures for LinkAuth broker tests."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

from broker.config import AppConfig, ProxyConfig, SecurityConfig, SessionsConfig
from broker.dao.base import SessionDAO
from broker.models import Session, SessionStatus


class InMemorySessionDAO(SessionDAO):
    """Minimal in-memory DAO for unit tests."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    async def init(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def create(self, session: Session) -> None:
        self._sessions[session.session_id] = session

    async def get(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    async def get_by_code(self, code: str) -> Session | None:
        hashed = Session.hash_code(code)
        return self._sessions.get(hashed)

    async def update_status(
        self, session_id: str, status: SessionStatus,
        connect_token: str | None = None,
    ) -> bool:
        s = self._sessions.get(session_id)
        if not s:
            return False
        s.status = status
        if connect_token is not None:
            s.connect_token = connect_token
        return True

    async def store_ciphertext(
        self, session_id: str, ciphertext: str, algorithm: str,
    ) -> bool:
        s = self._sessions.get(session_id)
        if not s or s.status not in (SessionStatus.PENDING, SessionStatus.CONFIRMED, SessionStatus.READY):
            return False
        s.ciphertext = ciphertext
        s.algorithm = algorithm
        s.status = SessionStatus.READY
        return True

    async def consume(self, session_id: str) -> Session | None:
        s = self._sessions.get(session_id)
        if not s or s.status != SessionStatus.READY:
            return None
        s.status = SessionStatus.CONSUMED
        return s

    async def delete(self, session_id: str) -> bool:
        return self._sessions.pop(session_id, None) is not None

    async def cleanup_expired(self) -> int:
        return 0

    async def store_oauth_state(self, session_id: str, code_verifier: str) -> bool:
        s = self._sessions.get(session_id)
        if not s:
            return False
        s.oauth_code_verifier = code_verifier
        return True

    async def clear_oauth_state(self, session_id: str) -> bool:
        s = self._sessions.get(session_id)
        if not s:
            return False
        s.oauth_code_verifier = None
        return True

    async def get_by_custom_state(self, custom_state: str) -> Session | None:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        candidates = [
            s for s in self._sessions.values()
            if s.custom_state == custom_state
            and s.custom_authorize_url is not None
            and s.oauth_code_verifier is not None
            and s.expires_at > now
        ]
        if not candidates:
            return None
        return sorted(candidates, key=lambda s: s.created_at, reverse=True)[0]


def build_test_app(
    *,
    api_keys: list[str] | None = None,
    proxy_enabled: bool = True,
    proxy_allowed_domains: list[str] | None = None,
    sessions_config: SessionsConfig | None = None,
) -> FastAPI:
    """Create a FastAPI app wired for testing."""
    from broker.api import router

    app = FastAPI()
    app.include_router(router)

    config = AppConfig(
        security=SecurityConfig(api_keys=api_keys or []),
        proxy=ProxyConfig(
            enabled=proxy_enabled,
            allowed_domains=proxy_allowed_domains or [],
        ),
        sessions=sessions_config or SessionsConfig(),
    )
    app.state.config = config
    app.state.session_dao = InMemorySessionDAO()
    return app


@pytest.fixture()
def app() -> FastAPI:
    return build_test_app()


@pytest.fixture()
def secured_app() -> FastAPI:
    return build_test_app(api_keys=["test-key-123"])
