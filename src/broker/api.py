from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from broker.callback import deliver_callback
from broker.dao.base import SessionDAO
from broker.models import Session, SessionStatus
from broker.templates import resolve_template

router = APIRouter(prefix="/v1")

def _poll_interval(request: Request) -> int:
    """Get the configured polling interval (RFC 8628)."""
    return request.app.state.config.sessions.poll_interval


# ---------------------------------------------------------------------------
# RFC 9457 — Problem Details for HTTP APIs
# ---------------------------------------------------------------------------

def problem_response(
    status: int,
    title: str,
    detail: str,
    error_type: str = "about:blank",
    extra: dict | None = None,
) -> JSONResponse:
    """Return an RFC 9457 application/problem+json error response."""
    body = {
        "type": error_type,
        "title": title,
        "status": status,
        "detail": detail,
    }
    if extra:
        body.update(extra)
    return JSONResponse(
        status_code=status,
        content=body,
        media_type="application/problem+json",
    )


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class FieldSchema(BaseModel):
    name: str
    label: str
    type: str = "text"
    required: bool = True
    options: list[str] | None = None


class CreateSessionRequest(BaseModel):
    public_key: str
    template: str | None = None
    display_name: str | None = None
    fields: list[FieldSchema] | None = None
    oauth_provider: str | None = None
    oauth_scopes: list[str] | None = None
    callback_url: str | None = None
    ttl: int | None = None


class CreateSessionResponse(BaseModel):
    session_id: str
    code: str
    url: str
    poll_token: str
    expires_at: str
    interval: int  # RFC 8628: recommended polling interval in seconds


class SessionStatusResponse(BaseModel):
    status: str
    expires_at: str
    interval: int | None = None  # RFC 8628: polling interval hint
    ciphertext: str | None = None
    algorithm: str | None = None


class CompleteSessionRequest(BaseModel):
    ciphertext: str
    algorithm: str = "RSA-OAEP-256+AES-256-GCM"


class ConfirmSessionRequest(BaseModel):
    code: str


class SecurityInfo(BaseModel):
    secure: bool
    mode: str  # "production", "development", "insecure"
    message: str | None = None


class SessionInfoResponse(BaseModel):
    status: str
    display_name: str
    template_type: str  # "form" or "oauth"
    code: str
    fields: list[dict[str, Any]]  # for form templates
    public_key: str
    security: SecurityInfo
    oauth_url: str | None = None  # for oauth templates: redirect URL


# ---------------------------------------------------------------------------
# Dependency injection helpers
# ---------------------------------------------------------------------------

def get_session_dao(request: Request) -> SessionDAO:
    return request.app.state.session_dao


def get_config(request: Request):
    return request.app.state.config


def _detect_security(request: Request) -> SecurityInfo:
    """Detect TLS/security status from the request and config."""
    config = request.app.state.config
    base_url: str = config.server.base_url

    # Check if connection is over TLS
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    scheme = forwarded_proto or request.url.scheme
    is_tls = scheme == "https" or base_url.startswith("https://")

    # Check if this is a localhost/dev environment
    host = request.url.hostname or ""
    is_localhost = host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")

    if is_tls:
        return SecurityInfo(secure=True, mode="production")
    elif is_localhost:
        return SecurityInfo(
            secure=False,
            mode="development",
            message="Development mode -- connection is not encrypted. Do not enter real credentials.",
        )
    else:
        return SecurityInfo(
            secure=False,
            mode="insecure",
            message="WARNING: Connection is not encrypted (no TLS). Do not enter real credentials. "
                    "Configure HTTPS or a reverse proxy before using in production.",
        )


# ---------------------------------------------------------------------------
# Agent-facing endpoints
# ---------------------------------------------------------------------------

@router.post("/sessions", status_code=201, response_model=CreateSessionResponse)
async def create_session(
    body: CreateSessionRequest,
    dao: SessionDAO = Depends(get_session_dao),
    config=Depends(get_config),
):
    """Agent creates a new credential session."""
    try:
        tpl = resolve_template(
            body.template,
            body.display_name,
            [f.model_dump() for f in body.fields] if body.fields else None,
            oauth_provider=body.oauth_provider,
            oauth_scopes=body.oauth_scopes,
        )
    except ValueError as e:
        return problem_response(
            status=400,
            title="Invalid Template",
            detail=str(e),
        )

    ttl = min(body.ttl or config.sessions.default_ttl, config.sessions.max_ttl)
    now = datetime.now(timezone.utc)

    code = Session.generate_code(config.sessions.code_length)
    session = Session(
        session_id=Session.hash_code(code),
        code=code,
        public_key=body.public_key,
        template=tpl,
        poll_token=Session.generate_poll_token(),
        callback_url=body.callback_url,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )
    await dao.create(session)

    url = f"{config.server.base_url}/connect/{code}"
    return CreateSessionResponse(
        session_id=session.session_id,
        code=code,
        url=url,
        poll_token=session.poll_token,
        expires_at=session.expires_at.isoformat(),
        interval=config.sessions.poll_interval,
    )


# Track last poll time per session for RFC 8628 slow_down
_last_poll: dict[str, float] = {}


@router.get("/sessions/{session_id}")
async def get_session(
    session_id: str,
    request: Request,
    dao: SessionDAO = Depends(get_session_dao),
):
    """Agent polls session status. Requires poll_token as Bearer token.

    Implements RFC 8628 polling semantics:
    - Returns `interval` hint for recommended polling frequency
    - Returns 429 with `slow_down` error if client polls too fast
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return problem_response(
            status=401,
            title="Unauthorized",
            detail="Missing or invalid Authorization header. Use: Bearer <poll_token>",
        )
    poll_token = auth.removeprefix("Bearer ").strip()

    session = await dao.get(session_id)
    if not session:
        return problem_response(
            status=404,
            title="Session Not Found",
            detail="Session not found or expired.",
        )
    if session.poll_token != poll_token:
        return problem_response(
            status=403,
            title="Forbidden",
            detail="Invalid poll_token.",
        )

    # RFC 8628 §3.5: slow_down — if client polls faster than interval
    poll_interval = _poll_interval(request)
    now = time.monotonic()
    last = _last_poll.get(session_id, 0.0)
    if now - last < poll_interval:
        return problem_response(
            status=429,
            title="Slow Down",
            detail="Polling too frequently. Increase your polling interval.",
            error_type="urn:ietf:params:oauth:error:slow_down",
            extra={"interval": poll_interval + 5},
        )
    _last_poll[session_id] = now

    # If ready, consume (one-time retrieval)
    if session.status == SessionStatus.READY:
        consumed = await dao.consume(session_id)
        if consumed:
            # Clean up tracking
            _last_poll.pop(session_id, None)
            return SessionStatusResponse(
                status="ready",
                expires_at=consumed.expires_at.isoformat(),
                ciphertext=consumed.ciphertext,
                algorithm=consumed.algorithm,
            )

    return SessionStatusResponse(
        status=session.status.value,
        expires_at=session.expires_at.isoformat(),
        interval=poll_interval,
    )


# ---------------------------------------------------------------------------
# Frontend-facing endpoints
# ---------------------------------------------------------------------------

@router.get("/connect/{code}", response_model=SessionInfoResponse)
async def get_session_info(
    code: str,
    request: Request,
    dao: SessionDAO = Depends(get_session_dao),
):
    """Frontend fetches session info to render the connect page."""
    session = await dao.get_by_code(code)
    if not session:
        return problem_response(404, "Session Not Found", "Session not found or expired.")
    if session.status not in (SessionStatus.PENDING, SessionStatus.CONFIRMED):
        return problem_response(410, "Session Gone", "Session already completed.")

    return SessionInfoResponse(
        status=session.status.value,
        display_name=session.template.display_name,
        template_type=session.template.template_type.value,
        code=session.code,
        fields=[
            {"name": f.name, "label": f.label, "type": f.type,
             "required": f.required, "options": f.options}
            for f in session.template.fields
        ],
        public_key=session.public_key,
        security=_detect_security(request),
        # OAuth URL will be populated when OAuth flow is implemented
    )


@router.post("/connect/{code}/confirm", status_code=204)
async def confirm_code(
    code: str,
    dao: SessionDAO = Depends(get_session_dao),
):
    """User confirms they see the correct code. Transitions to CONFIRMED."""
    session = await dao.get_by_code(code)
    if not session:
        return problem_response(404, "Session Not Found", "Session not found or expired.")
    if session.status != SessionStatus.PENDING:
        return problem_response(409, "Already Confirmed", "Session has already been confirmed.")

    await dao.update_status(session.session_id, SessionStatus.CONFIRMED)


@router.post("/connect/{code}/complete", status_code=204)
async def complete_session(
    code: str,
    body: CompleteSessionRequest,
    background: BackgroundTasks,
    dao: SessionDAO = Depends(get_session_dao),
):
    """Frontend submits encrypted credentials."""
    session = await dao.get_by_code(code)
    if not session:
        return problem_response(404, "Session Not Found", "Session not found or expired.")
    if session.status not in (SessionStatus.PENDING, SessionStatus.CONFIRMED):
        return problem_response(409, "Session Not Completable", "Session is not in a completable state.")

    ok = await dao.store_ciphertext(session.session_id, body.ciphertext, body.algorithm)
    if not ok:
        return problem_response(500, "Storage Error", "Failed to store encrypted credentials.")

    if session.callback_url:
        background.add_task(
            deliver_callback, session.callback_url, session.session_id, body.ciphertext
        )
