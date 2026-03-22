from __future__ import annotations

import asyncio
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import hmac

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from broker.callback import deliver_callback
from broker.dao.base import SessionDAO
from broker.models import Session, SessionStatus, TemplateType
from broker.oauth import (
    OAuthSession,
    build_authorization_url,
    encrypt_for_agent,
    exchange_token,
    generate_pkce,
    resolve_provider,
)
from broker.templates import resolve_template

router = APIRouter(prefix="/v1")

def _poll_interval(request: Request) -> int:
    """Get the configured polling interval (RFC 8628)."""
    return request.app.state.config.sessions.poll_interval


# ---------------------------------------------------------------------------
# RFC 9457 — Problem Details for HTTP APIs
# ---------------------------------------------------------------------------

def _session_not_found() -> JSONResponse:
    """Standard 404 for missing/expired/confirmed sessions. Intentionally vague."""
    return problem_response(404, "Session Not Found", "Session not found or expired.")


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
    oauth_extra_params: dict[str, str] | None = None
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
    connect_token: str


class ConfirmSessionResponse(BaseModel):
    connect_token: str  # one-time token to proceed with Step 2


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


def require_api_key(request: Request):
    """Validate X-API-Key header against configured API keys.

    If no API keys are configured, access is unrestricted (development mode).
    Uses constant-time comparison to prevent timing attacks.
    """
    config = request.app.state.config
    api_keys = config.security.api_keys

    # No keys configured → open access (development / single-tenant without auth)
    if not api_keys:
        return

    provided_key = request.headers.get("X-API-Key", "")
    if not provided_key:
        raise HTTPException(
            status_code=401,
            detail={
                "type": "about:blank",
                "title": "API Key Required",
                "status": 401,
                "detail": "Missing X-API-Key header. Provide a valid API key to access this endpoint.",
            },
        )

    # Constant-time comparison against all configured keys
    if not any(hmac.compare_digest(provided_key, key) for key in api_keys):
        raise HTTPException(
            status_code=403,
            detail={
                "type": "about:blank",
                "title": "Invalid API Key",
                "status": 403,
                "detail": "The provided API key is not valid.",
            },
        )


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

@router.post("/sessions", status_code=201, response_model=CreateSessionResponse, dependencies=[Depends(require_api_key)])
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
            oauth_extra_params=body.oauth_extra_params,
        )
    except ValueError as e:
        return problem_response(
            status=400,
            title="Invalid Template",
            detail=str(e),
        )

    # Validate OAuth provider if this is an OAuth template
    if tpl.template_type == TemplateType.OAUTH and tpl.oauth_provider:
        try:
            resolve_provider(tpl.oauth_provider, config.oauth_providers)
        except ValueError as e:
            detail = str(e)
            # Distinguish between "not registered" (400) and "no credentials" (503)
            if "not registered" in detail:
                return problem_response(400, "OAuth Provider Unknown", detail)
            elif "missing credentials" in detail:
                return problem_response(503, "OAuth Provider Not Configured", detail)
            else:
                return problem_response(400, "OAuth Provider Error", detail)

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


@router.get("/sessions/{session_id}", dependencies=[Depends(require_api_key)])
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
        return _session_not_found()
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
    """Frontend fetches session info to render the connect page.

    Only returns full session data (fields, public_key) for PENDING sessions.
    Once CONFIRMED, the session is locked to the browser that confirmed it
    (via connect_token). Other browsers only see that confirmation happened.
    """
    session = await dao.get_by_code(code)
    if not session:
        return _session_not_found()
    if session.status not in (SessionStatus.PENDING, SessionStatus.CONFIRMED):
        return problem_response(410, "Session Gone", "Session already completed.")

    # After confirmation, behave as if the session doesn't exist.
    # This prevents information leakage (attacker can't tell if a code is valid).
    if session.status == SessionStatus.CONFIRMED:
        return _session_not_found()

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
    )


@router.post("/connect/{code}/confirm", response_model=ConfirmSessionResponse)
async def confirm_code(
    code: str,
    dao: SessionDAO = Depends(get_session_dao),
):
    """User confirms they see the correct code. Issues a one-time connect_token.

    After confirmation, the code cannot be used again. All subsequent
    operations (OAuth redirect, form submit) require the connect_token.
    """
    session = await dao.get_by_code(code)
    if not session:
        return _session_not_found()
    if session.status != SessionStatus.PENDING:
        return problem_response(409, "Already Confirmed", "Session has already been confirmed.")

    # Issue a one-time connect_token — this replaces the code for Step 2
    connect_token = f"ct_{secrets.token_urlsafe(32)}"
    await dao.update_status(
        session.session_id, SessionStatus.CONFIRMED,
        connect_token=connect_token,
    )
    return ConfirmSessionResponse(connect_token=connect_token)


@router.post("/connect/{code}/complete", status_code=204)
async def complete_session(
    code: str,
    body: CompleteSessionRequest,
    background: BackgroundTasks,
    dao: SessionDAO = Depends(get_session_dao),
):
    """Frontend submits encrypted credentials. Requires connect_token."""
    session = await dao.get_by_code(code)
    if not session:
        return _session_not_found()
    if session.status != SessionStatus.CONFIRMED:
        return problem_response(409, "Session Not Completable", "Session is not in a completable state.")
    if body.connect_token != session.connect_token:
        return problem_response(
            403, "Invalid Connect Token",
            "Invalid connect_token. Re-confirm the session code.",
        )

    ok = await dao.store_ciphertext(session.session_id, body.ciphertext, body.algorithm)
    if not ok:
        return problem_response(500, "Storage Error", "Failed to store encrypted credentials.")

    if session.callback_url:
        background.add_task(
            deliver_callback, session.callback_url, session.session_id, body.ciphertext
        )


# ---------------------------------------------------------------------------
# OAuth endpoints
# ---------------------------------------------------------------------------

# In-memory PKCE state (maps state param -> OAuthSession)
# In production, this should be stored in the DAO layer.
_oauth_sessions: dict[str, OAuthSession] = {}


@router.get("/oauth/authorize/{code}")
async def oauth_authorize(
    code: str,
    connect_token: str | None = None,
    dao: SessionDAO = Depends(get_session_dao),
    config=Depends(get_config),
):
    """Redirect user to OAuth provider after code confirmation.

    Called by the frontend when user clicks "Connect with <Provider>".
    Requires connect_token issued during code confirmation.
    """
    session = await dao.get_by_code(code)
    if not session:
        return _session_not_found()
    if session.status != SessionStatus.CONFIRMED:
        return problem_response(
            409, "Code Not Confirmed",
            "Session code must be confirmed before starting OAuth flow.",
        )
    if not connect_token or connect_token != session.connect_token:
        return problem_response(
            403, "Invalid Connect Token",
            "Invalid or missing connect_token. Re-confirm the session code.",
        )
    if session.template.template_type != TemplateType.OAUTH or not session.template.oauth_provider:
        return problem_response(400, "Not an OAuth Session", "This session does not use OAuth.")

    try:
        provider = resolve_provider(session.template.oauth_provider, config.oauth_providers)
    except ValueError as e:
        return problem_response(503, "OAuth Provider Error", str(e))

    # Generate PKCE (RFC 7636) — fresh for every attempt
    code_verifier, code_challenge = generate_pkce()

    # Use session_id as state to map callback back to this session
    state = session.session_id
    _oauth_sessions[state] = OAuthSession(
        code_verifier=code_verifier,
        state=state,
    )

    redirect_uri = f"{config.server.base_url}/v1/oauth/callback"
    auth_url = build_authorization_url(
        provider=provider,
        redirect_uri=redirect_uri,
        scopes=session.template.oauth_scopes,
        state=state,
        code_challenge=code_challenge,
        extra_params=session.template.oauth_extra_params,
    )

    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/oauth/callback")
async def oauth_callback(
    state: str | None = None,
    code: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    background: BackgroundTasks = None,
    dao: SessionDAO = Depends(get_session_dao),
    config=Depends(get_config),
):
    """OAuth provider redirects back here after user authorization.

    Exchanges the authorization code for tokens, encrypts them with
    the agent's public key, and stores the ciphertext.
    """
    # Handle provider errors — reset session to PENDING so code must be re-confirmed
    if error:
        detail = error_description or error
        if state:
            _oauth_sessions.pop(state, None)
            session = await dao.get(state)
            if session:
                await dao.update_status(session.session_id, SessionStatus.PENDING)
        return problem_response(400, "OAuth Authorization Failed", f"Provider returned error: {detail}")

    if not state or not code:
        return problem_response(400, "Invalid Callback", "Missing state or code parameter.")

    # Look up PKCE session
    oauth_session = _oauth_sessions.pop(state, None)
    if not oauth_session:
        return problem_response(400, "Invalid State", "OAuth state parameter not recognized. Session may have expired.")

    # Look up LinkAuth session via state (= session_id)
    session = await dao.get(state)
    if not session:
        return problem_response(404, "Session Not Found", "LinkAuth session not found or expired.")

    if not session.template.oauth_provider:
        return problem_response(400, "Not an OAuth Session", "This session does not use OAuth.")

    try:
        provider = resolve_provider(session.template.oauth_provider, config.oauth_providers)
    except ValueError as e:
        return problem_response(503, "OAuth Provider Error", str(e))

    # Exchange code for tokens (RFC 6749 + RFC 7636 PKCE)
    redirect_uri = f"{config.server.base_url}/v1/oauth/callback"
    try:
        token = await exchange_token(
            provider=provider,
            redirect_uri=redirect_uri,
            authorization_code=code,
            code_verifier=oauth_session.code_verifier,
        )
    except ValueError as e:
        # Reset to PENDING — user must re-confirm code for next attempt
        await dao.update_status(session.session_id, SessionStatus.PENDING)
        return problem_response(502, "OAuth Token Exchange Failed", str(e))

    # Encrypt token with agent's public key (server-side encryption)
    # The broker briefly sees the tokens in plaintext — this is the documented
    # OAuth zero-knowledge caveat.
    try:
        ciphertext_b64 = encrypt_for_agent(token, session.public_key)
    except Exception as exc:
        return problem_response(
            500,
            "Encryption Failed",
            f"Failed to encrypt OAuth tokens with agent's public key: {exc}",
        )

    # Store encrypted tokens
    ok = await dao.store_ciphertext(
        session.session_id, ciphertext_b64, "RSA-OAEP-256+AES-256-GCM"
    )
    if not ok:
        return problem_response(500, "Storage Error", "Failed to store encrypted tokens.")

    # Trigger callback if configured
    if session.callback_url and background:
        background.add_task(
            deliver_callback, session.callback_url, session.session_id, ciphertext_b64
        )

    # Redirect user to a success page
    return RedirectResponse(
        url=f"{config.server.base_url}/connect/{session.code}?status=success",
        status_code=302,
    )
