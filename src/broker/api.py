from __future__ import annotations

import fnmatch
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import hmac
import httpx
import structlog

try:
    import drawbridge
except ImportError:
    drawbridge = None  # type: ignore[assignment]

logger = structlog.get_logger("linkauth.api")

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from broker.callback import deliver_callback
from broker.dao.base import SessionDAO
from broker.models import Session, SessionStatus, TemplateType
from broker.crypto import validate_public_key
from broker.oauth import (
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


def _oauth_failed() -> JSONResponse:
    """Standard 400 for OAuth errors. Intentionally vague to prevent information leakage."""
    return problem_response(400, "OAuth Authorization Failed", "Authorization was not completed.")


def problem_response(
    status: int,
    title: str,
    detail: str,
    error_type: str = "about:blank",
    extra: dict | None = None,
) -> JSONResponse:
    """Return an RFC 9457 application/problem+json error response."""
    logger.warning("problem", status_code=status, title=title, detail=detail)
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
    custom_authorize_url: str | None = None
    custom_callback_params: list[str] | None = None
    custom_state: str | None = None
    enable_webhook: bool = False


class CreateSessionResponse(BaseModel):
    session_id: str
    code: str
    url: str
    poll_token: str
    expires_at: str
    interval: int  # RFC 8628: recommended polling interval in seconds
    callback_secret: str | None = None
    webhook_url: str | None = None


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


class ProxyRequest(BaseModel):
    method: str = Field(..., pattern="^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$")
    url: str
    headers: dict[str, str] | None = None
    body: str | None = None
    timeout: int = Field(default=30, ge=1, le=120)


class ProxyResponse(BaseModel):
    status_code: int
    headers: dict[str, str]
    body: str


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
        logger.warning("auth.api_key.missing")
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
        logger.warning("auth.api_key.invalid")
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
    key_error = validate_public_key(body.public_key)
    if key_error:
        return problem_response(
            status=400,
            title="Invalid Public Key",
            detail=key_error,
        )

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

    # Validate callback_url scheme — HTTPS required except on localhost
    if body.callback_url:
        parsed_cb = urlparse(body.callback_url)
        cb_host = parsed_cb.hostname or ""
        is_local = cb_host in ("localhost", "127.0.0.1", "::1")
        if parsed_cb.scheme != "https" and not is_local:
            return problem_response(
                400, "Invalid Callback URL",
                "callback_url must use HTTPS in production. "
                "HTTP is only allowed for localhost.",
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
        custom_authorize_url=body.custom_authorize_url,
        custom_callback_params=body.custom_callback_params,
        custom_state=body.custom_state,
    )

    if body.callback_url:
        session.callback_secret = Session.generate_callback_secret()
    if body.enable_webhook:
        session.webhook_token = Session.generate_webhook_token()

    await dao.create(session)

    url = f"{config.server.base_url}/connect/{code}"

    structlog.contextvars.bind_contextvars(
        session_id=session.session_id,
        code=code,
        template_id=tpl.template_id,
        template_type=tpl.template_type.value,
        ttl=ttl,
        has_callback=bool(body.callback_url),
        oauth_provider=tpl.oauth_provider,
    )
    logger.info("session.created")

    return CreateSessionResponse(
        session_id=session.session_id,
        code=code,
        url=url,
        poll_token=session.poll_token,
        expires_at=session.expires_at.isoformat(),
        interval=config.sessions.poll_interval,
        callback_secret=session.callback_secret,
        webhook_url=(
            f"{config.server.base_url}/v1/sessions/{session.session_id}/webhook?token={session.webhook_token}"
            if session.webhook_token else None
        ),
    )


# Track last poll time per session for RFC 8628 slow_down
_last_poll: dict[str, float] = {}

# Rate limiting for connect/confirm endpoints (keyed by IP + code)
_connect_attempts: dict[str, list[float]] = {}

def _check_connect_rate_limit(request: Request, code: str) -> JSONResponse | None:
    """Enforce rate limiting on connect and confirm endpoints.

    Limits to 10 requests per minute per source IP per code.
    Returns a 429 problem response if exceeded, None otherwise.
    """
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    key = f"{client_ip}:{code}"
    now = time.monotonic()
    window = 60.0  # 1 minute

    attempts = _connect_attempts.get(key, [])
    # Prune old entries outside the window
    attempts = [t for t in attempts if now - t < window]
    attempts.append(now)
    _connect_attempts[key] = attempts

    if len(attempts) > 10:
        logger.warning("connect.rate_limited", client_ip=client_ip, code=code)
        return problem_response(
            429, "Too Many Requests",
            "Rate limit exceeded. Try again later.",
        )
    return None


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
    structlog.contextvars.bind_contextvars(session_id=session_id)

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={
                "type": "about:blank",
                "title": "Unauthorized",
                "status": 401,
                "detail": "Missing or invalid Authorization header. Use: Bearer <poll_token>",
            },
            headers={"WWW-Authenticate": "Bearer"},
            media_type="application/problem+json",
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

    structlog.contextvars.bind_contextvars(
        session_status=session.status.value,
        code=session.code,
    )

    # RFC 8628 §3.5: slow_down — if client polls faster than interval
    poll_interval = _poll_interval(request)
    now = time.monotonic()
    last = _last_poll.get(session_id, 0.0)
    if now - last < poll_interval:
        logger.warning("session.poll.slow_down", interval=poll_interval + 5)
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
            _last_poll.pop(session_id, None)
            logger.info("session.consumed")
            return SessionStatusResponse(
                status="ready",
                expires_at=consumed.expires_at.isoformat(),
                ciphertext=consumed.ciphertext,
                algorithm=consumed.algorithm,
            )

    logger.debug("session.polled")

    return SessionStatusResponse(
        status=session.status.value,
        expires_at=session.expires_at.isoformat(),
        interval=poll_interval,
    )


# ---------------------------------------------------------------------------
# Generic HTTP proxy
# ---------------------------------------------------------------------------

def _is_domain_allowed(url: str, allowed_domains: list[str]) -> bool:
    """Check whether *url*'s hostname matches the allowlist.

    An empty allowlist means "allow everything".  Patterns may use
    leading ``*.`` wildcards (e.g. ``*.auth0.com``).
    """
    if not allowed_domains:
        return True
    hostname = urlparse(url).hostname or ""
    return any(fnmatch.fnmatch(hostname, pat) for pat in allowed_domains)


@router.post(
    "/proxy",
    response_model=ProxyResponse,
    dependencies=[Depends(require_api_key)],
)
async def http_proxy(
    body: ProxyRequest,
    config=Depends(get_config),
):
    """Forward an HTTP request on behalf of a sandboxed agent.

    The broker acts as a transparent forward proxy.  The agent
    authenticates with its API key; the broker makes the outbound call
    and returns the raw response.
    """
    proxy_cfg = config.proxy
    if not proxy_cfg.enabled:
        return problem_response(
            403, "Proxy Disabled",
            "The HTTP proxy endpoint is disabled on this broker.",
        )

    if not _is_domain_allowed(body.url, proxy_cfg.allowed_domains):
        return problem_response(
            403, "Domain Not Allowed",
            "The target domain is not on the proxy allowlist.",
        )

    timeout = min(body.timeout, proxy_cfg.max_timeout)

    req_headers = dict(body.headers) if body.headers else {}
    content = body.body.encode("utf-8") if body.body else None

    try:
        if drawbridge is not None:
            policy = drawbridge.Policy(
                allow_private=proxy_cfg.allow_private_ips,
                max_redirects=0,
                timeout=timeout,
            )
            async with drawbridge.Client(policy) as client:
                resp = await client.request(
                    method=body.method,
                    url=body.url,
                    headers=req_headers,
                    content=content,
                )
        else:
            async with httpx.AsyncClient() as client:
                resp = await client.request(
                    method=body.method,
                    url=body.url,
                    headers=req_headers,
                    content=content,
                    timeout=timeout,
                )
    except Exception as exc:
        if drawbridge is not None and isinstance(exc, drawbridge.DrawbridgeError):
            return problem_response(
                403, "SSRF Blocked",
                "Request blocked: target resolves to a private/reserved IP.",
            )
        if isinstance(exc, httpx.TimeoutException):
            return problem_response(
                504, "Gateway Timeout",
                f"The upstream server did not respond within {timeout}s.",
            )
        if isinstance(exc, httpx.RequestError):
            return problem_response(
                502, "Bad Gateway",
                f"Failed to reach upstream: {exc}",
            )
        raise

    resp_headers = {k: v for k, v in resp.headers.items()}

    return ProxyResponse(
        status_code=resp.status_code,
        headers=resp_headers,
        body=resp.text,
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
    Once CONFIRMED, the session is locked to the connect_token bearer.
    """
    structlog.contextvars.bind_contextvars(code=code)

    rate_limit = _check_connect_rate_limit(request, code)
    if rate_limit:
        return rate_limit

    session = await dao.get_by_code(code)
    if not session:
        logger.warning("connect.not_found")
        return _session_not_found()
    if session.status not in (SessionStatus.PENDING, SessionStatus.CONFIRMED):
        return problem_response(410, "Session Gone", "Session already completed.")

    if session.status == SessionStatus.CONFIRMED:
        logger.warning("connect.not_found", reason="already_confirmed")
        return _session_not_found()

    structlog.contextvars.bind_contextvars(
        session_id=session.session_id,
        template_type=session.template.template_type.value,
        display_name=session.template.display_name,
    )
    logger.info("connect.info")

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
    request: Request,
    dao: SessionDAO = Depends(get_session_dao),
):
    """User confirms they see the correct code. Issues a one-time connect_token.

    After confirmation, the code cannot be used again. All subsequent
    operations (OAuth redirect, form submit) require the connect_token.
    """
    structlog.contextvars.bind_contextvars(code=code)

    rate_limit = _check_connect_rate_limit(request, code)
    if rate_limit:
        return rate_limit

    session = await dao.get_by_code(code)
    if not session:
        return _session_not_found()
    if session.status != SessionStatus.PENDING:
        return problem_response(409, "Already Confirmed", "Session has already been confirmed.")

    connect_token = f"ct_{secrets.token_urlsafe(32)}"
    await dao.update_status(
        session.session_id, SessionStatus.CONFIRMED,
        connect_token=connect_token,
    )

    structlog.contextvars.bind_contextvars(session_id=session.session_id)
    logger.info("connect.confirmed")

    return ConfirmSessionResponse(connect_token=connect_token)


@router.post("/connect/{code}/complete", status_code=204)
async def complete_session(
    code: str,
    body: CompleteSessionRequest,
    background: BackgroundTasks,
    dao: SessionDAO = Depends(get_session_dao),
):
    """Frontend submits encrypted credentials. Requires connect_token."""
    structlog.contextvars.bind_contextvars(code=code)

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

    structlog.contextvars.bind_contextvars(
        session_id=session.session_id,
        algorithm=body.algorithm,
        has_callback=bool(session.callback_url),
    )
    logger.info("connect.completed")

    if session.callback_url:
        background.add_task(
            deliver_callback, session.callback_url, session.session_id, body.ciphertext,
            algorithm=body.algorithm, callback_secret=session.callback_secret,
        )


# ---------------------------------------------------------------------------
# OAuth endpoints
# ---------------------------------------------------------------------------

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
    structlog.contextvars.bind_contextvars(code=code)

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
    # -- Passthrough redirect: custom authorize URL from the agent --
    if session.custom_authorize_url:
        await dao.store_oauth_state(session.session_id, "")
        return RedirectResponse(url=session.custom_authorize_url, status_code=302)

    # -- Standard OAuth flow --
    if session.template.template_type != TemplateType.OAUTH or not session.template.oauth_provider:
        return problem_response(400, "Not an OAuth Session", "This session does not use OAuth.")

    structlog.contextvars.bind_contextvars(
        session_id=session.session_id,
        oauth_provider=session.template.oauth_provider,
    )

    try:
        provider = resolve_provider(session.template.oauth_provider, config.oauth_providers)
    except ValueError as e:
        return problem_response(503, "OAuth Provider Error", str(e))

    # Consume connect_token: invalidate it so the OAuth flow cannot be restarted.
    # The session remains CONFIRMED but with a cleared connect_token.
    await dao.update_status(session.session_id, SessionStatus.CONFIRMED, connect_token="")

    code_verifier, code_challenge = generate_pkce()

    state = session.session_id
    await dao.store_oauth_state(session.session_id, code_verifier)

    redirect_uri = f"{config.server.base_url}/v1/oauth/callback"
    auth_url = build_authorization_url(
        provider=provider,
        redirect_uri=redirect_uri,
        scopes=session.template.oauth_scopes,
        state=state,
        code_challenge=code_challenge,
        extra_params=session.template.oauth_extra_params,
    )

    logger.info("oauth.authorize", connect_token_consumed=True)

    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/oauth/callback")
async def oauth_callback(
    request: Request,
    state: str | None = None,
    code: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    background: BackgroundTasks = None,
    dao: SessionDAO = Depends(get_session_dao),
    config=Depends(get_config),
):
    """OAuth provider redirects back here after user authorization.

    Standard mode: exchanges the authorization code for tokens.
    Passthrough mode: extracts custom callback parameters, encrypts
    and stores them for the agent to retrieve.
    """
    if state:
        structlog.contextvars.bind_contextvars(session_id=state)

    # Handle provider errors — session stays CONFIRMED until TTL expiry (one-shot design).
    # The connect_token was already consumed at redirect initiation, so no retry is possible.
    # The agent must create a new session if the user needs to try again.
    if error:
        detail = error_description or error
        if state:
            # Try standard lookup first, then custom_state lookup
            session = await dao.get(state)
            if not session:
                session = await dao.get_by_custom_state(state)
            if session:
                await dao.clear_oauth_state(session.session_id)
                structlog.contextvars.bind_contextvars(
                    oauth_provider=session.template.oauth_provider,
                )
        logger.warning("oauth.callback.error", oauth_error=error, oauth_error_description=error_description)
        return _oauth_failed()

    # -- Path A: Standard lookup by state (= session_id) --
    session = None
    is_passthrough = False
    if state:
        session = await dao.get(state)
        if session and session.oauth_code_verifier is not None:
            is_passthrough = bool(session.custom_authorize_url)
        else:
            session = None

    # -- Path B: Passthrough lookup by custom_state --
    if not session and state:
        session = await dao.get_by_custom_state(state)
        if session:
            is_passthrough = True

    if not session:
        if not state and not code:
            return problem_response(400, "Invalid Callback", "Missing state or code parameter.")
        return problem_response(400, "Invalid State", "OAuth state parameter not recognized. Session may have expired.")

    code_verifier = session.oauth_code_verifier or ""
    # Pop semantics: clear OAuth state to prevent replay
    await dao.clear_oauth_state(session.session_id)

    # -- Passthrough: extract custom callback params, encrypt, store --
    if is_passthrough:
        all_params = dict(request.query_params)
        capture = session.custom_callback_params or []
        captured = {k: all_params.get(k, "") for k in capture}
        if not any(captured.values()):
            captured["code"] = all_params.get("code", "")

        try:
            ciphertext_b64 = encrypt_for_agent(captured, session.public_key)
        except Exception as exc:
            return problem_response(
                500, "Encryption Failed",
                f"Failed to encrypt callback params: {exc}",
            )

        ok = await dao.store_ciphertext(
            session.session_id, ciphertext_b64, "RSA-OAEP-256+AES-256-GCM",
        )
        if not ok:
            return problem_response(500, "Storage Error", "Failed to store encrypted data.")

        if session.callback_url and background:
            background.add_task(
                deliver_callback, session.callback_url, session.session_id, ciphertext_b64,
                algorithm="RSA-OAEP-256+AES-256-GCM", callback_secret=session.callback_secret,
            )

        return RedirectResponse(
            url=f"{config.server.base_url}/connect/{session.code}?status=success",
            status_code=302,
        )

    # -- Standard OAuth flow --
    if not code:
        return problem_response(400, "Invalid Callback", "Missing code parameter.")

    if not session.template.oauth_provider:
        return problem_response(400, "Not an OAuth Session", "This session does not use OAuth.")

    structlog.contextvars.bind_contextvars(
        oauth_provider=session.template.oauth_provider,
        code=session.code,
    )

    try:
        provider = resolve_provider(session.template.oauth_provider, config.oauth_providers)
    except ValueError as e:
        return problem_response(503, "OAuth Provider Error", str(e))

    redirect_uri = f"{config.server.base_url}/v1/oauth/callback"
    try:
        token = await exchange_token(
            provider=provider,
            redirect_uri=redirect_uri,
            authorization_code=code,
            code_verifier=code_verifier,
        )
    except ValueError as e:
        # Session stays CONFIRMED (one-shot design) — no retry possible.
        logger.error("oauth.token_exchange.failed", error=str(e))
        return _oauth_failed()

    try:
        ciphertext_b64 = encrypt_for_agent(token, session.public_key)
    except Exception as exc:
        return problem_response(
            500,
            "Encryption Failed",
            f"Failed to encrypt OAuth tokens with agent's public key: {exc}",
        )

    ok = await dao.store_ciphertext(
        session.session_id, ciphertext_b64, "RSA-OAEP-256+AES-256-GCM"
    )
    if not ok:
        return problem_response(500, "Storage Error", "Failed to store encrypted tokens.")

    if session.callback_url and background:
        background.add_task(
            deliver_callback, session.callback_url, session.session_id, ciphertext_b64,
            algorithm="RSA-OAEP-256+AES-256-GCM", callback_secret=session.callback_secret,
        )

    logger.info("oauth.callback.success")

    return RedirectResponse(
        url=f"{config.server.base_url}/connect/{session.code}?status=success",
        status_code=302,
    )


# ---------------------------------------------------------------------------
# Webhook relay
# ---------------------------------------------------------------------------

@router.post("/sessions/{session_id}/webhook", status_code=200)
async def webhook_relay(
    session_id: str,
    request: Request,
    token: str | None = None,
    dao: SessionDAO = Depends(get_session_dao),
    config=Depends(get_config),
):
    """Receive an inbound webhook payload and store it encrypted for the agent.

    This is an ephemeral relay — the session's TTL (max 15 min) applies.
    The webhook_token is auto-generated and included in the webhook URL
    returned when creating a session with enable_webhook=True.
    """
    session = await dao.get(session_id)
    if not session:
        return _session_not_found()

    if not session.webhook_token:
        return problem_response(403, "Webhook Not Enabled", "This session does not have webhooks enabled.")

    if not token or not hmac.compare_digest(token, session.webhook_token):
        return problem_response(403, "Invalid Webhook Token", "The provided webhook token is not valid.")

    body_bytes = await request.body()
    max_payload = config.sessions.max_webhook_payload
    if len(body_bytes) > max_payload:
        return problem_response(
            413, "Payload Too Large",
            f"Webhook payload exceeds the maximum allowed size of {max_payload} bytes.",
        )

    content_type = request.headers.get("content-type", "application/octet-stream")
    payload = {
        "headers": dict(request.headers),
        "body": body_bytes.decode("utf-8", errors="replace"),
        "content_type": content_type,
    }

    try:
        ciphertext_b64 = encrypt_for_agent(payload, session.public_key)
    except Exception as exc:
        return problem_response(
            500, "Encryption Failed",
            f"Failed to encrypt webhook payload: {exc}",
        )

    ok = await dao.store_ciphertext(
        session.session_id, ciphertext_b64, "RSA-OAEP-256+AES-256-GCM",
    )
    if not ok:
        return problem_response(500, "Storage Error", "Failed to store encrypted webhook payload.")

    return {"status": "accepted", "session_id": session_id}
