from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from broker.callback import deliver_callback
from broker.dao.base import SessionDAO
from broker.models import Session, SessionStatus
from broker.templates import resolve_template

router = APIRouter(prefix="/v1")


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
    callback_url: str | None = None
    ttl: int | None = None


class CreateSessionResponse(BaseModel):
    session_id: str
    code: str
    url: str
    poll_token: str
    expires_at: str


class SessionStatusResponse(BaseModel):
    status: str
    expires_at: str
    ciphertext: str | None = None
    algorithm: str | None = None


class CompleteSessionRequest(BaseModel):
    ciphertext: str
    algorithm: str = "RSA-OAEP-256+AES-256-GCM"


class ConfirmSessionRequest(BaseModel):
    code: str


class SessionInfoResponse(BaseModel):
    status: str
    display_name: str
    code: str
    fields: list[dict[str, Any]]
    public_key: str


# ---------------------------------------------------------------------------
# Dependency injection helpers
# ---------------------------------------------------------------------------

def get_session_dao(request: Request) -> SessionDAO:
    return request.app.state.session_dao


def get_config(request: Request):
    return request.app.state.config


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
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

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
    )


@router.get("/sessions/{session_id}", response_model=SessionStatusResponse)
async def get_session(
    session_id: str,
    request: Request,
    dao: SessionDAO = Depends(get_session_dao),
):
    """Agent polls session status. Requires poll_token as Bearer token."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing poll_token")
    poll_token = auth.removeprefix("Bearer ").strip()

    session = await dao.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    if session.poll_token != poll_token:
        raise HTTPException(status_code=403, detail="Invalid poll_token")

    # If ready, consume (one-time retrieval)
    if session.status == SessionStatus.READY:
        consumed = await dao.consume(session_id)
        if consumed:
            return SessionStatusResponse(
                status="ready",
                expires_at=consumed.expires_at.isoformat(),
                ciphertext=consumed.ciphertext,
                algorithm=consumed.algorithm,
            )

    return SessionStatusResponse(
        status=session.status.value,
        expires_at=session.expires_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Frontend-facing endpoints
# ---------------------------------------------------------------------------

@router.get("/connect/{code}", response_model=SessionInfoResponse)
async def get_session_info(
    code: str,
    dao: SessionDAO = Depends(get_session_dao),
):
    """Frontend fetches session info to render the connect page."""
    session = await dao.get_by_code(code)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    if session.status not in (SessionStatus.PENDING, SessionStatus.CONFIRMED):
        raise HTTPException(status_code=410, detail="Session already completed")

    return SessionInfoResponse(
        status=session.status.value,
        display_name=session.template.display_name,
        code=session.code,
        fields=[
            {"name": f.name, "label": f.label, "type": f.type,
             "required": f.required, "options": f.options}
            for f in session.template.fields
        ],
        public_key=session.public_key,
    )


@router.post("/connect/{code}/confirm", status_code=204)
async def confirm_code(
    code: str,
    dao: SessionDAO = Depends(get_session_dao),
):
    """User confirms they see the correct code. Transitions to CONFIRMED."""
    session = await dao.get_by_code(code)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    if session.status != SessionStatus.PENDING:
        raise HTTPException(status_code=409, detail="Session already confirmed")

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
        raise HTTPException(status_code=404, detail="Session not found or expired")
    if session.status not in (SessionStatus.PENDING, SessionStatus.CONFIRMED):
        raise HTTPException(status_code=409, detail="Session not in a completable state")

    ok = await dao.store_ciphertext(session.session_id, body.ciphertext, body.algorithm)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to store credentials")

    if session.callback_url:
        background.add_task(
            deliver_callback, session.callback_url, session.session_id, body.ciphertext
        )
