from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import aiosqlite

from broker.dao.base import SessionDAO, TemplateDAO
from broker.models import (
    CredentialTemplate,
    FieldDefinition,
    Session,
    SessionStatus,
)

_CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    code         TEXT NOT NULL UNIQUE,
    public_key   TEXT NOT NULL,
    template_json TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    poll_token   TEXT NOT NULL,
    callback_url TEXT,
    ciphertext   TEXT,
    algorithm    TEXT,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    consumed_at  TEXT
);
"""

_CREATE_TEMPLATES = """
CREATE TABLE IF NOT EXISTS templates (
    template_id  TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    fields_json  TEXT NOT NULL,
    builtin      INTEGER NOT NULL DEFAULT 0
);
"""


def _dt_to_str(dt: datetime) -> str:
    return dt.isoformat()


def _str_to_dt(s: str) -> datetime:
    return datetime.fromisoformat(s)


def _template_to_json(t: CredentialTemplate) -> str:
    return json.dumps({
        "template_id": t.template_id,
        "display_name": t.display_name,
        "fields": [
            {"name": f.name, "label": f.label, "type": f.type,
             "required": f.required, "options": f.options}
            for f in t.fields
        ],
        "builtin": t.builtin,
    })


def _json_to_template(raw: str) -> CredentialTemplate:
    d = json.loads(raw)
    return CredentialTemplate(
        template_id=d["template_id"],
        display_name=d["display_name"],
        fields=[FieldDefinition(**f) for f in d["fields"]],
        builtin=d.get("builtin", False),
    )


def _row_to_session(row: aiosqlite.Row) -> Session:
    return Session(
        session_id=row["session_id"],
        code=row["code"],
        public_key=row["public_key"],
        template=_json_to_template(row["template_json"]),
        status=SessionStatus(row["status"]),
        poll_token=row["poll_token"],
        callback_url=row["callback_url"],
        ciphertext=row["ciphertext"],
        algorithm=row["algorithm"],
        created_at=_str_to_dt(row["created_at"]),
        expires_at=_str_to_dt(row["expires_at"]),
        consumed_at=_str_to_dt(row["consumed_at"]) if row["consumed_at"] else None,
    )


class SqliteSessionDAO(SessionDAO):
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def init(self) -> None:
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute(_CREATE_SESSIONS)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    @property
    def db(self) -> aiosqlite.Connection:
        assert self._db is not None, "DAO not initialized — call init() first"
        return self._db

    async def create(self, session: Session) -> None:
        await self.db.execute(
            """INSERT INTO sessions
               (session_id, code, public_key, template_json, status,
                poll_token, callback_url, ciphertext, algorithm,
                created_at, expires_at, consumed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session.session_id,
                session.code,
                session.public_key,
                _template_to_json(session.template),
                session.status.value,
                session.poll_token,
                session.callback_url,
                session.ciphertext,
                session.algorithm,
                _dt_to_str(session.created_at),
                _dt_to_str(session.expires_at),
                _dt_to_str(session.consumed_at) if session.consumed_at else None,
            ),
        )
        await self.db.commit()

    async def get(self, session_id: str) -> Session | None:
        cursor = await self.db.execute(
            "SELECT * FROM sessions WHERE session_id = ? AND expires_at > ?",
            (session_id, _dt_to_str(datetime.now(timezone.utc))),
        )
        row = await cursor.fetchone()
        return _row_to_session(row) if row else None

    async def get_by_code(self, code: str) -> Session | None:
        session_id = Session.hash_code(code)
        return await self.get(session_id)

    async def update_status(self, session_id: str, status: SessionStatus) -> bool:
        cursor = await self.db.execute(
            "UPDATE sessions SET status = ? WHERE session_id = ?",
            (status.value, session_id),
        )
        await self.db.commit()
        return cursor.rowcount > 0

    async def store_ciphertext(
        self, session_id: str, ciphertext: str, algorithm: str
    ) -> bool:
        cursor = await self.db.execute(
            """UPDATE sessions
               SET ciphertext = ?, algorithm = ?, status = ?
               WHERE session_id = ? AND status IN (?, ?)""",
            (
                ciphertext,
                algorithm,
                SessionStatus.READY.value,
                session_id,
                SessionStatus.PENDING.value,
                SessionStatus.CONFIRMED.value,
            ),
        )
        await self.db.commit()
        return cursor.rowcount > 0

    async def consume(self, session_id: str) -> Session | None:
        session = await self.get(session_id)
        if not session or session.status != SessionStatus.READY:
            return None
        now = _dt_to_str(datetime.now(timezone.utc))
        await self.db.execute(
            "UPDATE sessions SET status = ?, consumed_at = ? WHERE session_id = ?",
            (SessionStatus.CONSUMED.value, now, session_id),
        )
        await self.db.commit()
        session.status = SessionStatus.CONSUMED
        return session

    async def delete(self, session_id: str) -> bool:
        cursor = await self.db.execute(
            "DELETE FROM sessions WHERE session_id = ?", (session_id,)
        )
        await self.db.commit()
        return cursor.rowcount > 0

    async def cleanup_expired(self) -> int:
        now = _dt_to_str(datetime.now(timezone.utc))
        cursor = await self.db.execute(
            "DELETE FROM sessions WHERE expires_at < ? OR status = ?",
            (now, SessionStatus.CONSUMED.value),
        )
        await self.db.commit()
        return cursor.rowcount


class SqliteTemplateDAO(TemplateDAO):
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def init(self) -> None:
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute(_CREATE_TEMPLATES)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    @property
    def db(self) -> aiosqlite.Connection:
        assert self._db is not None, "DAO not initialized — call init() first"
        return self._db

    async def get(self, template_id: str) -> CredentialTemplate | None:
        cursor = await self.db.execute(
            "SELECT * FROM templates WHERE template_id = ?", (template_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return CredentialTemplate(
            template_id=row["template_id"],
            display_name=row["display_name"],
            fields=[FieldDefinition(**f) for f in json.loads(row["fields_json"])],
            builtin=bool(row["builtin"]),
        )

    async def list(self) -> list[CredentialTemplate]:
        cursor = await self.db.execute("SELECT * FROM templates")
        rows = await cursor.fetchall()
        return [
            CredentialTemplate(
                template_id=row["template_id"],
                display_name=row["display_name"],
                fields=[FieldDefinition(**f) for f in json.loads(row["fields_json"])],
                builtin=bool(row["builtin"]),
            )
            for row in rows
        ]

    async def register(self, template: CredentialTemplate) -> None:
        fields_json = json.dumps([
            {"name": f.name, "label": f.label, "type": f.type,
             "required": f.required, "options": f.options}
            for f in template.fields
        ])
        await self.db.execute(
            """INSERT OR REPLACE INTO templates
               (template_id, display_name, fields_json, builtin)
               VALUES (?, ?, ?, ?)""",
            (template.template_id, template.display_name, fields_json,
             int(template.builtin)),
        )
        await self.db.commit()
