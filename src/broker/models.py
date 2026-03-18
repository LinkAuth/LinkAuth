from __future__ import annotations

import hashlib
import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class SessionStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"  # user confirmed code, entering credentials
    READY = "ready"          # credentials encrypted and stored
    CONSUMED = "consumed"    # agent retrieved ciphertext
    EXPIRED = "expired"


@dataclass
class FieldDefinition:
    name: str
    label: str
    type: str = "text"       # text, password, textarea, select
    required: bool = True
    options: list[str] | None = None  # for select fields


@dataclass
class CredentialTemplate:
    template_id: str
    display_name: str
    fields: list[FieldDefinition]
    builtin: bool = True


@dataclass
class Session:
    session_id: str          # SHA-256 of the code
    code: str                # human-readable code, e.g. "ABCD-1234"
    public_key: str          # agent's RSA public key (base64/PEM)
    template: CredentialTemplate
    status: SessionStatus = SessionStatus.PENDING
    poll_token: str = ""
    callback_url: str | None = None
    ciphertext: str | None = None
    algorithm: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    consumed_at: datetime | None = None

    @staticmethod
    def generate_code(length: int = 8) -> str:
        chars = string.ascii_uppercase + string.digits
        raw = "".join(secrets.choice(chars) for _ in range(length))
        # format as ABCD-1234
        mid = length // 2
        return f"{raw[:mid]}-{raw[mid:]}"

    @staticmethod
    def hash_code(code: str) -> str:
        normalized = code.replace("-", "").upper()
        return hashlib.sha256(normalized.encode()).hexdigest()

    @staticmethod
    def generate_poll_token() -> str:
        return f"pt_{secrets.token_urlsafe(32)}"
