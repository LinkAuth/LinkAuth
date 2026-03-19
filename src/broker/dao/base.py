from __future__ import annotations

from abc import ABC, abstractmethod

from broker.models import CredentialTemplate, Session, SessionStatus


class SessionDAO(ABC):
    """Abstract interface for session persistence."""

    @abstractmethod
    async def create(self, session: Session) -> None:
        """Persist a new session."""

    @abstractmethod
    async def get(self, session_id: str) -> Session | None:
        """Retrieve a session by ID. Returns None if not found or expired."""

    @abstractmethod
    async def get_by_code(self, code: str) -> Session | None:
        """Retrieve a session by its human-readable code."""

    @abstractmethod
    async def update_status(
        self, session_id: str, status: SessionStatus,
        connect_token: str | None = None,
    ) -> bool:
        """Update session status. Optionally set connect_token. Returns False if not found."""

    @abstractmethod
    async def store_ciphertext(
        self, session_id: str, ciphertext: str, algorithm: str
    ) -> bool:
        """Store encrypted credentials and set status to READY."""

    @abstractmethod
    async def consume(self, session_id: str) -> Session | None:
        """Mark session as consumed and return it. Returns None if not found/ready."""

    @abstractmethod
    async def delete(self, session_id: str) -> bool:
        """Delete a session. Returns False if not found."""

    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Delete all expired sessions. Returns count of deleted rows."""

    @abstractmethod
    async def init(self) -> None:
        """Initialize storage (create tables, etc.)."""

    @abstractmethod
    async def close(self) -> None:
        """Clean up resources (close connections, etc.)."""


class TemplateDAO(ABC):
    """Abstract interface for credential template persistence."""

    @abstractmethod
    async def get(self, template_id: str) -> CredentialTemplate | None:
        """Retrieve a template by ID."""

    @abstractmethod
    async def list(self) -> list[CredentialTemplate]:
        """List all registered templates."""

    @abstractmethod
    async def register(self, template: CredentialTemplate) -> None:
        """Register or update a custom template."""

    @abstractmethod
    async def init(self) -> None:
        """Initialize storage."""

    @abstractmethod
    async def close(self) -> None:
        """Clean up resources."""
