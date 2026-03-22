from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    base_url: str = "http://localhost:8080"


@dataclass
class SqliteConfig:
    path: str = "./data/broker.db"


@dataclass
class StorageConfig:
    backend: str = "sqlite"
    sqlite: SqliteConfig = field(default_factory=SqliteConfig)


@dataclass
class SessionsConfig:
    default_ttl: int = 600
    max_ttl: int = 900
    cleanup_interval: int = 60
    code_length: int = 8
    poll_interval: int = 5  # RFC 8628: recommended polling interval in seconds


@dataclass
class SecurityConfig:
    """API key authentication for agent-facing endpoints."""
    api_keys: list[str] = field(default_factory=list)


@dataclass
class RateLimitConfig:
    max_sessions_per_minute: int = 10


@dataclass
class OAuthProviderConfig:
    provider_id: str = ""
    # OIDC Discovery — set issuer to auto-discover auth_url + token_url
    issuer: str | None = None
    # URLs — auto-discovered via loginpass/OIDC, or set manually for custom providers
    auth_url: str | None = None
    token_url: str | None = None
    userinfo_url: str | None = None
    # Credentials — loaded from env: OAUTH_{PROVIDER}_CLIENT_ID / _CLIENT_SECRET
    client_id: str = ""
    client_secret: str = ""


@dataclass
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    sessions: SessionsConfig = field(default_factory=SessionsConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    oauth_providers: dict[str, OAuthProviderConfig] = field(default_factory=dict)


def load_config(path: str = "config.yaml") -> AppConfig:
    """Load configuration from YAML file, falling back to defaults."""
    config_path = Path(path)
    if not config_path.exists():
        return AppConfig()

    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}

    server_raw = raw.get("server", {})
    storage_raw = raw.get("storage", {})
    sessions_raw = raw.get("sessions", {})
    security_raw = raw.get("security", {})
    rate_limit_raw = raw.get("rate_limit", {})

    sqlite_raw = storage_raw.get("sqlite", {})

    # Parse OAuth providers — credentials from env, URLs from YAML
    oauth_raw = raw.get("oauth_providers", {})
    oauth_providers = {}
    for name, provider_raw in oauth_raw.items():
        provider_raw = provider_raw or {}  # handle empty `google: {}`
        env_prefix = f"OAUTH_{name.upper()}"
        oauth_providers[name] = OAuthProviderConfig(
            provider_id=name,
            issuer=provider_raw.get("issuer"),
            auth_url=provider_raw.get("auth_url"),
            token_url=provider_raw.get("token_url"),
            userinfo_url=provider_raw.get("userinfo_url"),
            client_id=os.environ.get(f"{env_prefix}_CLIENT_ID", ""),
            client_secret=os.environ.get(f"{env_prefix}_CLIENT_SECRET", ""),
        )

    # API keys: env var takes precedence, comma-separated list
    env_api_keys = os.environ.get("LINKAUTH_API_KEYS", "")
    api_keys_from_env = [k.strip() for k in env_api_keys.split(",") if k.strip()]
    api_keys_from_yaml = security_raw.get("api_keys", []) or []
    # Merge: env keys first, then YAML keys (deduplicated)
    all_api_keys = list(dict.fromkeys(api_keys_from_env + api_keys_from_yaml))

    # base_url: env var takes precedence (required for Docker/Coolify deployment)
    # Coolify injects SERVICE_FQDN_LINKAUTH with the public URL
    env_base_url = os.environ.get("LINKAUTH_BASE_URL") or os.environ.get("SERVICE_FQDN_LINKAUTH") or ""
    if env_base_url:
        env_base_url = env_base_url.rstrip("/")
        if not env_base_url.startswith(("http://", "https://")):
            env_base_url = f"https://{env_base_url}"
        server_raw["base_url"] = env_base_url

    return AppConfig(
        server=ServerConfig(**server_raw),
        storage=StorageConfig(
            backend=storage_raw.get("backend", "sqlite"),
            sqlite=SqliteConfig(**sqlite_raw),
        ),
        sessions=SessionsConfig(**sessions_raw),
        security=SecurityConfig(api_keys=all_api_keys),
        rate_limit=RateLimitConfig(**rate_limit_raw),
        oauth_providers=oauth_providers,
    )
