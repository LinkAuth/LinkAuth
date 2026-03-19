"""OAuth 2.0 flow handler using authlib.

Handles:
- Provider resolution (known providers via discovery, custom via config)
- PKCE generation (RFC 7636)
- Authorization URL construction
- Token exchange + hybrid encryption
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
from dataclasses import dataclass, field

from authlib.integrations.httpx_client import AsyncOAuth2Client

from broker.config import OAuthProviderConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known providers — auth_url + token_url auto-configured
# For OIDC providers we could use server_metadata_url, but explicit URLs
# are more predictable and don't require an extra HTTP call at startup.
# ---------------------------------------------------------------------------

KNOWN_PROVIDERS: dict[str, dict[str, str]] = {
    "google": {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
    },
    "microsoft": {
        "auth_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/oidc/userinfo",
    },
    "github": {
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
    },
    "slack": {
        "auth_url": "https://slack.com/oauth/v2/authorize",
        "token_url": "https://slack.com/api/oauth.v2.access",
    },
    "gitlab": {
        "auth_url": "https://gitlab.com/oauth/authorize",
        "token_url": "https://gitlab.com/oauth/token",
        "userinfo_url": "https://gitlab.com/oauth/userinfo",
    },
    "discord": {
        "auth_url": "https://discord.com/api/oauth2/authorize",
        "token_url": "https://discord.com/api/oauth2/token",
        "userinfo_url": "https://discord.com/api/users/@me",
    },
    "spotify": {
        "auth_url": "https://accounts.spotify.com/authorize",
        "token_url": "https://accounts.spotify.com/api/token",
        "userinfo_url": "https://api.spotify.com/v1/me",
    },
}


@dataclass
class ResolvedProvider:
    """Fully resolved OAuth provider with all URLs and credentials."""
    provider_id: str
    auth_url: str
    token_url: str
    client_id: str
    client_secret: str
    userinfo_url: str | None = None


@dataclass
class OAuthSession:
    """Tracks OAuth state for a LinkAuth session (PKCE + state)."""
    code_verifier: str
    state: str  # maps back to the LinkAuth session_id


def resolve_provider(
    provider_id: str,
    config_providers: dict[str, OAuthProviderConfig],
) -> ResolvedProvider:
    """Resolve a provider ID to a fully configured provider.

    Raises ValueError with a specific message if resolution fails.
    """
    # 1. Must be registered in config.yaml
    if provider_id not in config_providers:
        raise ValueError(
            f"OAuth provider '{provider_id}' is not registered. "
            f"Add '{provider_id}' to oauth_providers in config.yaml."
        )

    cfg = config_providers[provider_id]

    # 2. Credentials must be set via env
    if not cfg.client_id or not cfg.client_secret:
        env_prefix = f"OAUTH_{provider_id.upper()}"
        raise ValueError(
            f"OAuth provider '{provider_id}' is missing credentials. "
            f"Set {env_prefix}_CLIENT_ID and {env_prefix}_CLIENT_SECRET "
            f"environment variables."
        )

    # 3. Resolve URLs: config override > known provider > error
    known = KNOWN_PROVIDERS.get(provider_id, {})
    auth_url = cfg.auth_url or known.get("auth_url")
    token_url = cfg.token_url or known.get("token_url")
    userinfo_url = cfg.userinfo_url or known.get("userinfo_url")

    if not auth_url or not token_url:
        raise ValueError(
            f"OAuth provider '{provider_id}' has no auth_url/token_url configured "
            f"and is not a known provider. Add auth_url and token_url to "
            f"oauth_providers.{provider_id} in config.yaml."
        )

    return ResolvedProvider(
        provider_id=provider_id,
        auth_url=auth_url,
        token_url=token_url,
        client_id=cfg.client_id,
        client_secret=cfg.client_secret,
        userinfo_url=userinfo_url,
    )


def generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (RFC 7636)."""
    import hashlib
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def build_authorization_url(
    provider: ResolvedProvider,
    redirect_uri: str,
    scopes: list[str],
    state: str,
    code_challenge: str,
) -> str:
    """Build the OAuth authorization URL with PKCE."""
    client = AsyncOAuth2Client(
        client_id=provider.client_id,
        redirect_uri=redirect_uri,
        scope=" ".join(scopes),
        code_challenge_method="S256",
    )
    url, _ = client.create_authorization_url(
        provider.auth_url,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    return url


async def exchange_token(
    provider: ResolvedProvider,
    redirect_uri: str,
    authorization_code: str,
    code_verifier: str,
) -> dict:
    """Exchange authorization code for tokens.

    Returns the full token dict (access_token, refresh_token, etc.).
    Raises ValueError if the exchange fails.
    """
    async with AsyncOAuth2Client(
        client_id=provider.client_id,
        client_secret=provider.client_secret,
        redirect_uri=redirect_uri,
    ) as client:
        try:
            token = await client.fetch_token(
                provider.token_url,
                code=authorization_code,
                code_verifier=code_verifier,
            )
        except Exception as exc:
            raise ValueError(
                f"OAuth provider '{provider.provider_id}' rejected the token exchange. "
                f"Verify that OAUTH_{provider.provider_id.upper()}_CLIENT_ID and "
                f"OAUTH_{provider.provider_id.upper()}_CLIENT_SECRET are correct. "
                f"Error: {exc}"
            ) from exc

    return dict(token)
