"""OAuth 2.0 flow handler using authlib + loginpass.

Provider resolution strategy (in order):
1. Explicit auth_url + token_url from config.yaml override
2. loginpass predefined providers (Google, GitHub, Slack, ...)
3. OIDC Discovery via issuer URL (/.well-known/openid-configuration)

Handles:
- Provider resolution (loginpass → OIDC discovery → config override)
- PKCE generation (RFC 7636)
- Authorization URL construction
- Token exchange + hybrid encryption
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from dataclasses import dataclass

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from broker.config import OAuthProviderConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# loginpass provider registry — maps provider_id to OAUTH_CONFIG
# ---------------------------------------------------------------------------

_LOGINPASS_PROVIDERS: dict[str, dict] = {}

def _load_loginpass_providers() -> None:
    """Load all predefined providers from loginpass."""
    try:
        import loginpass
        for name in dir(loginpass):
            cls = getattr(loginpass, name)
            if (
                isinstance(cls, type)
                and hasattr(cls, "OAUTH_CONFIG")
                and hasattr(cls, "NAME")
            ):
                _LOGINPASS_PROVIDERS[cls.NAME] = cls.OAUTH_CONFIG
    except ImportError:
        logger.debug("loginpass not installed — no predefined providers available")

_load_loginpass_providers()


@dataclass
class ResolvedProvider:
    """Fully resolved OAuth provider with all URLs and credentials."""
    provider_id: str
    auth_url: str
    token_url: str
    client_id: str
    client_secret: str
    userinfo_url: str | None = None
    server_metadata_url: str | None = None


@dataclass
class OAuthSession:
    """Tracks OAuth state for a LinkAuth session (PKCE + state)."""
    code_verifier: str
    state: str  # maps back to the LinkAuth session_id


def _discover_oidc_endpoints(issuer: str) -> dict[str, str]:
    """Fetch OIDC Discovery document from issuer.

    Accepts both full URL (https://example.com) and bare domain (example.com).
    Returns dict with authorization_endpoint, token_endpoint, etc.
    Raises ValueError if discovery fails.
    """
    # Accept bare domain — prepend https:// if no scheme
    if not issuer.startswith(("http://", "https://")):
        issuer = f"https://{issuer}"
    well_known = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    try:
        resp = httpx.get(well_known, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        raise ValueError(
            f"OIDC Discovery failed for issuer '{issuer}' "
            f"({well_known}): {exc}"
        ) from exc


def resolve_provider(
    provider_id: str,
    config_providers: dict[str, OAuthProviderConfig],
) -> ResolvedProvider:
    """Resolve a provider ID to a fully configured provider.

    No YAML entry required for known providers — credentials from env vars
    are sufficient. Config YAML is only needed for overrides (issuer,
    custom auth_url/token_url).

    Resolution order for URLs:
    1. Config overrides (auth_url/token_url from config.yaml)
    2. loginpass predefined providers (22+ built-in)
    3. OIDC Discovery via issuer URL

    Raises ValueError with a specific message if resolution fails.
    """
    # 1. Build effective config: YAML override + env vars (read at request time)
    cfg = config_providers.get(provider_id)
    env_prefix = f"OAUTH_{provider_id.upper()}"
    client_id = os.environ.get(f"{env_prefix}_CLIENT_ID", "")
    client_secret = os.environ.get(f"{env_prefix}_CLIENT_SECRET", "")

    # YAML config overrides env for URLs/issuer only (not credentials)
    if cfg:
        # Prefer env credentials, fall back to config (for backwards compat)
        client_id = client_id or cfg.client_id
        client_secret = client_secret or cfg.client_secret

    # 2. Credentials must exist
    if not client_id or not client_secret:
        is_known = provider_id in _LOGINPASS_PROVIDERS
        hint = (
            f"Set {env_prefix}_CLIENT_ID and {env_prefix}_CLIENT_SECRET "
            f"environment variables."
        )
        if not is_known and not cfg:
            hint += (
                f" Provider '{provider_id}' is not a known provider — "
                f"also set {env_prefix}_ISSUER for OIDC Discovery, or "
                f"{env_prefix}_AUTH_URL + {env_prefix}_TOKEN_URL."
            )
        raise ValueError(
            f"OAuth provider '{provider_id}' is not configured. {hint}"
        )

    # 3. Resolve URLs — priority: env > YAML > loginpass > OIDC discovery
    auth_url = (
        os.environ.get(f"{env_prefix}_AUTH_URL")
        or (cfg.auth_url if cfg else None)
    )
    token_url = (
        os.environ.get(f"{env_prefix}_TOKEN_URL")
        or (cfg.token_url if cfg else None)
    )
    userinfo_url = cfg.userinfo_url if cfg else None
    server_metadata_url = None

    # Try loginpass if URLs not explicitly set
    if not auth_url or not token_url:
        lp = _LOGINPASS_PROVIDERS.get(provider_id, {})
        if lp:
            server_metadata_url = lp.get("server_metadata_url")
            # Some loginpass providers use server_metadata_url (OIDC Discovery)
            # rather than explicit URLs. If so, fetch them.
            if server_metadata_url and (not auth_url or not token_url):
                try:
                    endpoints = _discover_oidc_endpoints(
                        server_metadata_url.replace(
                            "/.well-known/openid-configuration", ""
                        )
                    )
                    auth_url = auth_url or endpoints.get("authorization_endpoint")
                    token_url = token_url or endpoints.get("token_endpoint")
                    userinfo_url = userinfo_url or endpoints.get("userinfo_endpoint")
                except ValueError:
                    logger.warning(
                        "OIDC Discovery via loginpass failed for %s, "
                        "trying explicit config", provider_id
                    )
            # Some loginpass providers have explicit URLs
            auth_url = auth_url or lp.get("authorize_url") or lp.get("access_token_url")
            token_url = token_url or lp.get("access_token_url")

    # Try OIDC Discovery via issuer if still missing
    issuer = (
        os.environ.get(f"{env_prefix}_ISSUER")
        or (cfg.issuer if cfg else None)
    )
    if (not auth_url or not token_url) and issuer:
        try:
            endpoints = _discover_oidc_endpoints(issuer)
            auth_url = auth_url or endpoints.get("authorization_endpoint")
            token_url = token_url or endpoints.get("token_endpoint")
            userinfo_url = userinfo_url or endpoints.get("userinfo_endpoint")
        except ValueError as e:
            raise ValueError(
                f"OAuth provider '{provider_id}' has no auth_url/token_url "
                f"and OIDC Discovery failed: {e}"
            ) from e

    if not auth_url or not token_url:
        raise ValueError(
            f"OAuth provider '{provider_id}' cannot resolve auth_url/token_url. "
            f"Set {env_prefix}_ISSUER for OIDC Discovery, or "
            f"{env_prefix}_AUTH_URL + {env_prefix}_TOKEN_URL explicitly. "
            f"Alternatively, add these to oauth_providers.{provider_id} in config.yaml."
        )

    return ResolvedProvider(
        provider_id=provider_id,
        auth_url=auth_url,
        token_url=token_url,
        client_id=client_id,
        client_secret=client_secret,
        userinfo_url=userinfo_url,
        server_metadata_url=server_metadata_url,
    )


def generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (RFC 7636)."""
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
    extra_params: dict[str, str] | None = None,
) -> str:
    """Build the OAuth authorization URL with PKCE.

    extra_params are passed as additional query parameters to the auth URL.
    Use this for provider-specific parameters like:
    - audience (Auth0)
    - hd (Google domain hint)
    - login_hint, prompt, etc.
    """
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
        **(extra_params or {}),
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


def encrypt_for_agent(plaintext_dict: dict, public_key_b64: str) -> str:
    """Hybrid-encrypt a dict with the agent's RSA public key.

    Uses RSA-OAEP-256 + AES-256-GCM (same as crypto.js in the browser).
    Returns a base64-encoded JSON payload containing wrapped_key, iv, ciphertext.
    """
    pub_key_der = base64.b64decode(public_key_b64)
    public_key = serialization.load_der_public_key(pub_key_der)

    aes_key = AESGCM.generate_key(bit_length=256)
    iv = secrets.token_bytes(12)
    aesgcm = AESGCM(aes_key)
    plaintext = json.dumps(plaintext_dict).encode()
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    payload = {
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()
