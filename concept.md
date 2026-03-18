# MCS Credential Broker — Zero-Knowledge Credential Broker for AI Agents

## Vision

A universal, agent-agnostic credential broker that uses a Device-Flow-inspired UX (URL + Code) to let users provide credentials to AI agents — without the agent needing a web server, callback endpoint, or direct access to user interfaces.

The broker acts as a secure intermediary: the agent never handles raw user input, the broker never sees plaintext credentials, and the user gets a familiar, simple experience.

---

## Problem Statement

AI agents need credentials (OAuth tokens, API keys, passwords) to access external services on behalf of users. Current solutions have significant limitations:

| Approach | Problem |
|----------|---------|
| Hardcoded tokens / env vars | Insecure, not user-friendly, requires manual setup |
| OAuth with callback | Agent needs a web server / callback endpoint |
| Auth0 Device Flow | Works for auth, but not for Token Vault (confidential client required) |
| Composio / managed platforms | Vendor lock-in, agent must use their SDK |
| Local credential managers | Agent must run on same machine as user |

**The gap:** No solution lets an agent request arbitrary credentials from a user in a protocol-agnostic, zero-knowledge, infrastructure-free way.

---

## Core Concept

### The Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        CREDENTIAL BROKER                         │
│                    (hosted web service + API)                     │
└─────────────────────────────────────────────────────────────────┘

1. INITIATE                          2. USER CONSENT
   Agent ──POST /sessions──→ Broker     User opens URL in browser
   - sends public_key                   - sees confirmation code
   - sends credential_type              - enters credentials / does OAuth
   - receives: code + URL               - broker encrypts with agent's
                                           public key and stores ciphertext

3. PRESENT                           4. RETRIEVE
   Agent → LLM → User                  Agent ──GET /sessions/:hash──→ Broker
   "Please open URL and                - receives encrypted payload
    enter code ABCD-1234"              - decrypts locally with private key
                                       - has credentials, broker never saw them
```

### Why This Is Different

- **Device Flow UX** — URL + Code, no callback, no web server on agent side
- **Zero Knowledge** — Broker stores only ciphertext encrypted with agent's public key
- **Universal** — Works for OAuth, API keys, passwords, certificates, anything
- **Agent-agnostic** — CLI, Telegram bot, web app, cron job, Docker container — all work
- **Decoupled** — Agent and user don't need to share a runtime, machine, or network

---

## Security Architecture

### Zero-Knowledge with Asymmetric Encryption

```
Agent (private)                    Broker (untrusted storage)              User (browser)
───────────────                    ──────────────────────────              ──────────────
1. Generate keypair
   (Ed25519 / RSA-OAEP)
   private_key stays local

2. POST /sessions
   { public_key, type, meta }
         ──────────────────→  3. Generate session
                                  code = "ABCD-1234"
                                  session_id = SHA256(code)
                                  store: { session_id,
                                           public_key,
                                           status: "pending",
                                           expires_at }
                              ←── { code, url, session_id }

4. Show URL + code to user
   (via LLM, console, chat)
                                                                    5. Open URL
                                                                       See code "ABCD-1234"
                                                                       Confirm code matches

                                                                    6. Enter credentials
                                                                       (API key, password,
                                                                        or OAuth redirect)

                                                                    7. Browser JS encrypts
                                                                       credentials with
                                                                       agent's public_key

                                  8. Store encrypted payload     ←── POST /sessions/:id/complete
                                     { session_id,                    { ciphertext }
                                       ciphertext,
                                       status: "ready" }

9. Poll: GET /sessions/:hash
         ──────────────────→  10. Return { ciphertext }

11. Decrypt with private_key
    → plaintext credentials

12. Use credentials
    (API calls, OAuth exchange, etc.)
```

### Security Properties

| Property | How |
|----------|-----|
| **Broker never sees plaintext** | Encryption happens in user's browser (client-side JS) using agent's public key |
| **Database breach is useless** | Stored ciphertext can only be decrypted by agent's private key |
| **Code is not the encryption key** | Code is only for session matching (human-friendly), not cryptographic material |
| **Sessions expire** | TTL of 5-15 minutes, auto-cleanup |
| **One-time use** | Credentials can only be retrieved once, then deleted |
| **No replay** | Each session generates a fresh keypair |

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Database breach | Only ciphertext stored, useless without agent's private key |
| Man-in-the-middle | TLS for transport, encryption at rest, code confirmation prevents phishing |
| Code brute-force | Code is for session matching only, not encryption. Rate limiting + short TTL |
| Phishing (fake broker URL) | User verifies code matches what agent showed. Domain trust. |
| Agent compromise | Private key in agent's memory. Standard runtime security applies. |

---

## REST API Design

### Base URL

```
https://broker.example.com/v1
```

### Endpoints

#### 1. Create Session

```
POST /v1/sessions

Request:
{
  "public_key": "<base64-encoded Ed25519/RSA public key>",
  "credential_type": "oauth" | "api_key" | "basic_auth" | "custom",
  "meta": {
    "service": "gmail",
    "display_name": "Google Gmail Access",
    "scopes": ["https://mail.google.com/"],
    "oauth_provider": "google"           // only for type=oauth
  },
  "ttl": 600                             // optional, seconds, default 600
}

Response (201):
{
  "session_id": "a1b2c3d4...",           // SHA256(code), used for polling
  "code": "ABCD-1234",                   // human-readable, shown to user
  "url": "https://broker.example.com/connect/ABCD-1234",
  "expires_at": "2026-03-18T12:15:00Z"
}
```

#### 2. Poll Session Status

```
GET /v1/sessions/{session_id}

Response (200) — pending:
{
  "status": "pending",
  "expires_at": "2026-03-18T12:15:00Z"
}

Response (200) — ready:
{
  "status": "ready",
  "ciphertext": "<base64-encoded encrypted credentials>",
  "algorithm": "RSA-OAEP-256"
}

Response (410) — expired/consumed:
{
  "status": "expired"
}
```

#### 3. Complete Session (called by browser frontend)

```
POST /v1/sessions/{session_id}/complete

Request:
{
  "ciphertext": "<base64-encoded encrypted payload>"
}

Response (204): No content
```

#### 4. List Active Sessions (admin/debug)

```
GET /v1/sessions?status=pending

Response (200):
{
  "sessions": [
    { "session_id": "...", "credential_type": "oauth", "service": "gmail", "expires_at": "..." }
  ]
}
```

#### 5. Delete Session

```
DELETE /v1/sessions/{session_id}

Response (204): No content
```

---

## Database Schema

```sql
CREATE TABLE sessions (
    session_id      TEXT PRIMARY KEY,      -- SHA256(code)
    code_display    TEXT NOT NULL,          -- "ABCD-1234" (for UI display only)
    public_key      TEXT NOT NULL,          -- Agent's public key (PEM/base64)
    credential_type TEXT NOT NULL,          -- "oauth", "api_key", "basic_auth", "custom"
    meta            JSONB,                 -- Service name, scopes, OAuth config, etc.
    status          TEXT NOT NULL DEFAULT 'pending',  -- "pending", "ready", "consumed", "expired"
    ciphertext      BYTEA,                 -- Encrypted credentials (NULL until completed)
    algorithm       TEXT,                  -- "RSA-OAEP-256", "X25519-XSalsa20-Poly1305"
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ            -- Set on first retrieval, then deleted
);

CREATE INDEX idx_sessions_status ON sessions (status) WHERE status = 'pending';
CREATE INDEX idx_sessions_expires ON sessions (expires_at);
```

### Cleanup Job

```sql
-- Run every minute
DELETE FROM sessions
WHERE expires_at < NOW()
   OR (status = 'consumed' AND consumed_at < NOW() - INTERVAL '1 minute');
```

---

## Frontend (Browser UI)

The broker hosts a simple web UI at `/connect/{code}`.

### For API Keys / Passwords

```
┌────────────────────────────────────────┐
│  Connect to Gmail                       │
│                                         │
│  Confirmation Code: ABCD-1234          │
│  (verify this matches your agent)       │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │ Enter your API key:             │   │
│  │ [________________________]      │   │
│  └─────────────────────────────────┘   │
│                                         │
│         [Connect]                       │
└────────────────────────────────────────┘
```

On submit:
1. Browser fetches the session's `public_key` from API
2. Encrypts the entered value with `public_key` using Web Crypto API
3. POSTs `ciphertext` to `/sessions/{id}/complete`
4. Shows "Done! You can close this window."

### For OAuth

```
┌────────────────────────────────────────┐
│  Connect to Gmail                       │
│                                         │
│  Confirmation Code: ABCD-1234          │
│  (verify this matches your agent)       │
│                                         │
│  This will connect your Google account  │
│  with the following permissions:        │
│  - Read and send email                  │
│                                         │
│     [Sign in with Google]               │
└────────────────────────────────────────┘
```

OAuth flow:
1. User clicks "Sign in with Google"
2. Redirect to Google → consent → callback to broker
3. Broker receives OAuth tokens (access_token, refresh_token)
4. Broker encrypts tokens with agent's `public_key`
5. Stores ciphertext, sets status = "ready"
6. Shows "Done!"

---

## Agent SDK (Python)

### Usage

```python
from mcs_credential_broker import BrokerClient

broker = BrokerClient(url="https://broker.example.com/v1")

# Request credentials — returns URL + code for the user
session = broker.request_credential(
    credential_type="oauth",
    service="gmail",
    scopes=["https://mail.google.com/"],
)

# Show to user (via LLM, console, Telegram, etc.)
print(f"Please open {session.url} and verify code {session.code}")

# Poll until user completes (blocking, with timeout)
credentials = session.wait(timeout=300)

# Use the credentials
print(credentials["access_token"])
```

### As a CredentialProvider (MCS integration)

```python
from mcs_credential_broker import BrokerCredentialProvider
from mcs.auth.challenge import AuthChallenge

class BrokerCredentialProvider:
    """CredentialProvider backed by the Credential Broker."""

    def __init__(self, broker_url: str) -> None:
        self._client = BrokerClient(url=broker_url)
        self._tokens: dict[str, str] = {}
        self._pending: dict[str, Session] = {}

    def get_token(self, scope: str) -> str:
        # 1. Have cached token? Return it.
        if scope in self._tokens:
            return self._tokens[scope]

        # 2. Have pending session? Poll once.
        if scope in self._pending:
            session = self._pending[scope]
            result = session.poll()
            if result is not None:
                self._tokens[scope] = result["access_token"]
                del self._pending[scope]
                return self._tokens[scope]
            # Still pending
            raise AuthChallenge(
                f"Authentication pending for '{scope}'. "
                f"Please open {session.url} and verify code {session.code}",
                url=session.url,
                code=session.code,
                scope=scope,
            )

        # 3. Start new session
        session = self._client.request_credential(
            credential_type="oauth",
            service=scope,
        )
        self._pending[scope] = session
        raise AuthChallenge(
            f"Authentication required for '{scope}'. "
            f"Please open {session.url} and verify code {session.code}",
            url=session.url,
            code=session.code,
            scope=scope,
        )
```

### Integration with MCS AuthMixin

```python
from mcs.auth.mixin import AuthMixin
from mcs.driver.mail import MailDriver

class SecureMailDriver(AuthMixin, MailDriver):
    pass

# The AuthMixin catches AuthChallenge from get_token()
# and returns it as a tool result to the LLM.
# The LLM presents the URL + code to the user.
# On retry, the broker has the credentials.
driver = SecureMailDriver(
    read_adapter="gmail",
    send_adapter="gmail",
    read_kwargs={"_credential": BrokerCredentialProvider("https://broker.example.com/v1")},
    send_kwargs={"_credential": BrokerCredentialProvider("https://broker.example.com/v1")},
)
```

---

## OAuth Provider Configuration

The broker needs OAuth credentials for each supported provider. These are configured on the broker side, not by the agent.

```yaml
# broker-config.yaml
oauth_providers:
  google:
    client_id: "..."
    client_secret: "..."
    authorize_url: "https://accounts.google.com/o/oauth2/v2/auth"
    token_url: "https://oauth2.googleapis.com/token"
    default_scopes: ["openid", "email"]
    extra_params:
      access_type: "offline"
      prompt: "consent"

  slack:
    client_id: "..."
    client_secret: "..."
    authorize_url: "https://slack.com/oauth/v2/authorize"
    token_url: "https://slack.com/api/oauth.v2.access"

  github:
    client_id: "..."
    client_secret: "..."
    authorize_url: "https://github.com/login/oauth/authorize"
    token_url: "https://github.com/login/oauth/access_token"
```

The broker handles the callback (`/oauth/callback`), encrypts the tokens, and stores them. The agent never knows which OAuth provider was used.

---

## Technology Stack (Recommended)

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **API Server** | Python (FastAPI) or Go | Fast, async, easy to deploy |
| **Database** | PostgreSQL or SQLite | Sessions are short-lived, schema is simple |
| **Frontend** | Vanilla JS + HTML | Minimal, no framework needed, Web Crypto API for encryption |
| **Encryption** | RSA-OAEP (Web Crypto) or NaCl box (libsodium) | Browser-native, well-tested |
| **Deployment** | Docker single container | API + frontend + DB in one |
| **Agent SDK** | Python (first), TypeScript (later) | Matches MCS ecosystem |

---

## Deployment Modes

### 1. Self-Hosted (Docker)

```bash
docker run -p 8080:8080 \
  -e DATABASE_URL=sqlite:///data/broker.db \
  -v broker-data:/data \
  ghcr.io/modelcontextstandard/credential-broker
```

### 2. Cloud-Hosted (SaaS)

```
https://broker.modelcontextstandard.io/v1
```

Shared instance for quick testing. Agents create sessions, users connect. Zero infrastructure for the agent developer.

### 3. Embedded (Library Mode)

For local development — broker runs in-process:

```python
from mcs_credential_broker import EmbeddedBroker

broker = EmbeddedBroker(port=8080)  # starts local server
provider = BrokerCredentialProvider(broker.url)
```

---

## Comparison with Existing Solutions

| Feature | This Broker | Auth0 Token Vault | Composio | Scalekit | Peta |
|---------|------------|-------------------|----------|----------|------|
| No callback needed (agent side) | Yes | No | No | No | No |
| Zero-knowledge storage | Yes | No | No | No | Partial |
| Works with any credential type | Yes | OAuth only | OAuth + Keys | OAuth only | Keys only |
| Agent-agnostic (CLI, bot, web) | Yes | Web only | SDK required | SDK required | SDK required |
| Open source | Yes | No | Partial | No | No |
| Self-hostable | Yes | No | No | No | No |
| Device Flow UX (URL + code) | Yes | Partial | No | No | No |

---

## Project Structure

```
credential-broker/
├── broker/                    # Backend API (FastAPI)
│   ├── api.py                # REST endpoints
│   ├── models.py             # Database models
│   ├── crypto.py             # Encryption helpers
│   ├── oauth.py              # OAuth flow handler
│   └── config.py             # Provider configuration
├── frontend/                  # Browser UI
│   ├── index.html            # Connect page
│   ├── crypto.js             # Web Crypto encryption
│   └── oauth.html            # OAuth redirect handler
├── sdk/                       # Agent SDK
│   └── python/
│       └── mcs_credential_broker/
│           ├── client.py     # BrokerClient
│           ├── provider.py   # BrokerCredentialProvider (MCS integration)
│           └── crypto.py     # Local decryption
├── docker-compose.yml
├── Dockerfile
└── README.md
```

---

## MVP Scope (Hackathon / v0.1)

### Must Have
- [ ] API: POST /sessions, GET /sessions/:id, POST /sessions/:id/complete
- [ ] Frontend: Simple HTML page with code confirmation + API key input
- [ ] Encryption: RSA-OAEP via Web Crypto API (browser) + Python cryptography (agent)
- [ ] Python SDK: BrokerClient with request_credential() and poll()
- [ ] MCS integration: BrokerCredentialProvider implementing CredentialProvider Protocol
- [ ] SQLite storage with auto-expiry

### Nice to Have (v0.2)
- [ ] OAuth flow support (Google, GitHub, Slack)
- [ ] Docker single-container deployment
- [ ] Token refresh management (broker-side)
- [ ] Audit logging

### Future (v1.0)
- [ ] Multi-tenant support
- [ ] RBAC / scoped access policies
- [ ] TypeScript SDK
- [ ] Cloud-hosted SaaS instance
- [ ] Webhook notifications (instead of polling)
- [ ] Auth0 Token Vault integration as one of many backends
