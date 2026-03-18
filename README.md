# LinkAuth

> A zero-knowledge credential broker for autonomous AI agents.

AI agents need credentials (OAuth tokens, API keys, passwords) to access external services on behalf of users. Current solutions require callback endpoints, vendor lock-in, or manual setup. LinkAuth solves this with a Device-Flow-inspired UX and zero-knowledge architecture.

## How It Works

```
Agent                         Broker                          User (Browser)
──────                        ──────                          ──────────────
1. Generate RSA keypair
   (private key stays local)

2. POST /sessions
   { public_key, type, meta }
         ───────────────→     3. Create session
                                 code = "ABCD-1234"
                                 session_id = SHA256(code)
                              ←── { code, url, poll_token }

4. Show URL + code to user
   (via LLM, console, chat)
                                                              5. Open URL, verify code

                                                              6. Enter credentials
                                                                 (API key, password,
                                                                  or complete OAuth)

                                                              7. Browser encrypts with
                                                                 agent's public_key
                                                                 (Hybrid: RSA-OAEP + AES-256-GCM)

                              8. Store ciphertext           ←── POST /sessions/:id/complete
                                 status = "ready"

9. Poll: GET /sessions/:id
   Authorization: Bearer <poll_token>
         ───────────────→     10. Return { ciphertext }

11. Decrypt locally
    → plaintext credentials
```

### Key Properties

- **Zero Knowledge** — Broker stores only ciphertext encrypted with the agent's public key (Note: for OAuth flows, the broker acts as a confidential client and briefly handles tokens before encryption — see [concept.md](concept.md) for details)
- **No Callback Required** — URL + Code UX with polling; optional callback URL for agents that have an endpoint
- **Universal** — Works for OAuth tokens, API keys, passwords, certificates
- **Agent-Agnostic** — CLI, Telegram bot, web app, cron job, Docker container — all work
- **Decoupled** — Agent and user don't need to share a runtime, machine, or network

## Quick Start

LinkAuth is language-agnostic — any HTTP client works. No SDK required.

### 1. Create a Session

```bash
curl -X POST https://broker.example.com/v1/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "<base64-encoded RSA public key>",
    "template": "openai",
    "callback_url": "https://my-agent.example.com/credentials/ready"
  }'
```

Response:
```json
{
  "session_id": "a1b2c3d4...",
  "code": "ABCD-1234",
  "url": "https://broker.example.com/connect/ABCD-1234",
  "poll_token": "pt_...",
  "expires_at": "2026-03-18T12:15:00Z"
}
```

### 2. User Opens URL, Enters Credentials

The frontend renders the form based on the template — the user sees labeled input fields, enters their data, and the browser encrypts everything client-side before submitting.

### 3. Retrieve Result (Polling or Callback)

**Option A — Polling:**
```bash
curl https://broker.example.com/v1/sessions/a1b2c3d4... \
  -H "Authorization: Bearer pt_..."
```

**Option B — Callback:**
If `callback_url` was provided, the broker sends a POST to that URL when the session completes:
```json
{
  "session_id": "a1b2c3d4...",
  "status": "ready",
  "ciphertext": "<base64-encoded encrypted payload>"
}
```

## Credential Templates

Templates define which fields the frontend collects from the user. LinkAuth ships with built-in templates for common services and supports fully custom schemas.

### Built-in Templates

| Template | Fields | Use Case |
|----------|--------|----------|
| `openai` | `api_key` | OpenAI API access |
| `anthropic` | `api_key` | Anthropic API access |
| `aws` | `access_key_id`, `secret_access_key`, `region` | AWS programmatic access |
| `basic_auth` | `username`, `password` | Generic login credentials |
| `api_key` | `api_key` | Generic single API key |
| `oauth` | *(handled via OAuth flow)* | Google, GitHub, Slack, etc. |

Usage with a built-in template:
```json
{ "template": "openai", "public_key": "..." }
```

### Custom Schemas

For anything not covered by a built-in template, define fields inline:

```json
{
  "public_key": "...",
  "template": "custom",
  "display_name": "ACME Corp Login",
  "fields": [
    { "name": "company_id",  "label": "Company ID",        "type": "text",     "required": true },
    { "name": "user_id",     "label": "User ID",           "type": "text",     "required": true },
    { "name": "password",    "label": "Password",          "type": "password", "required": true },
    { "name": "auth_code",   "label": "2FA Code (if any)", "type": "text",     "required": false }
  ]
}
```

The frontend dynamically renders the form based on `fields`. Supported field types: `text`, `password`, `textarea`, `select`.

### Template Registry (Future)

Agents will be able to register reusable custom templates on the broker:

```
PUT /v1/templates/acme_login
{ "display_name": "ACME Corp Login", "fields": [...] }
```

Then use them like built-in templates: `{ "template": "acme_login" }`

## Encryption

LinkAuth uses **Hybrid Encryption** to avoid RSA-OAEP payload size limits:

1. Browser generates a random AES-256-GCM key
2. Credentials are encrypted with AES-256-GCM
3. The AES key is encrypted with the agent's RSA-OAEP public key
4. Both ciphertexts are sent to the broker as a single payload
5. Agent decrypts AES key with its private key, then decrypts credentials

This allows arbitrarily large payloads (OAuth tokens, certificates, etc.) while keeping the zero-knowledge property.

## Security

| Property | Implementation |
|----------|---------------|
| Broker never sees plaintext | Encryption happens client-side in the browser via Web Crypto API |
| Database breach is useless | Stored ciphertext requires agent's private key to decrypt |
| Sessions expire | TTL of 5–15 minutes, auto-cleanup |
| One-time use | Credentials retrieved once, then deleted |
| Polling is authenticated | `poll_token` required to retrieve session results |
| Rate-limited | Session creation is rate-limited per IP / API key |

> **OAuth Caveat:** When the broker handles OAuth flows (Google, GitHub, etc.), it acts as the OAuth confidential client. The broker briefly sees the OAuth tokens in memory before encrypting them. This is an inherent limitation of OAuth — the broker is trusted for OAuth flows but zero-knowledge for direct credential input.

For the full security architecture and threat model, see [concept.md](concept.md).

## Standards Compliance

LinkAuth is built on established IETF standards:

| Standard | Role in LinkAuth |
|----------|-----------------|
| [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) — OAuth 2.0 Device Authorization Grant | Core inspiration for the URL + Code + Polling UX |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) / [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) — OAuth 2.0 Framework & Bearer Tokens | Foundation for OAuth credential flows |
| [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) — PKCS #1 (RSA-OAEP) | Asymmetric encryption for key wrapping |
| [RFC 5116](https://datatracker.ietf.org/doc/html/rfc5116) — AES-GCM Authenticated Encryption | Symmetric encryption for credential payloads |
| [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) / [RFC 9325](https://datatracker.ietf.org/doc/html/rfc9325) — TLS 1.3 & Best Practices | Mandatory transport security (TLS 1.2+) |
| [RFC 9700](https://datatracker.ietf.org/doc/rfc9700/) — OAuth 2.0 Security Best Current Practice | Security baseline for all OAuth interactions |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) — PKCE | Anti-interception for OAuth code exchanges |
| [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) — DPoP (Proof of Possession) | Future: bind tokens to agent's keypair |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) / [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516) — JWK & JWE | Public key representation & encrypted token format |
| [RFC 9457](https://datatracker.ietf.org/doc/html/rfc9457) — Problem Details for HTTP APIs | Structured API error responses |
| [RFC 6585](https://datatracker.ietf.org/doc/html/rfc6585) — HTTP 429 Too Many Requests | Polling rate control (per RFC 8628 `slow_down`) |

### Emerging IETF Drafts (AI Agent Authorization)

The IETF is actively working on standards for AI agent authentication — LinkAuth aligns with these emerging specifications:

- **draft-oauth-ai-agents-on-behalf-of-user** — OAuth 2.0 Extension for AI agent delegation
- **draft-rosenberg-oauth-aauth** — AAuth: Agentic Authorization OAuth 2.1 Extension
- **draft-klrc-aiagent-auth** — AI Agent Authentication and Authorization
- **draft-ietf-httpapi-ratelimit-headers** — Standardized RateLimit headers for HTTP APIs

## Architecture

```
linkauth/
├── broker/                    # Backend API (FastAPI)
│   ├── api.py                # REST endpoints
│   ├── models.py             # Domain models (dataclasses, not ORM-bound)
│   ├── dao/                  # Data Access Object layer
│   │   ├── base.py           # Abstract DAO interfaces (SessionDAO, TemplateDAO)
│   │   ├── sqlite.py         # SQLite implementation (MVP default)
│   │   └── postgres.py       # PostgreSQL implementation (SaaS / multi-tenant)
│   ├── crypto.py             # Encryption helpers (server-side, for OAuth token encryption)
│   ├── oauth.py              # OAuth flow handler
│   ├── templates.py          # Built-in credential templates + custom schema validation
│   ├── callback.py           # Outbound callback delivery
│   └── config.py             # Provider, template & DAO configuration
├── frontend/                  # Browser UI (Vanilla JS + Web Crypto API)
│   ├── index.html            # Connect page (dynamic form rendering from template)
│   ├── crypto.js             # Hybrid encryption (RSA-OAEP + AES-256-GCM)
│   └── oauth.html            # OAuth redirect handler
├── docker-compose.yml
└── Dockerfile
```

### DAO Pattern

The data layer uses the **Data Access Object** pattern — all storage operations go through abstract interfaces, so the backing store can be swapped without touching business logic.

```
┌─────────────┐      ┌──────────────┐      ┌─────────────────┐
│   API Layer │─────→│   DAO Iface  │←─────│  SQLite (MVP)   │
│  (api.py)   │      │  (base.py)   │←─────│  PostgreSQL     │
│             │      │              │←─────│  DynamoDB       │
└─────────────┘      └──────────────┘      │  Redis          │
                                           │  ...            │
                                           └─────────────────┘
```

The DAO backend is selected via configuration:

```yaml
# config.yaml
storage:
  backend: "sqlite"               # or "postgres", "dynamodb", ...
  sqlite:
    path: "./data/broker.db"
  postgres:
    dsn: "postgresql://user:pass@host/linkauth"
```

## Deployment

```bash
docker run -p 8080:8080 \
  -e DATABASE_URL=sqlite:///data/broker.db \
  -v broker-data:/data \
  ghcr.io/linkauth/linkauth
```

## IETF Standardization

LinkAuth is not just a product — it aims to contribute to the emerging standards for AI agent authorization.

### Our Roadmap

1. **Participate** — Join the [OAuth Working Group](https://datatracker.ietf.org/wg/oauth/about/) mailing list and contribute to the active AI agent authorization drafts (draft-oauth-ai-agents-on-behalf-of-user, draft-rosenberg-oauth-aauth, draft-klrc-aiagent-auth)
2. **Demonstrate** — Present LinkAuth as running code at an [IETF Hackathon](https://www.ietf.org/how/runningcode/hackathons/) (held at every IETF meeting, remote participation possible)
3. **Formalize** — Submit an Internet-Draft: *"Zero-Knowledge Credential Brokering for Autonomous Agents"*, formalizing the LinkAuth protocol as an interoperable specification
4. **Standardize** — Work toward WG adoption within the OAuth or GNAP working groups

The IETF values *running code and rough consensus* ([RFC 7282](https://datatracker.ietf.org/doc/html/rfc7282)). A working implementation with an SDK is the strongest argument for a protocol proposal.

### Why This Matters

The AI agent ecosystem currently lacks a standard for credential delegation. Multiple independent drafts are being proposed simultaneously — this is the right moment to contribute a battle-tested approach. LinkAuth's zero-knowledge architecture and device-flow UX offer a unique perspective that complements the existing proposals.

## Status

LinkAuth is in early development. See [TODO.md](TODO.md) for the current roadmap and [concept.md](concept.md) for the full design document.

## License

AGPL-3.0 — see [LICENSE](LICENSE) for details.
