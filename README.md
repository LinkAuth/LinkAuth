# LinkAuth

> A zero-knowledge credential broker for autonomous AI agents.

AI agents need credentials (OAuth tokens, API keys, passwords) to access external services on behalf of users. Current solutions require callback endpoints, vendor lock-in, or manual setup. LinkAuth solves this with a Device-Flow-inspired UX and zero-knowledge architecture.

## How It Works

```
Agent                         Broker                          User (Browser)
------                        ------                          --------------
1. Generate RSA keypair
   (private key stays local)

2. POST /sessions
   { public_key, type, meta }
         --------------->     3. Create session
                                 code = "ABCD-1234"
                                 session_id = SHA256(code)
                              <-- { code, url, poll_token }

4. Show URL + code to user
   (via LLM, console, chat)
                                                              5. Open URL, verify code

                                                              6. Enter credentials
                                                                 (API key, password,
                                                                  or complete OAuth)

                                                              7. Browser encrypts with
                                                                 agent's public_key
                                                                 (Hybrid: RSA-OAEP + AES-256-GCM)

                              8. Store ciphertext           <-- POST /sessions/:id/complete
                                 status = "ready"

9. Poll: GET /sessions/:id
   Authorization: Bearer <poll_token>
         --------------->     10. Return { ciphertext }

11. Decrypt locally
    -> plaintext credentials
```

### Key Properties

- **Zero Knowledge** -- Broker stores only ciphertext encrypted with the agent's public key (Note: for OAuth flows, the broker acts as a confidential client and briefly handles tokens before encryption -- see [concept.md](concept.md) for details)
- **No Callback Required** -- URL + Code UX with polling; optional callback URL for agents that have an endpoint
- **Universal** -- Works for OAuth tokens, API keys, passwords, certificates
- **Agent-Agnostic** -- CLI, Telegram bot, web app, cron job, Docker container -- all work
- **Decoupled** -- Agent and user don't need to share a runtime, machine, or network

## Quick Start -- Try It Yourself

Experience the full flow in under 2 minutes. The included agent simulation uses a mock LLM but the credential flow is **100% real**.

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### 1. Install & Start the Broker

```bash
git clone https://github.com/LinkAuth/LinkAuth.git
cd linkauth
uv sync --all-extras

# Start the broker (Terminal 1)
$env:PYTHONPATH="src"; python -m uvicorn broker.main:app --port 8080   # PowerShell
PYTHONPATH=src python -m uvicorn broker.main:app --port 8080           # Bash/Linux/Mac
```

The broker is now running at `http://localhost:8080` ([Swagger UI](http://localhost:8080/docs)).

### 2. Run the Agent Simulation

```bash
# In a second terminal
python examples/agent_simulation.py
```

### 3. Walk Through the Flow

Type anything -- the mock LLM pretends you asked for your emails and calls the `imap_read` tool:

```
You: Show me my last 5 emails

+- DriverResponse ------------------------------------------------+
| call_executed=True  call_failed=False                           |
| tool: imap_read(count=5)  action: calling                       |
+-----------------------------------------------------------------+

Assistant: I need authentication to access your emails.
          Please open this link:

          -> http://localhost:8080/connect/ABCD-1234

          and confirm the code ABCD-1234.
```

Now open the link in your browser:

1. **Step 1** -- You see the confirmation code `ABCD-1234`. Verify it matches what the agent displayed and click "I Confirm".
2. **Step 2** -- Enter any credentials (e.g. username + password). The browser encrypts them client-side before submitting.

Back in the terminal, type anything again:

```
You: Ok done, fetch my emails now

+-----------------------------------------------------------------+
| call_executed=True  call_failed=False                           |
| tool: imap_read(count=5)  action: retrying                      |
+-----------------------------------------------------------------+
Assistant: Here are your last 5 emails (Account: you@example.com):

 #  Date         From                     Subject
 1  2026-03-18   alice@example.com        Meeting tomorrow at 10am
 2  2026-03-17   bob@corp.de              Invoice #4521 attached
 3  2026-03-17   newsletter@dev.to        Top 10 Python tips this week
 4  2026-03-16   charlie@startup.io       Re: API integration questions
 5  2026-03-15   hr@company.com           Updated vacation policy

+-----------------------------------------------------------------+
| Roundtrip complete!                                             |
| The broker never saw your credentials in plaintext.             |
+-----------------------------------------------------------------+
```

The broker stored only ciphertext. Your credentials were encrypted in the browser and decrypted by the agent.

## API Reference

LinkAuth is language-agnostic -- any HTTP client works. No SDK required.

### Create a Session

```bash
curl -X POST http://localhost:8080/v1/sessions \
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
  "url": "http://localhost:8080/connect/ABCD-1234",
  "poll_token": "pt_...",
  "expires_at": "2026-03-18T12:15:00Z"
}
```

### Retrieve Result (Polling or Callback)

**Option A -- Polling:**
```bash
curl http://localhost:8080/v1/sessions/a1b2c3d4... \
  -H "Authorization: Bearer pt_..."
```

**Option B -- Callback:**
If `callback_url` was provided, the broker POSTs to that URL when the session completes. The response to `POST /sessions` includes a `callback_secret` for verifying the signature.

```json
{
  "session_id": "a1b2c3d4...",
  "status": "ready",
  "ciphertext": "<base64-encoded encrypted payload>",
  "algorithm": "RSA-OAEP-256+AES-256-GCM"
}
```

The callback includes authentication headers:
- `X-LinkAuth-Signature: sha256=<hmac>` -- HMAC-SHA256 over the JSON body, keyed with `callback_secret`
- `X-LinkAuth-Delivery-Id: <uuid>` -- idempotent delivery identifier (same across retries)

Delivery is retried up to 3 times with exponential backoff (1s, 4s) on 5xx errors. Non-5xx errors are not retried. `callback_url` must use HTTPS (HTTP is allowed only for `localhost`).

### HTTP Proxy for Sandboxed Agents

Agents running in sandboxed environments (Docker, CLI, serverless) often cannot make direct outbound HTTP calls or receive callbacks. The broker provides a generic HTTP proxy endpoint that lets agents route arbitrary requests through the broker.

```bash
curl -X POST http://localhost:8080/v1/proxy \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-api-key>" \
  -d '{
    "method": "POST",
    "url": "https://accounts.google.com/o/oauth2/token",
    "headers": { "Authorization": "Bearer <token>" },
    "body": "{\"grant_type\": \"refresh_token\", \"refresh_token\": \"...\"}",
    "timeout": 30
  }'
```

Response:
```json
{
  "status_code": 200,
  "headers": { "content-type": "application/json" },
  "body": "{\"access_token\": \"ya29...\", \"expires_in\": 3600}"
}
```

The proxy is provider-agnostic -- any outbound HTTP call the agent cannot make directly can be routed through it:

| Use Case | Method | Target |
|----------|--------|--------|
| **Auth0 Connected Accounts** | `POST` | `/me/v1/connected-accounts/connect` |
| **Microsoft Entra OBO** | `POST` | Token endpoint with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` |
| **Salesforce JWT Bearer** | `POST` | Token endpoint with signed JWT assertion |
| **Token Refresh** | `POST` | Any OAuth token endpoint with `grant_type=refresh_token` |
| **Webhook Registration** | `POST` | External API to register a callback URL |

An optional domain allowlist restricts which hosts the proxy can reach:

```yaml
proxy:
  enabled: true
  allowed_domains:
    - "*.auth0.com"
    - "login.microsoftonline.com"
    - "accounts.google.com"
    - "login.salesforce.com"
```

An empty list means all domains are allowed (suitable for trusted single-tenant deployments).

#### SSRF Protection

The proxy uses [drawbridge](https://github.com/tachyon-oss/drawbridge) for transport-layer SSRF protection. DNS resolution is performed once and the resulting IP is pinned for the connection, eliminating the validate-then-fetch gap that enables DNS rebinding attacks.

- **Private IPs blocked by default** -- requests to `127.0.0.1`, `10.x.x.x`, `169.254.x.x`, etc. are rejected
- **No redirect following** -- `max_redirects=0` prevents open-redirect chains into internal networks
- **Configurable** -- set `proxy.allow_private_ips: true` in `config.yaml` for local development

### Webhook Relay (Ephemeral)

Some workflows require external services to push events *to* the agent (e.g. a Stripe payment confirmation or an OAuth callback from Auth0 Connected Accounts). Agents in sandboxed environments have no public URL to receive these events.

The webhook relay gives each session a short-lived inbound endpoint that external services can POST to. The payload is encrypted with the agent's public key and stored for retrieval via polling.

**Scope:** This is an *ephemeral* relay — it shares the session's TTL (max 15 minutes) and is designed for short-lived callback flows, not long-lived webhook subscriptions.

#### Full Workflow Example

**Step 1 — Agent creates a session with webhook enabled:**
```bash
curl -X POST http://localhost:8080/v1/sessions \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-api-key>" \
  -d '{
    "public_key": "<base64-encoded RSA public key>",
    "template": "custom",
    "display_name": "Stripe Payment",
    "fields": [{ "name": "status", "label": "Status", "type": "text" }],
    "enable_webhook": true
  }'
```

Response includes `webhook_url`:
```json
{
  "session_id": "a1b2c3d4...",
  "code": "ABCD-1234",
  "url": "http://localhost:8080/connect/ABCD-1234",
  "poll_token": "pt_...",
  "webhook_url": "http://localhost:8080/v1/sessions/a1b2c3d4.../webhook?token=wt_...",
  "expires_at": "2026-03-27T12:15:00Z"
}
```

**Step 2 — Agent registers the webhook URL with a third-party service** (via the proxy if needed):
```bash
curl -X POST http://localhost:8080/v1/proxy \
  -H "X-API-Key: <your-api-key>" \
  -d '{
    "method": "POST",
    "url": "https://api.stripe.com/v1/webhook_endpoints",
    "headers": { "Authorization": "Bearer sk_..." },
    "body": "{\"url\": \"http://localhost:8080/v1/sessions/a1b2c3d4.../webhook?token=wt_...\", \"enabled_events\": [\"payment_intent.succeeded\"]}"
  }'
```

**Step 3 — External service POSTs to the webhook URL:**
```bash
# Stripe (or any external service) sends the event:
curl -X POST "http://localhost:8080/v1/sessions/a1b2c3d4.../webhook?token=wt_..." \
  -H "Content-Type: application/json" \
  -d '{"type": "payment_intent.succeeded", "data": {"id": "pi_123"}}'
```

The broker encrypts the payload with the agent's public key and stores it.

**Step 4 — Agent polls for the result:**
```bash
curl http://localhost:8080/v1/sessions/a1b2c3d4... \
  -H "Authorization: Bearer pt_..."
```

Returns the encrypted webhook payload, which the agent decrypts locally.

#### Security

- **Auto-generated token** -- The `webhook_token` (prefixed `wt_`) is generated by the broker and included in the URL. It is never transmitted separately.
- **Constant-time comparison** -- Token validation uses `hmac.compare_digest` to prevent timing attacks.
- **Payload size limit** -- Default 64 KB (`sessions.max_webhook_payload` in config). Returns 413 if exceeded.
- **E2E encryption** -- Webhook payloads are encrypted with the agent's public key before storage.
- **Ephemeral** -- The endpoint expires with the session (max 15 min TTL).

> **Note:** For long-lived webhook subscriptions with persistent storage, a separate Webhook Inbox feature is planned for a future release.

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
| Sessions expire | TTL of 5-15 minutes, auto-cleanup |
| One-time use | Credentials retrieved once, then deleted |
| Polling is authenticated | `poll_token` required to retrieve session results |
| Rate-limited | Session creation is rate-limited per IP / API key |
| Proxy SSRF protection | DNS pinned at transport layer via drawbridge, private IPs blocked by default |
| Callback authentication | HMAC-SHA256 signed with `callback_secret`, retry with exponential backoff, idempotent delivery ID |
| Webhook relay | E2E encrypted, auto-generated webhook token, payload size limited (64 KB default) |

> **OAuth Caveat:** When the broker handles OAuth flows (Google, GitHub, etc.), it acts as the OAuth confidential client. The broker briefly sees the OAuth tokens in memory before encrypting them. This is an inherent limitation of OAuth -- the broker is trusted for OAuth flows but zero-knowledge for direct credential input.

### TLS and End-to-End Encryption

Credentials are end-to-end encrypted even without TLS -- the browser encrypts with the agent's public key before anything leaves the page. A network observer only sees ciphertext that is useless without the agent's private key.

**However, TLS is still required in production** to guarantee the integrity of the encryption code itself. Without TLS, a man-in-the-middle could replace `crypto.js` with a malicious version that exfiltrates credentials in plaintext before encryption. TLS prevents this by ensuring the frontend code is delivered unmodified.

| Scenario | Credentials safe? | Why |
|----------|:-:|-----|
| HTTPS (production) | Yes | E2E encryption + code integrity guaranteed |
| HTTP on localhost | Yes | E2E encryption, no network MITM possible |
| HTTP on remote host | **No** | E2E encryption present, but attacker could replace the JS that performs it |

The frontend displays a security banner when TLS is not active:
- **Yellow** (localhost) -- "Development mode" reminder
- **Red** (remote without TLS) -- "Connection is not encrypted" warning, blocks real credential entry

For the full security architecture and threat model, see [concept.md](concept.md).

## Standards Compliance

LinkAuth is built on established IETF standards:

| Standard | Role in LinkAuth | Status |
|----------|-----------------|--------|
| [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) -- OAuth 2.0 Device Authorization Grant | URL + Code + Polling UX, `interval` hint, `slow_down` (429) error | Implemented |
| [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) -- PKCS #1 (RSA-OAEP) | Asymmetric encryption for AES key wrapping | Implemented |
| [RFC 5116](https://datatracker.ietf.org/doc/html/rfc5116) -- AES-GCM Authenticated Encryption | Symmetric encryption for credential payloads | Implemented |
| [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) -- OAuth 2.0 Bearer Token Usage | Session poll tokens issued and verified as Bearer tokens | Implemented |
| [RFC 9457](https://datatracker.ietf.org/doc/html/rfc9457) -- Problem Details for HTTP APIs | All API errors returned as `application/problem+json` | Implemented |
| [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) -- TLS 1.3 | Transport security via reverse proxy (Caddy), HSTS header | Via deployment |
| [RFC 6797](https://datatracker.ietf.org/doc/html/rfc6797) -- HTTP Strict Transport Security | HSTS header auto-added when TLS is detected | Implemented |

> **Note on TLS:** LinkAuth itself is an application server -- it does not terminate TLS directly. TLS 1.3 is enforced via the reference deployment (Caddy reverse proxy with automatic Let's Encrypt). The application detects TLS status and adds HSTS headers when running behind a TLS-terminating proxy. A security banner warns users when TLS is not present.

### Emerging IETF Drafts (AI Agent Authorization)

The IETF is actively working on standards for AI agent authentication -- LinkAuth aligns with these emerging specifications:

- **draft-klrc-aiagent-auth** (2026-03) -- AI Agent Authentication and Authorization. Authors from AWS, Zscaler, Ping Identity. Builds on the WIMSE framework.
- **draft-rosenberg-oauth-aauth** -- AAuth: Agentic Authorization OAuth 2.1 Extension

## Architecture

```
src/
+-- broker/                    # Backend API (FastAPI)
|   +-- main.py               # App entry point + lifespan
|   +-- api.py                # REST endpoints
|   +-- models.py             # Domain models (pure dataclasses)
|   +-- dao/                  # Data Access Object layer
|   |   +-- base.py           # Abstract DAO interfaces
|   |   +-- sqlite.py         # SQLite implementation (MVP)
|   +-- templates.py          # Built-in + custom credential templates
|   +-- callback.py           # Outbound callback delivery
|   +-- config.py             # Configuration loading
+-- frontend/                  # Browser UI (Vanilla JS + Tailwind CSS)
|   +-- index.html            # Connect page (two-step flow)
|   +-- crypto.js             # Hybrid encryption (RSA-OAEP + AES-256-GCM)
+-- tests/
```

### DAO Pattern

The data layer uses the **Data Access Object** pattern -- all storage operations go through abstract interfaces, so the backing store can be swapped without touching business logic.

```
+-------------+      +--------------+      +-----------------+
|  API Layer  |----->|  DAO Iface   |<-----|  SQLite (MVP)   |
|  (api.py)   |      |  (base.py)   |<-----|  PostgreSQL     |
|             |      |              |<-----|  DynamoDB       |
+-------------+      +--------------+      +-----------------+
```

## Configuration

Settings are loaded from `config.yaml` in the project root:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  base_url: "http://localhost:8080"   # used to generate connect URLs

storage:
  backend: "sqlite"                    # swappable via DAO pattern
  sqlite:
    path: "./data/broker.db"

sessions:
  default_ttl: 600                     # session lifetime in seconds
  max_ttl: 900
  cleanup_interval: 60                 # expired session cleanup interval

proxy:
  enabled: true                        # HTTP proxy for sandboxed agents
  allowed_domains: []                  # empty = allow all (single-tenant)
  default_timeout: 30
  max_timeout: 60
```

## IETF Standardization

LinkAuth is not just a product -- it aims to contribute to the emerging standards for AI agent authorization.

1. **Participate** -- Join the [OAuth Working Group](https://datatracker.ietf.org/wg/oauth/about/) mailing list and contribute to the active AI agent authorization drafts
2. **Demonstrate** -- Present LinkAuth as running code at an [IETF Hackathon](https://www.ietf.org/how/runningcode/hackathons/)
3. **Formalize** -- Submit an Internet-Draft: *"Zero-Knowledge Credential Brokering for Autonomous Agents"*
4. **Standardize** -- Work toward WG adoption within the OAuth or GNAP working groups

The IETF values *running code and rough consensus* ([RFC 7282](https://datatracker.ietf.org/doc/html/rfc7282)). A working implementation is the strongest argument for a protocol proposal.

## Status

LinkAuth is in early development. See [TODO.md](TODO.md) for the current roadmap and [concept.md](concept.md) for the full design document.

## License

Apache 2.0 -- see [LICENSE](LICENSE) for details.
