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
git clone https://github.com/your-org/linkauth.git
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
If `callback_url` was provided, the broker POSTs to that URL when the session completes:
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

> **OAuth Caveat:** When the broker handles OAuth flows (Google, GitHub, etc.), it acts as the OAuth confidential client. The broker briefly sees the OAuth tokens in memory before encrypting them. This is an inherent limitation of OAuth -- the broker is trusted for OAuth flows but zero-knowledge for direct credential input.

For the full security architecture and threat model, see [concept.md](concept.md).

## Standards Compliance

LinkAuth is built on established IETF standards:

| Standard | Role in LinkAuth |
|----------|-----------------|
| [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) -- OAuth 2.0 Device Authorization Grant | Core inspiration for the URL + Code + Polling UX |
| [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) -- PKCS #1 (RSA-OAEP) | Asymmetric encryption for key wrapping |
| [RFC 5116](https://datatracker.ietf.org/doc/html/rfc5116) -- AES-GCM Authenticated Encryption | Symmetric encryption for credential payloads |
| [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) -- TLS 1.3 | Mandatory transport security |
| [RFC 9457](https://datatracker.ietf.org/doc/html/rfc9457) -- Problem Details for HTTP APIs | Structured API error responses |

### Emerging IETF Drafts (AI Agent Authorization)

The IETF is actively working on standards for AI agent authentication -- LinkAuth aligns with these emerging specifications:

- **draft-oauth-ai-agents-on-behalf-of-user** -- OAuth 2.0 Extension for AI agent delegation
- **draft-rosenberg-oauth-aauth** -- AAuth: Agentic Authorization OAuth 2.1 Extension
- **draft-klrc-aiagent-auth** -- AI Agent Authentication and Authorization

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
