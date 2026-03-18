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
- **No Callback Needed** — URL + Code UX, no web server required on agent side
- **Universal** — Works for OAuth tokens, API keys, passwords, certificates
- **Agent-Agnostic** — CLI, Telegram bot, web app, cron job, Docker container — all work
- **Decoupled** — Agent and user don't need to share a runtime, machine, or network

## Quick Start

### Python SDK

```python
from linkauth import BrokerClient

broker = BrokerClient(url="https://broker.example.com/v1")

# Request credentials — returns URL + code for the user
session = broker.request_credential(
    credential_type="api_key",
    service="openai",
    display_name="OpenAI API Key",
)

# Show to user (via LLM, console, Telegram, etc.)
print(f"Please open {session.url} and verify code {session.code}")

# Wait until user completes (blocking, with timeout)
credentials = session.wait(timeout=300)

print(credentials["api_key"])
```

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

## Architecture

```
linkauth/
├── broker/                    # Backend API (FastAPI + SQLite)
│   ├── api.py                # REST endpoints
│   ├── models.py             # Database models
│   ├── crypto.py             # Encryption helpers
│   ├── oauth.py              # OAuth flow handler
│   └── config.py             # Provider configuration
├── frontend/                  # Browser UI (Vanilla JS + Web Crypto API)
│   ├── index.html            # Connect page
│   ├── crypto.js             # Hybrid encryption (RSA-OAEP + AES-256-GCM)
│   └── oauth.html            # OAuth redirect handler
├── sdk/                       # Agent SDKs
│   └── python/
│       └── linkauth/
│           ├── client.py     # BrokerClient
│           ├── provider.py   # CredentialProvider integration
│           └── crypto.py     # Local decryption
├── docker-compose.yml
└── Dockerfile
```

## Deployment

```bash
# Self-hosted (Docker)
docker run -p 8080:8080 \
  -e DATABASE_URL=sqlite:///data/broker.db \
  -v broker-data:/data \
  ghcr.io/linkauth/linkauth

# Embedded (local development)
from linkauth import EmbeddedBroker
broker = EmbeddedBroker(port=8080)
```

## Status

LinkAuth is in early development. See [TODO.md](TODO.md) for the current roadmap and [concept.md](concept.md) for the full design document.

## License

AGPL-3.0 — see [LICENSE](LICENSE) for details.
