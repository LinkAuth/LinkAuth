# LinkAuth — TODO

## RFC Compliance

- [ ] **RFC 8628 (Device Flow)**: Implement polling behavior per spec — `slow_down` error, `interval` parameter, exponential backoff
- [ ] **RFC 8017 / RFC 5116**: Implement hybrid encryption per spec (RSA-OAEP-256 + AES-256-GCM), prevent nonce reuse
- [ ] **RFC 7517 (JWK)**: Exchange public keys in JWK format instead of raw base64-PEM
- [ ] **RFC 7516 (JWE)**: Format encrypted payload as JWE Compact Serialization (standardized instead of custom format)
- [ ] **RFC 9457 (Problem Details)**: Return API errors as `application/problem+json`
- [ ] **RFC 6585 (HTTP 429)**: Rate limiting with correct 429 status + `Retry-After` header
- [ ] **RFC 9700 (OAuth Security BCP)**: Review and implement all applicable recommendations
- [ ] **RFC 7636 (PKCE)**: PKCE mandatory for all OAuth code exchanges in the broker
- [ ] **RFC 9449 (DPoP)**: Evaluate binding tokens to agent keypair (v1.0)
- [ ] **RFC 8446 / RFC 9325 (TLS)**: TLS 1.2+ mandatory, TLS 1.3 preferred, document requirements
- [ ] **Track emerging drafts**: draft-oauth-ai-agents-on-behalf-of-user, draft-rosenberg-oauth-aauth, draft-klrc-aiagent-auth — evaluate upon RFC publication

## Open Design Decisions

- [ ] **Finalize cryptography**: Ed25519 is a signature algorithm, not suitable for encryption. Decision: RSA-OAEP + AES-256-GCM (Hybrid Encryption) as default. Alternative: X25519 + XSalsa20-Poly1305 (NaCl box). RSA-OAEP has the advantage of native Web Crypto API support.
- [ ] **RSA key size**: 2048-bit (faster) vs 4096-bit (more secure). Recommendation: 2048-bit is sufficient for short-lived session keys.
- [ ] **Document OAuth zero-knowledge caveat**: The broker sees OAuth tokens in plaintext before encrypting them. This is not zero-knowledge — must be clearly communicated. Evaluate alternatives (e.g., OAuth PKCE directly in browser, broker as relay only).

## Security & Hardening

- [ ] **Session authentication**: Return `poll_token` on `POST /sessions`, required as Bearer token for polling. Without this, anyone with the `session_id` can retrieve the ciphertext.
- [ ] **Rate limiting**: Limit session creation per IP and/or API key. Without this, the broker becomes a spam target.
- [ ] **Abuse prevention / anti-phishing**: The frontend `/connect/{code}` could be abused for phishing. Mitigations: domain trust, clear warnings, optionally display agent identification.
- [ ] **CORS & CSP**: Strict Content-Security-Policy for the connect page to prevent injected JS from intercepting credentials. Configure CORS correctly for frontend API calls.
- [ ] **Input validation**: Validate all API inputs (public_key format, credential_type enum, TTL boundaries).

## MVP (v0.1) — Broker + Frontend only, no SDK

- [ ] **DAO Layer** (Data Access Object Pattern)
  - [ ] `dao/base.py` — Abstract interfaces: `SessionDAO`, `TemplateDAO` (Protocol classes)
    - [ ] `SessionDAO`: `create()`, `get()`, `update_status()`, `store_ciphertext()`, `delete()`, `cleanup_expired()`
    - [ ] `TemplateDAO`: `get()`, `list()`, `register()` (for v0.2 Template Registry)
  - [ ] `dao/sqlite.py` — SQLite implementation as MVP default
  - [ ] DAO backend selectable via config (`storage.backend` in config.yaml)
  - [ ] Domain models in `models.py` as pure dataclasses (not ORM-bound)
- [ ] **Backend API** (FastAPI)
  - [ ] `POST /v1/sessions` — Create session with template reference or custom schema, return poll_token
  - [ ] `GET /v1/sessions/{session_id}` — Retrieve status/ciphertext (with poll_token auth)
  - [ ] `POST /v1/sessions/{session_id}/complete` — Store ciphertext
  - [ ] **Optional callback**: If `callback_url` provided at session creation, POST to that URL on completion
  - [ ] Session expiry: automatic cleanup via `SessionDAO.cleanup_expired()`
  - [ ] Rate limiting middleware
  - [ ] DAO injection via FastAPI Dependency Injection (`Depends`)
- [ ] **Credential Templates**
  - [ ] Built-in templates: `openai`, `anthropic`, `aws`, `basic_auth`, `api_key`
  - [ ] Custom schema support: client sends `fields` array with `name`, `label`, `type`, `required`
  - [ ] Field types: `text`, `password`, `textarea`, `select`
  - [ ] Template validation: schema validation for custom fields
- [ ] **Frontend** (Vanilla JS + Tailwind CSS via CDN)
  - [ ] **Two-step flow**: Step 1 = display code + user confirms, Step 2 = credential form
  - [ ] Connect page with code display
  - [ ] **Dynamic form rendering** from template/custom schema (fields, labels, types)
  - [ ] Hybrid encryption via Web Crypto API (RSA-OAEP + AES-256-GCM)
  - [ ] Strict CSP headers
- [ ] **End-to-end test**: curl → Broker → Browser → credentials back (no SDK needed)

## v0.2

- [ ] **OAuth flow support** (Google, GitHub, Slack)
  - [ ] OAuth provider config (broker-side)
  - [ ] `/oauth/callback` endpoint
  - [ ] Token encryption after OAuth callback
- [ ] **Template Registry**: `PUT /v1/templates/{name}` — register reusable custom templates on the broker
- [ ] **WebSocket/SSE instead of polling**: `GET /v1/sessions/{session_id}/events` for real-time updates
- [ ] **Callback security**: HMAC signature for callback requests, retry with backoff on failure
- [ ] **Code entry mode (high security)**: Configurable alternative flow — user must manually type the code instead of just confirming. Fully prevents phishing via manipulated links.
- [ ] **Docker single-container deployment**
- [ ] **Token refresh management** (broker-side, for OAuth)
- [ ] **Audit logging**
- [ ] **Python SDK**: BrokerClient with keypair generation, polling/callback handling, hybrid decryption
- [ ] **TypeScript SDK**

## IETF Engagement

- [ ] **Join OAuth WG mailing list**: https://www.ietf.org/mailman/listinfo/oauth — follow discussions, contribute to AI agent drafts
- [ ] **Review and comment on existing drafts**: draft-oauth-ai-agents-on-behalf-of-user, draft-rosenberg-oauth-aauth, draft-klrc-aiagent-auth — provide feedback from LinkAuth perspective
- [ ] **IETF Hackathon participation**: Identify next IETF meeting, prepare LinkAuth as running code demo (remote participation possible)
- [ ] **Write Internet-Draft**: "Zero-Knowledge Credential Brokering for Autonomous Agents" — formalize LinkAuth protocol as I-D. Format: xml2rfc, submit via https://datatracker.ietf.org
- [ ] **Create IETF Datatracker account**: Required for draft submission
- [ ] **Ensure interoperability**: Design protocol so other implementations (not just LinkAuth) can adopt it — clear separation of protocol vs. implementation

## v1.0

- [ ] **PostgreSQL DAO**: `dao/postgres.py` — for SaaS / multi-tenant (asyncpg or SQLAlchemy async)
- [ ] **Multi-tenant support**: Tenant ID in DAO layer, row-level isolation
- [ ] RBAC / scoped access policies
- [ ] Update concept.md: fix Ed25519 references, document hybrid encryption, add poll_token + templates + callback to API design
