# LinkAuth — TODO

## RFC Compliance

- [x] **RFC 8628 (Device Flow)**: Implement polling behavior per spec — `slow_down` error (429), `interval` parameter, configurable via `config.yaml`
- [x] **RFC 8017 / RFC 5116**: Hybrid encryption implemented (RSA-OAEP-256 + AES-256-GCM) in `crypto.js` (browser) and `basic_roundtrip.py` (Python)
- [ ] **RFC 7517 (JWK)**: Exchange public keys in JWK format instead of raw base64-DER
- [ ] **RFC 7516 (JWE)**: Format encrypted payload as JWE Compact Serialization (standardized instead of custom format)
- [x] **RFC 9457 (Problem Details)**: All API errors returned as `application/problem+json`
- [x] **RFC 6585 (HTTP 429)**: `slow_down` returns 429 with increased `interval` (per RFC 8628 §3.5)
- [ ] **RFC 9700 (OAuth Security BCP)**: Review and implement all applicable recommendations
- [ ] **RFC 7636 (PKCE)**: PKCE mandatory for all OAuth code exchanges in the broker
- [ ] **RFC 9449 (DPoP)**: Evaluate binding tokens to agent keypair (v1.0)
- [x] **RFC 8446 / RFC 9325 (TLS)**: TLS via reverse proxy (Caddy reference deployment), security banner when TLS not present, documented in README
- [x] **RFC 6797 (HSTS)**: HSTS header auto-added when TLS is detected via `X-Forwarded-Proto` or `base_url`
- [ ] **Track emerging drafts**: draft-oauth-ai-agents-on-behalf-of-user, draft-rosenberg-oauth-aauth, draft-klrc-aiagent-auth — evaluate upon RFC publication

## Open Design Decisions

- [x] **Finalize cryptography**: RSA-OAEP + AES-256-GCM (Hybrid Encryption) implemented. Uses Web Crypto API in browser, `cryptography` library in Python.
- [x] **RSA key size**: 2048-bit chosen — sufficient for short-lived session keys, universally supported.
- [x] **Document OAuth zero-knowledge caveat**: Documented in README Security section — broker sees OAuth tokens in plaintext before encrypting. Clearly communicated as inherent OAuth limitation.

## Security & Hardening

- [x] **Session authentication**: `poll_token` returned on `POST /sessions`, required as Bearer token for polling.
- [ ] **Rate limiting**: Limit session creation per IP and/or API key. Config exists (`rate_limit.max_sessions_per_minute`) but middleware not yet implemented.
- [ ] **Abuse prevention / anti-phishing**: The frontend `/connect/{code}` could be abused for phishing. Mitigations: domain trust, clear warnings, optionally display agent identification.
- [ ] **CORS & CSP**: Strict Content-Security-Policy for the connect page to prevent injected JS from intercepting credentials. CORS currently allows all origins — tighten for production.
- [ ] **Input validation**: Validate public_key format (valid base64, valid SPKI/DER), TTL boundaries. Currently accepts any string.
- [x] **TLS security banner**: Frontend shows yellow (localhost) or red (remote without TLS) banner. Documented E2E encryption guarantees and MITM JS-injection risk in README.

## MVP (v0.1) — Broker + Frontend only, no SDK

- [x] **DAO Layer** (Data Access Object Pattern)
  - [x] `dao/base.py` — Abstract interfaces: `SessionDAO`, `TemplateDAO`
    - [x] `SessionDAO`: `create()`, `get()`, `get_by_code()`, `update_status()`, `store_ciphertext()`, `consume()`, `delete()`, `cleanup_expired()`
    - [x] `TemplateDAO`: `get()`, `list()`, `register()`
  - [x] `dao/sqlite.py` — SQLite implementation as MVP default
  - [x] DAO backend selectable via config (`storage.backend` in config.yaml)
  - [x] Domain models in `models.py` as pure dataclasses (not ORM-bound)
- [x] **Backend API** (FastAPI)
  - [x] `POST /v1/sessions` — Create session with template reference or custom schema, return poll_token + interval
  - [x] `GET /v1/sessions/{session_id}` — Retrieve status/ciphertext (with poll_token auth, RFC 8628 slow_down)
  - [x] `POST /v1/connect/{code}/confirm` — User confirms code match
  - [x] `POST /v1/connect/{code}/complete` — Store ciphertext
  - [x] **Optional callback**: If `callback_url` provided at session creation, POST to that URL on completion
  - [x] Session expiry: automatic cleanup via background task + `SessionDAO.cleanup_expired()`
  - [ ] Rate limiting middleware (config exists, implementation pending)
  - [x] DAO injection via FastAPI Dependency Injection (`Depends`)
- [x] **Credential Templates**
  - [x] Built-in templates: `openai`, `anthropic`, `aws`, `basic_auth`, `api_key`
  - [x] Custom schema support: client sends `fields` array with `name`, `label`, `type`, `required`
  - [x] Field types: `text`, `password`, `textarea`, `select`
  - [x] Template resolution: built-in lookup + custom field validation
- [x] **Frontend** (Vanilla JS + Tailwind CSS via CDN)
  - [x] **Two-step flow**: Step 1 = display code + user confirms, Step 2 = credential form
  - [x] Connect page with code display
  - [x] **Dynamic form rendering** from template/custom schema (fields, labels, types)
  - [x] Hybrid encryption via Web Crypto API (RSA-OAEP + AES-256-GCM)
  - [x] TLS security banner (development/insecure modes)
  - [ ] Strict CSP headers
- [x] **End-to-end test**: `basic_roundtrip.py` + `agent_simulation.py` — full flow verified
- [x] **Examples**
  - [x] `basic_roundtrip.py` — Automated E2E test (no user interaction)
  - [x] `agent_simulation.py` — Interactive mock-LLM agent with real broker flow (rich UI)

## v0.2

- [ ] **OAuth flow support** (Google, GitHub, Slack)
  - [ ] OAuth provider config (broker-side)
  - [ ] `/oauth/callback` endpoint
  - [ ] Token encryption after OAuth callback
- [ ] **Template Registry**: `PUT /v1/templates/{name}` — register reusable custom templates on the broker
- [ ] **WebSocket/SSE instead of polling**: `GET /v1/sessions/{session_id}/events` for real-time updates
- [ ] **Callback security**: HMAC signature for callback requests, retry with backoff on failure
- [ ] **Code entry mode (high security)**: Configurable alternative flow — user must manually type the code instead of just confirming. Fully prevents phishing via manipulated links.
- [ ] **Docker deployment**: Single-container with Caddy reverse proxy (TLS 1.3, automatic Let's Encrypt)
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
