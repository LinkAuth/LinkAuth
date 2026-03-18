# LinkAuth — TODO

## RFC Compliance

- [ ] **RFC 8628 (Device Flow)**: Polling-Verhalten gemäß Spec implementieren — `slow_down` Error, `interval`-Parameter, exponential backoff
- [ ] **RFC 8017 / RFC 5116**: Hybrid Encryption korrekt nach Spec (RSA-OAEP-256 + AES-256-GCM), Nonce-Reuse verhindern
- [ ] **RFC 7517 (JWK)**: Public Keys im JWK-Format austauschen statt raw base64-PEM
- [ ] **RFC 7516 (JWE)**: Encrypted Payload als JWE-Compact-Serialization formatieren (standardisiert statt custom Format)
- [ ] **RFC 9457 (Problem Details)**: API-Errors als `application/problem+json` zurückgeben
- [ ] **RFC 6585 (HTTP 429)**: Rate Limiting mit korrektem 429-Status + `Retry-After` Header
- [ ] **RFC 9700 (OAuth Security BCP)**: Alle anwendbaren Empfehlungen prüfen und umsetzen
- [ ] **RFC 7636 (PKCE)**: PKCE mandatory für alle OAuth-Code-Exchanges im Broker
- [ ] **RFC 9449 (DPoP)**: Evaluieren ob Tokens an Agent-Keypair gebunden werden können (v1.0)
- [ ] **RFC 8446 / RFC 9325 (TLS)**: TLS 1.2+ mandatory, TLS 1.3 bevorzugt, dokumentieren
- [ ] **Emerging Drafts tracken**: draft-oauth-ai-agents-on-behalf-of-user, draft-rosenberg-oauth-aauth, draft-klrc-aiagent-auth — bei Veröffentlichung als RFC evaluieren

## Open Design Decisions

- [ ] **Kryptographie finalisieren**: Ed25519 ist ein Signatur-Algorithmus, nicht für Encryption geeignet. Entscheidung: RSA-OAEP + AES-256-GCM (Hybrid Encryption) als Standard. Alternativ: X25519 + XSalsa20-Poly1305 (NaCl box). RSA-OAEP hat den Vorteil nativer Web Crypto API Unterstützung.
- [ ] **RSA Key Size festlegen**: 2048-bit (schneller) vs 4096-bit (sicherer). Empfehlung: 2048-bit reicht für kurzlebige Session-Keys.
- [ ] **OAuth Zero-Knowledge Caveat dokumentieren**: Bei OAuth sieht der Broker die Tokens im Plaintext bevor er sie verschlüsselt. Das ist kein Zero-Knowledge — muss klar kommuniziert werden. Alternativen evaluieren (z.B. OAuth PKCE direkt im Browser, Broker nur als Relay).

## Security & Hardening

- [ ] **Session-Authentifizierung**: `poll_token` beim `POST /sessions` zurückgeben, das beim Polling als Bearer-Token mitgeschickt wird. Ohne das kann jeder mit der `session_id` den Ciphertext abrufen.
- [ ] **Rate Limiting**: Session-Erstellung pro IP und/oder API-Key begrenzen. Ohne das wird der Broker zum Spam-Target.
- [ ] **Abuse Prevention / Anti-Phishing**: Das Frontend `/connect/{code}` könnte für Phishing missbraucht werden. Maßnahmen: Domain-Trust, klare Warnhinweise, ggf. Agent-Identifikation anzeigen.
- [ ] **CORS & CSP**: Strikte Content-Security-Policy für die Connect-Page, damit kein injiziertes JS die Credentials abfangen kann. CORS korrekt konfigurieren für API-Aufrufe vom Frontend.
- [ ] **Input Validation**: Alle API-Inputs validieren (public_key Format, credential_type enum, TTL-Grenzen).

## MVP (v0.1) — Broker + Frontend only, kein SDK

- [ ] **DAO Layer** (Data Access Object Pattern)
  - [ ] `dao/base.py` — Abstrakte Interfaces: `SessionDAO`, `TemplateDAO` (Protocol-Klassen)
    - [ ] `SessionDAO`: `create()`, `get()`, `update_status()`, `store_ciphertext()`, `delete()`, `cleanup_expired()`
    - [ ] `TemplateDAO`: `get()`, `list()`, `register()` (für v0.2 Template Registry)
  - [ ] `dao/sqlite.py` — SQLite-Implementierung als MVP-Default
  - [ ] DAO-Backend per Config auswählbar (`storage.backend` in config.yaml)
  - [ ] Domain Models in `models.py` als reine Dataclasses (nicht ORM-gebunden)
- [ ] **Backend API** (FastAPI)
  - [ ] `POST /v1/sessions` — Session erstellen mit Template-Referenz oder Custom-Schema, poll_token zurückgeben
  - [ ] `GET /v1/sessions/{session_id}` — Status/Ciphertext abrufen (mit poll_token Auth)
  - [ ] `POST /v1/sessions/{session_id}/complete` — Ciphertext speichern
  - [ ] **Optionaler Callback**: Wenn `callback_url` bei Session-Erstellung mitgegeben, POST an diese URL bei Completion
  - [ ] Session-Expiry: automatisches Cleanup via `SessionDAO.cleanup_expired()`
  - [ ] Rate Limiting Middleware
  - [ ] DAO-Injection via FastAPI Dependency Injection (`Depends`)
- [ ] **Credential Templates**
  - [ ] Built-in Templates: `openai`, `anthropic`, `aws`, `basic_auth`, `api_key`
  - [ ] Custom Schema Support: Client sendet `fields`-Array mit `name`, `label`, `type`, `required`
  - [ ] Feldtypen: `text`, `password`, `textarea`, `select`
  - [ ] Template-Validierung: Schema-Validation für Custom Fields
- [ ] **Frontend** (Vanilla HTML/JS)
  - [ ] Connect-Page mit Code-Anzeige
  - [ ] **Dynamisches Form-Rendering** aus Template/Custom-Schema (Felder, Labels, Typen)
  - [ ] Hybrid Encryption via Web Crypto API (RSA-OAEP + AES-256-GCM)
  - [ ] Strikte CSP-Header
- [ ] **End-to-End Test**: curl → Broker → Browser → Credentials zurück (kein SDK nötig)

## v0.2

- [ ] **OAuth Flow Support** (Google, GitHub, Slack)
  - [ ] OAuth Provider Config (broker-seitig)
  - [ ] `/oauth/callback` Endpoint
  - [ ] Token-Encryption nach OAuth-Callback
- [ ] **Template Registry**: `PUT /v1/templates/{name}` — Wiederverwendbare Custom Templates auf dem Broker registrieren
- [ ] **WebSocket/SSE statt Polling**: `GET /v1/sessions/{session_id}/events` für Real-Time-Updates
- [ ] **Callback Security**: HMAC-Signatur für Callback-Requests, Retry mit Backoff bei Fehler
- [ ] **Docker Single-Container Deployment**
- [ ] **Token Refresh Management** (broker-seitig, für OAuth)
- [ ] **Audit Logging**
- [ ] **Python SDK**: BrokerClient mit Keypair-Generierung, Polling/Callback-Handling, Hybrid-Decryption
- [ ] **TypeScript SDK**

## IETF Engagement

- [ ] **OAuth WG Mailing-Liste beitreten**: https://www.ietf.org/mailman/listinfo/oauth — Diskussionen verfolgen, bei AI-Agent-Drafts mitdiskutieren
- [ ] **Bestehende Drafts reviewen und kommentieren**: draft-oauth-ai-agents-on-behalf-of-user, draft-rosenberg-oauth-aauth, draft-klrc-aiagent-auth — Feedback aus LinkAuth-Perspektive geben
- [ ] **IETF Hackathon Teilnahme**: Nächstes IETF-Meeting identifizieren, LinkAuth als Running-Code-Demo vorbereiten (remote möglich)
- [ ] **Internet-Draft verfassen**: "Zero-Knowledge Credential Brokering for Autonomous Agents" — LinkAuth-Protokoll als I-D formalisieren. Format: xml2rfc, Einreichung via https://datatracker.ietf.org
- [ ] **IETF Datatracker Account erstellen**: Voraussetzung für Draft-Einreichung
- [ ] **Interoperabilität sicherstellen**: Protokoll so designen, dass andere Implementierungen (nicht nur LinkAuth) es umsetzen können — klare Trennung Protokoll vs. Implementierung

## v1.0

- [ ] **PostgreSQL DAO**: `dao/postgres.py` — für SaaS/Multi-Tenant (asyncpg oder SQLAlchemy async)
- [ ] **Multi-Tenant Support**: Tenant-ID im DAO-Layer, Row-Level Isolation
- [ ] RBAC / Scoped Access Policies
- [ ] concept.md aktualisieren: Ed25519-Referenzen korrigieren, Hybrid Encryption dokumentieren, poll_token + Templates + Callback in API-Design aufnehmen
