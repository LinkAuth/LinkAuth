# LinkAuth — TODO

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

## MVP (v0.1)

- [ ] **Backend API** (FastAPI + SQLite)
  - [ ] `POST /v1/sessions` — Session erstellen, poll_token zurückgeben
  - [ ] `GET /v1/sessions/{session_id}` — Status/Ciphertext abrufen (mit poll_token Auth)
  - [ ] `POST /v1/sessions/{session_id}/complete` — Ciphertext speichern
  - [ ] Session-Expiry: automatisches Cleanup abgelaufener Sessions
  - [ ] Rate Limiting Middleware
- [ ] **Frontend** (Vanilla HTML/JS)
  - [ ] Connect-Page mit Code-Anzeige + API-Key-Input
  - [ ] Hybrid Encryption via Web Crypto API (RSA-OAEP + AES-256-GCM)
  - [ ] Strikte CSP-Header
- [ ] **Python SDK**
  - [ ] `BrokerClient` mit `request_credential()` und `wait()`/`poll()`
  - [ ] Lokale RSA-Keypair-Generierung + Hybrid-Decryption
  - [ ] Session-Retry-Logik (neue Session starten wenn expired)
- [ ] **End-to-End Test**: CLI-Agent → Broker → Browser → Credentials zurück

## v0.2

- [ ] **OAuth Flow Support** (Google, GitHub, Slack)
  - [ ] OAuth Provider Config (broker-seitig)
  - [ ] `/oauth/callback` Endpoint
  - [ ] Token-Encryption nach OAuth-Callback
- [ ] **WebSocket/SSE statt Polling**: `GET /v1/sessions/{session_id}/events` für Real-Time-Updates
- [ ] **Docker Single-Container Deployment**
- [ ] **Token Refresh Management** (broker-seitig, für OAuth)
- [ ] **Audit Logging**

## v1.0

- [ ] Multi-Tenant Support
- [ ] RBAC / Scoped Access Policies
- [ ] TypeScript SDK
- [ ] Cloud-Hosted SaaS Instance
- [ ] Webhook-Notifications (statt Polling)
- [ ] concept.md aktualisieren: Ed25519-Referenzen korrigieren, Hybrid Encryption dokumentieren, poll_token in API-Design aufnehmen
