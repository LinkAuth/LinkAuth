---
title: "LinkAuth: Credential Transfer Protocol for Callback-Constrained Agents"
abbrev: "LinkAuth"
category: info
docname: draft-gerst-linkauth-credential-transfer-00
submissiontype: independent
number:
date:
v: 3
area: "Security"
keyword:
  - credential transfer
  - AI agents
  - device flow
  - end-to-end encryption
  - OAuth
venue:
  mail: "wimse@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/wimse/"
  github: "LinkAuth/LinkAuth"

author:
  -
    fullname: Danny Gerst
    organization: BizRock
    email: d.gerst@bizrock.de

normative:
  RFC2119:
  RFC8174:
  RFC8628:
  RFC6750:
  RFC9457:
  RFC7636:
  RFC8017:
  RFC5116:

informative:
  RFC6797:
  RFC8446:
  I-D.klrc-aiagent-auth:
  I-D.hartman-credential-broker-4-agents:
  I-D.levy-wimse-headless-jwt-authentication:

--- abstract

This document specifies LinkAuth, a credential transfer protocol that
enables callback-constrained agents (CLI tools, containerized
workloads, sandboxed AI agents) to receive credentials from users
through a broker-mediated, device-flow-inspired interaction. Unlike
existing OAuth flows that require the agent to accept inbound
callbacks or operate a web server, LinkAuth allows agents that only
make outbound requests to securely receive credentials.

For form-based credential flows, the protocol provides end-to-end
encryption: credentials are encrypted in the user's browser with
the agent's public key before transmission. Under an
honest-but-curious broker model, the broker cannot access plaintext
credentials, though it does observe session metadata, timing, and
network context. An OPTIONAL OAuth-mediated extension allows the
broker to act as the confidential client on behalf of the agent,
with a different trust model. LinkAuth builds on
RFC 8628 (Device Authorization Grant) interaction semantics,
RFC 7636 (PKCE) for OAuth code exchange, and hybrid RSA-OAEP +
AES-256-GCM encryption for credential protection.

--- middle

# Introduction

## The Gap

A user wants to give an AI agent access to their Gmail, their CI
pipeline, or their cloud dashboard. Today, the standard mechanism
for this is OAuth: the user logs in, consents, and the agent
receives a token. But OAuth's delegation flows assume the agent
can do at least one of the following:

1. Accept inbound HTTP callbacks (Authorization Code Flow),
2. Open and control a local browser (interactive Device Flow), or
3. Operate a web server to receive redirect URIs.

A growing class of agents cannot satisfy any of these assumptions.
Container-based AI agents, headless CLI tools, Telegram bots,
sandboxed desktop agents (e.g., Claude Code Desktop), and cron
jobs can only make outbound requests. They have no mechanism to
receive callbacks, no browser to control, and no permission to
bind additional network ports.

RFC 8628 (Device Authorization Grant) comes closest: the agent
displays a code, the user visits a URL, and the agent polls for
completion. But RFC 8628 requires the authorization server to
implement the device grant type and cannot transfer non-OAuth
credentials such as API keys, service account files, or shared
secrets.

Between user consent and agent delegation, there is no
standardized bootstrap mechanism for callback-constrained agents.

## Scope of This Document

This document specifies LinkAuth, a credential transfer protocol
that addresses this gap. The core protocol (Sections 3-6, 8) is a
self-contained mechanism for encrypted credential transfer using
a device-flow-inspired interaction model. An agent creates a
session with its public key, displays a human-readable code and
URL to the user, and polls for completion. The user opens the URL,
verifies the code, and submits credentials through a form that
encrypts them client-side with the agent's public key. Under the
honest-but-curious broker assumption defined in {{broker-trust}},
the broker is blind to plaintext credential material in this flow.

Section 7 defines an OPTIONAL OAuth-mediated extension where the
broker acts as an OAuth Confidential Client on behalf of the
agent. This extension has a different trust model (the broker
temporarily handles plaintext tokens) and may be specified
separately in a future document.

## Relationship to Existing Work

LinkAuth is complementary to several existing and proposed
specifications:

- {{I-D.klrc-aiagent-auth}} defines OAuth-based authentication for
  AI agents using WIMSE and SPIFFE. LinkAuth addresses the
  credential delivery gap acknowledged in that draft: "Additional
  specification or design work may be needed to define how
  out-of-band interactions with the User occur."

- {{I-D.hartman-credential-broker-4-agents}} (CB4A) specifies an
  enterprise credential vaulting architecture where a broker manages
  existing credentials through a PDP/CDP separation. LinkAuth
  operates at a different layer: it addresses the initial
  user-to-agent credential handoff rather than ongoing credential
  management.

- {{I-D.levy-wimse-headless-jwt-authentication}} addresses
  workload-to-service authentication using JWT exchange. LinkAuth
  addresses the prior step: how the workload obtains credentials
  in the first place.

- {{RFC8628}} defines the Device Authorization Grant, whose
  interaction model (display code, user visits URL, agent polls)
  directly inspires LinkAuth. However, RFC 8628 requires the
  authorization server to support the device grant type and does not
  cover non-OAuth credentials.

## Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

Agent:
: A software process that acts on behalf of a user but cannot
  accept inbound HTTP connections. Examples include CLI tools,
  containerized AI agents, and sandboxed desktop applications.

Broker:
: An HTTP service that mediates credential transfer between a user
  and an agent. The broker hosts the session API and the
  user-facing credential submission interface.

Session:
: A time-limited context for a single credential transfer. A
  session progresses through defined states from creation to
  consumption.

User Code:
: A short, human-readable string (e.g., "ABCD-1234") displayed to
  the user for session identification and verification. Following
  {{RFC8628}} terminology, this is the `user_code`.

Verification URI:
: A broker-hosted URL where the user initiates the credential
  transfer. In `complete_uri` mode, the user code is embedded in
  the URL. In `manual_code_entry` mode, the URL points to a
  generic page where the user must enter the code manually.

Session ID:
: The SHA-256 hash of the normalized user code, used as the
  technical identifier for API operations.

Poll Token:
: A Bearer token ({{RFC6750}}) issued to the agent at session
  creation, used to authenticate polling requests.

Connect Token:
: A one-time Bearer token issued to the user's browser upon code
  confirmation, used to authenticate credential submission.

# Protocol Overview

The LinkAuth protocol involves three parties:

~~~
+-------+                +--------+                +------+
| Agent |                | Broker |                | User |
+---+---+                +---+----+                +--+---+
    |                        |                        |
    | 1. POST /sessions      |                        |
    |  (public_key, fields)  |                        |
    |----------------------->|                        |
    |                        |                        |
    | 2. {code, url,         |                        |
    |     poll_token}        |                        |
    |<-----------------------|                        |
    |                        |                        |
    | 3. Display code+url    |                        |
    |----------------------------------------------->|
    |                        |                        |
    |                        | 4. GET /connect/{code} |
    |                        |<-----------------------|
    |                        |                        |
    |                        | 5. {fields, public_key}|
    |                        |----------------------->|
    |                        |                        |
    |                        | 6. POST /confirm       |
    |                        |<-----------------------|
    |                        |                        |
    |                        | 7. {connect_token}     |
    |                        |----------------------->|
    |                        |                        |
    |                        | 8. POST /complete      |
    |                        |  (encrypted creds,     |
    |                        |   connect_token)       |
    |                        |<-----------------------|
    |                        |                        |
    | 9. GET /sessions/{id}  |                        |
    |  (poll_token)          |                        |
    |----------------------->|                        |
    |                        |                        |
    | 10. {status: ready,    |                        |
    |      ciphertext}       |                        |
    |<-----------------------|                        |
    |                        |                        |
    | 11. Decrypt with       |                        |
    |     private key        |                        |
    |                        |                        |
~~~
{: #fig-protocol-overview title="LinkAuth Protocol Flow (Form-Based)"}

For OAuth-based flows, steps 8 is replaced by an OAuth
Authorization Code flow where the broker acts as the confidential
client. See {{oauth-flow}} for details.

# Session Lifecycle

## Session States

A session progresses through the following states:

~~~
  PENDING --> CONFIRMED --> READY --> CONSUMED
     |            |           |
     +------------+-----------+--> EXPIRED
~~~
{: #fig-states title="Session State Machine"}

PENDING:
: Initial state after creation. The agent has received a poll
  token. The code is active and the user may retrieve session
  information and confirm the code.

CONFIRMED:
: The user has verified the code and received a connect token.
  Subsequent credential submission requires possession of this
  token. Credential submission may proceed.

READY:
: Encrypted credentials have been stored. The agent may retrieve
  them exactly once through polling.

CONSUMED:
: The agent has retrieved the encrypted credentials. The session
  is scheduled for deletion.

EXPIRED:
: The session TTL has elapsed. The session is no longer accessible
  and will be deleted by the cleanup process.

## Session Identifiers

### Code Generation

The code MUST be generated using a cryptographically secure random
number generator. The default format is 8 characters from the set
\[A-Z0-9\], displayed as two groups of four separated by a hyphen
(e.g., "ABCD-1234").

The code entropy MUST be at least 40 bits. Given the short session
TTL (default 10 minutes) and rate limiting, this provides adequate
resistance to brute-force attacks.

### Session ID Derivation

The session ID is derived from the code:

~~~
session_id = SHA-256(UPPER(REMOVE_HYPHENS(code)))
~~~

This allows the agent to compute the session ID from the code
without storing additional state, while preventing code enumeration
through the polling API.

# Agent-Facing API

## Create Session

~~~
POST /v1/sessions HTTP/1.1
Host: broker.example.com
Content-Type: application/json

{
  "public_key": "{base64-encoded RSA SubjectPublicKeyInfo}",
  "fields": [
    {
      "name": "api_key",
      "label": "API Key",
      "type": "password",
      "required": true
    }
  ],
  "display_name": "Gmail Access",
  "ttl": 600
}
~~~

The `public_key` field MUST contain an RSA public key of at least
2048 bits, encoded as base64(DER SubjectPublicKeyInfo).

The `fields` array defines the credential form presented to the
user. Each field specifies a name, label, type (text, password,
textarea, or select), and whether it is required.

Alternatively, the agent MAY specify `oauth_provider`,
`oauth_scopes`, and `oauth_extra_params` to initiate an OAuth-based
flow instead of a form-based flow. See {{oauth-flow}}.

The `ttl` field specifies the session lifetime in seconds. The
broker MUST enforce a maximum TTL and MAY reduce the requested TTL
accordingly.

Deployments MAY support additional fields such as `callback_url`
(for agents that can receive inbound notifications as an
optimization over polling) and deployment-specific authentication
headers. These are outside the scope of the core protocol.

On success, the broker responds with:

~~~
HTTP/1.1 201 Created
Content-Type: application/json

{
  "session_id": "{SHA-256 hex digest}",
  "user_code": "ABCD-1234",
  "verification_uri": "https://broker.example.com/connect",
  "verification_uri_complete":
    "https://broker.example.com/connect/ABCD-1234",
  "poll_token": "pt_{base64url(32 bytes)}",
  "expires_at": "2026-04-02T12:00:00Z",
  "interval": 5
}
~~~

The field names follow {{RFC8628}} Section 3.2:

- `user_code`: The code the agent displays to the user.
- `verification_uri`: A generic broker page where the user can
  enter the code manually (manual_code_entry mode).
- `verification_uri_complete`: OPTIONAL. A direct link with the
  code embedded (complete_uri mode). If present, the agent MAY
  display this as a clickable link for convenience.
- `interval`: The minimum polling interval in seconds.

## Poll Session

~~~
GET /v1/sessions/{session_id} HTTP/1.1
Host: broker.example.com
Authorization: Bearer pt_{poll_token}
~~~

The agent polls this endpoint to check session status. The broker
MUST validate the poll token against the session. If the
Authorization header is missing, malformed, or contains a token
that does not match the session's poll token, the broker MUST
respond with HTTP 401 Unauthorized:

~~~
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json
WWW-Authenticate: Bearer

{
  "type": "about:blank",
  "title": "Unauthorized",
  "status": 401,
  "detail": "Missing or invalid poll token."
}
~~~

Note: Broker deployments MAY require additional authentication
(e.g., API keys) for session creation and polling. Such mechanisms
are deployment-specific and outside the scope of this protocol.

### Pending Response

~~~
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "pending",
  "expires_at": "2026-04-02T12:00:00Z",
  "interval": 5
}
~~~

### Ready Response (One-Time Retrieval)

When credentials are available, the broker MUST return the
ciphertext exactly once and transition the session to CONSUMED:

~~~
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "ready",
  "expires_at": "2026-04-02T12:00:00Z",
  "ciphertext": "{base64-encoded encrypted payload}",
  "algorithm": "RSA-OAEP-256+AES-256-GCM"
}
~~~

Subsequent polling requests after consumption MUST return
`status: "consumed"` without ciphertext.

### Expired or Unknown Session

If the session has expired or does not exist, the broker MUST
respond with HTTP 404 and a Problem Details ({{RFC9457}}) body:

~~~
HTTP/1.1 404 Not Found
Content-Type: application/problem+json

{
  "type": "about:blank",
  "title": "Session Not Found",
  "status": 404,
  "detail": "Session not found or expired."
}
~~~

The agent SHOULD interpret a 404 response as terminal and stop
polling. Agents MUST NOT retry after receiving 404.

### Rate Limiting

If the agent polls faster than the indicated interval, the broker
MUST respond with HTTP 429 and a `slow_down` error following
{{RFC8628}} Section 3.5:

~~~
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{
  "error": "slow_down",
  "interval": 10
}
~~~

The increased interval tells the agent to back off.

# User-Facing API

## Verification Modes {#verification-modes}

LinkAuth supports two verification modes that offer different
trade-offs between usability and resistance to URL leakage:

### complete_uri Mode (Default)

The agent displays a `verification_uri_complete` that embeds the
user code in the URL (e.g.,
`https://broker.example.com/connect/ABCD-1234`). The user clicks
the link and proceeds directly to code confirmation.

This mode provides the best user experience but the code is
visible in the URL. If the link is intercepted (browser history,
chat logs, shoulder surfing, network without TLS), an attacker
can race to confirm the session.

### manual_code_entry Mode

The agent displays the `verification_uri` (a generic page without
an embedded code) and the `user_code` separately. The user opens
the generic page and manually enters the code.

~~~
Agent displays:
  Visit: https://broker.example.com/connect
  Enter code: ABCD-1234
~~~

In this mode, the code is not part of the URL. Intercepting the
URL alone does not reveal the code, providing stronger protection
against URL leakage. The code must be transmitted out-of-band
(displayed by the agent to the user).

### Resolve Endpoint (manual_code_entry Mode)

~~~
POST /v1/connect/resolve HTTP/1.1
Host: broker.example.com
Content-Type: application/json

{
  "user_code": "ABCD-1234"
}
~~~

The broker looks up the session by user code. On success, the
broker returns the same session information as
`GET /v1/connect/{code}` (see below). On failure (unknown code,
expired session), the broker MUST return HTTP 404 with the
standard vague error response.

The broker MUST enforce rate limiting on this endpoint to prevent
brute-force code enumeration (see rate limiting below).

### Mode Selection

The verification mode is a deployment policy, not a per-session
parameter. Brokers that require `manual_code_entry` SHOULD omit
`verification_uri_complete` from the create session response.
Agents MUST support both modes: if `verification_uri_complete` is
present, the agent MAY display it as a clickable link; if absent,
the agent MUST display `verification_uri` and `user_code`
separately.

## Retrieve Session Information

~~~
GET /v1/connect/{code} HTTP/1.1
Host: broker.example.com
~~~

Returns session metadata including display name, fields, public
key, and security information. This endpoint MUST only return full
session data for PENDING sessions. After confirmation, the session
is locked and this endpoint MUST return 404 to prevent phishing
attacks where an attacker who intercepts the link could substitute
their own credentials.

The broker MUST enforce rate limiting on the connect, confirm,
and resolve endpoints to prevent brute-force code enumeration.
Implementations SHOULD limit requests per source IP to no more
than 10 attempts per minute per code, and SHOULD return HTTP 429
when the limit is exceeded.

## Confirm Code

~~~
POST /v1/connect/{code}/confirm HTTP/1.1
Host: broker.example.com
Content-Type: application/json
~~~

The user confirms they see the expected code. The broker transitions
the session to CONFIRMED and returns a connect token:

~~~
HTTP/1.1 200 OK
Content-Type: application/json

{
  "connect_token": "ct_{base64url(32 bytes)}"
}
~~~

Subsequent confirmation attempts MUST return HTTP 409 Conflict.

## Submit Credentials (Form-Based Flow) {#form-flow}

~~~
POST /v1/connect/{code}/complete HTTP/1.1
Host: broker.example.com
Content-Type: application/json

{
  "ciphertext": "{base64-encoded encrypted payload}",
  "algorithm": "RSA-OAEP-256+AES-256-GCM",
  "connect_token": "ct_{connect_token}"
}
~~~

The browser encrypts credentials client-side before transmission.
See {{encryption}} for the encryption scheme. The broker stores the
ciphertext without decryption and transitions the session to READY.

On success, the broker responds with HTTP 204 No Content.

The broker MUST enforce the following error semantics:

- Missing or invalid connect token: HTTP 403 Forbidden.
- Session not in CONFIRMED state (e.g., already READY or
  CONSUMED): HTTP 409 Conflict. This prevents replay of
  credential submissions.
- Expired session: HTTP 404 Not Found.

A successful credential submission consumes the connect token
implicitly (the session transitions to READY, which no longer
accepts submissions). Implementations MUST NOT allow a second
credential submission to the same session.

# OAuth-Mediated Flow {#oauth-flow}

For OAuth-based credential transfers, the broker acts as the OAuth
Confidential Client on behalf of the agent. This enables agents to
receive OAuth tokens without operating a callback server.

~~~
+-------+         +--------+         +------+       +----------+
| Agent |         | Broker |         | User |       | OAuth AS |
+---+---+         +---+----+         +--+---+       +----+-----+
    |                  |                 |                |
    | POST /sessions   |                 |                |
    | (oauth_provider, |                 |                |
    |  oauth_scopes)   |                 |                |
    |----------------->|                 |                |
    |                  |                 |                |
    | {code, url,      |                 |                |
    |  poll_token}     |                 |                |
    |<-----------------|                 |                |
    |                  |                 |                |
    | Display URL+code |                 |                |
    |----------------------------------->|                |
    |                  |                 |                |
    |                  | GET /connect    |                |
    |                  |<----------------|                |
    |                  |                 |                |
    |                  | POST /confirm   |                |
    |                  |<----------------|                |
    |                  | {connect_token} |                |
    |                  |---------------->|                |
    |                  |                 |                |
    |                  | GET /oauth/authorize/{code}      |
    |                  |   ?connect_token=ct_...          |
    |                  |<----------------|                |
    |                  |                 |                |
    |                  | 302 Redirect    |                |
    |                  | (PKCE challenge)|                |
    |                  |---------------->|                |
    |                  |                 |                |
    |                  |                 | Authorization  |
    |                  |                 |--------------->|
    |                  |                 |                |
    |                  |                 | auth_code      |
    |                  |                 |<---------------|
    |                  |                 |                |
    |                  | GET /oauth/callback              |
    |                  |   ?code=...&state=...            |
    |                  |<----------------|                |
    |                  |                 |                |
    |                  | Token Exchange  |                |
    |                  | (code_verifier) |                |
    |                  |--------------------------------->|
    |                  |                 |                |
    |                  | {access_token,  |                |
    |                  |  refresh_token} |                |
    |                  |<---------------------------------|
    |                  |                 |                |
    |                  | Encrypt tokens  |                |
    |                  | with agent      |                |
    |                  | public_key      |                |
    |                  |                 |                |
    | GET /sessions    |                 |                |
    | (poll_token)     |                 |                |
    |----------------->|                 |                |
    |                  |                 |                |
    | {status: ready,  |                 |                |
    |  ciphertext}     |                 |                |
    |<-----------------|                 |                |
    |                  |                 |                |
~~~
{: #fig-oauth-flow title="LinkAuth OAuth-Mediated Flow"}

The broker MUST use PKCE ({{RFC7636}}) for the authorization code
exchange. The code verifier is generated and stored server-side; it
is never exposed to the user's browser.

After receiving tokens from the OAuth authorization server, the
broker MUST immediately encrypt them using the agent's public key
(see {{encryption}}) and MUST NOT retain plaintext tokens beyond the
encryption operation.

## OAuth Error Handling and Abort

If the OAuth authorization server returns an error callback
(e.g., `?error=access_denied`), or if the user abandons the
authorization flow without completing it, the session remains in
CONFIRMED state until the session TTL expires. The broker MUST
NOT transition the session to a retry-capable state.

This is a deliberate design choice: the connect token has already
been consumed at redirect initiation, and the session is bound to
a single OAuth flow attempt. If the user needs to retry, the
agent MUST create a new session. This avoids the complexity of
retry state management and ensures that each session represents
exactly one credential transfer attempt.

The broker SHOULD redirect the user to an error page that
explains the failure and instructs them to request a new session
from the agent. The polling agent will observe the session
remaining in a non-READY state until expiry, at which point it
receives HTTP 404 and SHOULD inform the user that the
authorization was not completed.

## Connect Token in OAuth Redirects

The OAuth authorization endpoint accepts the connect token as a
query parameter (`?connect_token=ct_...`). Query parameter
transport is permitted for simplicity. The connect token is
short-lived (bound to the session TTL) and single-use, which
limits but does not eliminate exposure through browser history,
server logs, or Referer headers.

The broker MUST consume the connect token upon initiating the
OAuth redirect (i.e., when generating the 302 response to the
OAuth authorization server). After consumption, the broker MUST
reject subsequent requests to `/oauth/authorize/{code}` as
follows:

- Missing or invalid connect token: HTTP 403 Forbidden.
- Valid but already-consumed connect token (replay): HTTP 409
  Conflict.
- Session not in CONFIRMED state: HTTP 409 Conflict.
- Expired session: HTTP 404 Not Found.

Deployments with higher confidentiality requirements SHOULD use
server-side session binding (e.g., HttpOnly cookies with SameSite
attributes) instead of query parameter transport.

# Encryption Scheme {#encryption}

## Hybrid RSA-OAEP + AES-256-GCM

LinkAuth uses a hybrid encryption scheme combining RSA-OAEP
({{RFC8017}}) for key encapsulation and AES-256-GCM ({{RFC5116}})
for authenticated encryption of credential data.

### Encryption (performed by browser or broker)

1. Generate a random 256-bit AES key.
2. Generate a random 96-bit initialization vector (IV).
3. Serialize credentials as a JSON object.
4. Encrypt the JSON with AES-256-GCM using the generated key
   and IV. This produces ciphertext and an authentication tag.
5. Encrypt the AES key with RSA-OAEP-256 using the agent's
   public key (SHA-256 for both hash and MGF1).
6. Encode the result as a JSON object:

~~~
{
  "wrapped_key": "{base64(RSA-encrypted AES key)}",
  "iv": "{base64(96-bit nonce)}",
  "ciphertext": "{base64(AES-GCM ciphertext + tag)}"
}
~~~

The outer JSON is then base64-encoded for transport.

### Decryption (performed by agent)

1. Base64-decode the transport payload.
2. Parse the JSON to extract wrapped_key, iv, and ciphertext.
3. Decrypt the AES key using RSA-OAEP-256 with the agent's
   private key.
4. Decrypt the ciphertext using AES-256-GCM with the recovered
   key and IV.
5. Parse the resulting JSON to obtain credentials.

### Algorithm Identifier

The algorithm identifier for this scheme is
"RSA-OAEP-256+AES-256-GCM". The `algorithm` field in API responses
allows future extension to other encryption schemes.

# Security Considerations

## Broker Trust Model {#broker-trust}

This protocol assumes an honest-but-curious broker: the broker
follows the protocol correctly but may attempt to learn credential
material from the data it processes. The protocol does NOT defend
against an actively malicious broker.

A malicious broker could substitute the agent's public key with
its own when serving the connect page, or modify the client-side
encryption code to exfiltrate plaintext credentials. These attacks
are possible because the broker serves both the session metadata
and the frontend code to the user's browser.

This trust model is appropriate for deployments where the agent
operator also controls the broker (self-hosted), or where the
broker is operated by a trusted party. It mirrors the trust model
of existing OAuth authorization servers, which similarly see
plaintext tokens during issuance.

### Future Work: Key Fingerprint Verification

A future version of this protocol MAY define a key fingerprint
mechanism where the agent displays a truncated hash of its public
key alongside the session code. The user could verify this
fingerprint in the browser before submitting credentials, detecting
key substitution by a compromised broker.

Note that fingerprint verification mitigates only one of the two
malicious-broker attacks identified above: it detects public key
substitution, but does not prevent a broker from serving modified
JavaScript that exfiltrates credentials before encryption. Full
protection against a malicious broker would require the encryption
code to be delivered independently of the broker (e.g., via a
browser extension or a locally installed application). This is
analogous to the limitation of SSH host key verification, which
authenticates the server but does not protect against a
compromised SSH client binary.

### Form-Based Flows (Honest-but-Curious Model)

Under the honest-but-curious assumption, the broker is blind to
plaintext credentials in form-based flows. Encryption occurs in
the user's browser using the agent's public key; the broker
receives, stores, and delivers only ciphertext. The broker cannot
recover credential material without the agent's private key.

The broker does observe session metadata (field names, timing, IP
addresses, session duration) and can infer the type and purpose
of credentials from this context.

### OAuth-Mediated Flows

For OAuth-mediated flows, the broker acts as the OAuth Confidential
Client and temporarily holds plaintext tokens in memory during the
encryption operation. This is an inherent consequence of the OAuth
architecture: the broker must exchange the authorization code for
tokens before encrypting them with the agent's public key.
Implementations MUST minimize this exposure window and MUST NOT
log or persist plaintext tokens. Deployments requiring stronger
isolation for OAuth tokens should consider the form-based flow
with client-side token exchange where the target service supports
it.

## Code Security

The human-readable code serves as a shared secret between agent and
user for session binding. The code provides approximately 40 bits of
entropy. Security relies on the combination of:

- Short session TTL (default 10 minutes)
- Rate limiting on the connect endpoint
- One-time code confirmation (CONFIRMED state prevents reuse)

The code is NOT used as cryptographic key material. Credential
encryption uses the agent's RSA keypair, which is independent of
the code.

Rate limiting on the connect and confirm endpoints (see
Section 6.1) is a normative requirement of this protocol, not
merely a deployment recommendation.

## Session Binding

After code confirmation, the session is bound to two independent
bearer tokens:

- The connect endpoint returns 404 for confirmed sessions,
  preventing phishing attacks where an attacker who intercepts
  the link could view the session.
- The connect token is required for credential submission,
  binding the operation to the party that confirmed the code.
  This is bearer-token binding, not browser binding: any party
  in possession of the connect token can submit credentials.
  See {{credential-misbinding}} for the security implications.
- Poll token is required for credential retrieval, binding the
  operation to the creating agent.

## Credential Misbinding {#credential-misbinding}

Possession of the connect token authorizes credential submission,
but does not prove that the submitted credential corresponds to
the user-intended account, tenant, or resource. Incorrect but
valid credentials can therefore misbind the agent to an unintended
security principal.

This risk is inherent to any credential transfer mechanism where
the submitting party is not cryptographically authenticated as the
resource owner. Concrete attack scenarios include:

- An attacker submits their own valid OAuth token. The agent
  connects to the correct service endpoint but operates under
  the attacker's account, potentially writing user data into
  an attacker-controlled resource.

- An attacker submits credentials for an attacker-controlled
  data source. The agent reads data that appears legitimate but
  contains crafted content (e.g., for prompt injection attacks
  against AI agents).

- In multi-tenant services where the API endpoint is shared
  (e.g., Slack, GitHub, Google Workspace), the credential
  determines which tenant the agent operates in. Misbinding
  can redirect agent operations to a different organizational
  context.

Mitigation of credential misbinding is largely outside the
protocol layer and depends on the credential type:

- For OAuth tokens that carry identity claims, agent
  implementations SHOULD verify the `sub`, `email`, or tenant
  identifier against the expected user before performing
  actions.

- For opaque credentials (API keys, service account files,
  shared secrets), programmatic verification of the associated
  principal is often not possible. The agent may be unable to
  distinguish a legitimate credential from an
  attacker-substituted one. Deployments that transfer opaque
  credentials SHOULD rely on out-of-band trust establishment
  (e.g., the user confirming the intended service context
  through the session display name) and SHOULD treat received
  credentials as untrusted input until validated through use.

This limitation is inherent to any credential transfer mechanism
for opaque secrets and is not specific to LinkAuth.

## One-Time Retrieval

Encrypted credentials are returned exactly once through the polling
API. After retrieval, the session transitions to CONSUMED and the
ciphertext is no longer available. This limits the exposure window
if the poll token is compromised after retrieval.

## Transport Security

Implementations MUST use TLS ({{RFC8446}}) for all API
communication in production deployments. Without TLS, an active
network attacker can substitute the JavaScript encryption code,
replace the agent's public key, intercept connect tokens, and
manipulate OAuth redirects. TLS is not merely a confidentiality
measure; it protects the integrity of the entire protocol flow.

The broker SHOULD set HTTP Strict-Transport-Security headers
({{RFC6797}}). Brokers SHOULD detect the absence of TLS and
warn users through the security information returned by the
connect endpoint. Brokers MAY refuse credential submission over
unencrypted connections.

## Phishing and URL Leakage Mitigation

The code confirmation step mitigates one specific phishing
scenario: an attacker creates a session with their own public key
and sends the crafted link to a victim. The victim would see a
code that does not match the code their agent displayed, alerting
them to the mismatch.

After confirmation, the connect endpoint returns 404, which
prevents a second party from viewing the session. However, in
`complete_uri` mode, the user code is embedded in the URL. If
an attacker intercepts the link (via network observation, chat
logs, browser history, or Referer headers), they can race to
confirm the session before the legitimate user.

The `manual_code_entry` mode (see {{verification-modes}})
mitigates this risk by separating the URL from the code.
Intercepting the URL alone does not reveal the code, and
brute-forcing the code is constrained by rate limiting and
short session TTLs.

Deployments with elevated security requirements SHOULD use
`manual_code_entry` mode and MUST use TLS to protect both the
URL and the code entry from network-level interception.

## Threat Model

| Threat | Severity | Mitigation |
|---|---|---|
| Stored encrypted payload disclosure | LOW | Ciphertext remains confidential without the agent private key |
| Active session state compromise | HIGH | Tokens and session metadata may enable takeover of in-flight sessions |
| Session hijacking | MEDIUM | poll_token + connect_token separation |
| Code brute-force | LOW | Short TTL + rate limiting + confirmation lock |
| URL leakage / session race | MEDIUM (complete_uri) / LOW (manual_code_entry) | manual_code_entry separates code from URL; post-confirm 404; TLS |
| Replay of ciphertext | LOW | One-time retrieval (CONSUMED state) |
| MITM on broker connection | HIGH | Mandatory TLS; protects integrity, not just confidentiality |
| Broker operator as adversary (honest-but-curious) | MEDIUM (form) / HIGH (OAuth) | E2E encryption for forms (metadata visible); OAuth requires broker trust |
| Broker operator as adversary (malicious) | CRITICAL | Out of scope; broker can substitute keys/JS. See {{broker-trust}} |
| Credential misbinding | MEDIUM | Agent-side identity verification (see {{credential-misbinding}}) |

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

The author thanks the WIMSE working group for discussions on
workload identity and credential management for AI agents.

# Implementation Status
{:numbered="false"}

An open-source reference implementation of this specification is
available at https://github.com/LinkAuth/LinkAuth. The
implementation includes:

- Python broker with SQLite storage
- Browser-based credential submission frontend
- OAuth proxy with PKCE support for 22+ providers
- Agent SDK integration for CLI, OpenWebUI, and Claude Code Desktop
