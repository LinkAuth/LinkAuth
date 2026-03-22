# LinkAuth Examples

Two examples that demonstrate the credential broker flow -- one interactive demo, one end-to-end test.

## Prerequisites

```bash
# From the project root
uv sync --all-extras
# or: pip install -e ".[examples]"
```

## Agent Simulation (`agent_simulation.py`)

Simulates a real LLM agent workflow with a mock LLM but **real broker interaction**. Shows how an agent requests IMAP credentials, presents a connect link to the user, and resumes after the user authenticates.

```bash
# Terminal 1: Start the broker
PYTHONPATH=src python -m uvicorn broker.main:app --port 8080

# Terminal 2: Run the simulation
python examples/agent_simulation.py
```

**What happens:**

1. Type anything -- the mock LLM pretends you asked for your last 5 emails
2. The `imap_read` tool checks the credential store -- no credentials found
3. Agent creates a LinkAuth session and shows you a URL + code
4. Open the URL in your browser, confirm the code, enter credentials
5. Background poller picks up the encrypted credentials and decrypts them
6. Type anything again -- credentials are found, mock emails are displayed

The LLM is mocked, but the credential flow is 100% real. The broker never sees your credentials in plaintext.

## Live Roundtrip (`live_roundtrip.py`)

End-to-end test against a running broker (local or remote). Creates a session, waits for you to complete it in your browser, then decrypts the result.

```bash
# Against a local broker (no API key)
python examples/live_roundtrip.py

# Against a deployed broker with API key
python examples/live_roundtrip.py \
  --broker https://broker.linkauth.io \
  --api-key YOUR_API_KEY
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--broker` | `http://localhost:8080` | Broker base URL |
| `--api-key` | *(none)* | `X-API-Key` for agent endpoints |
| `--timeout` | `300` | Polling timeout in seconds |

**Output:**

```
[Agent] Generating RSA-2048 keypair...
[Agent] Creating session...
  Code: QZWR-99J3
  URL:  https://broker.linkauth.io/connect/QZWR-99J3

  Open the URL above in your browser,
  confirm the code, and submit credentials.

  Poll: pending
  Poll: pending
  Poll: confirmed
  Poll: ready

[Agent] Decrypting credentials...
  Algorithm: RSA-OAEP-256+AES-256-GCM
  Decrypted: {"secret": "Es funktioniert!"}

  Roundtrip complete. The broker never saw the plaintext.
```
