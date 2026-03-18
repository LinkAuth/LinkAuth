"""
LinkAuth — Basic Roundtrip Example (no LLM, pure Python)

Demonstrates the full credential broker flow:
  1. Agent generates RSA keypair
  2. Agent creates a session on the broker
  3. User opens the URL and submits credentials (simulated here)
  4. Agent polls and retrieves the encrypted credentials
  5. Agent decrypts locally

Prerequisites:
  pip install cryptography httpx

Usage:
  # Start the broker first:
  PYTHONPATH=src python -m uvicorn broker.main:app --port 8080

  # Then run this example:
  python examples/basic_roundtrip.py
"""

from __future__ import annotations

import base64
import json
import time

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BROKER_URL = "http://localhost:8080/v1"


# ---------------------------------------------------------------------------
# Step 1: Generate RSA keypair (agent-side, stays local)
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[rsa.RSAPrivateKey, str]:
    """Generate an RSA-2048 keypair. Returns (private_key, public_key_base64)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_b64 = base64.b64encode(public_key_der).decode()
    return private_key, public_key_b64


# ---------------------------------------------------------------------------
# Step 2: Create session on broker
# ---------------------------------------------------------------------------

def create_session(public_key_b64: str, template: str = "openai") -> dict:
    """Agent requests a credential session from the broker."""
    resp = httpx.post(f"{BROKER_URL}/sessions", json={
        "public_key": public_key_b64,
        "template": template,
    })
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Step 3: Simulate what the browser does (encrypt + submit)
#
# In production, the user opens the URL in their browser.
# The browser JS does the encryption via Web Crypto API.
# Here we simulate that in Python.
# ---------------------------------------------------------------------------

def simulate_browser_confirm(code: str) -> None:
    """User confirms the code in the browser."""
    resp = httpx.post(f"{BROKER_URL}/connect/{code}/confirm")
    assert resp.status_code == 204, f"Confirm failed: {resp.text}"


def simulate_browser_encrypt_and_submit(
    code: str,
    public_key_b64: str,
    credentials: dict,
) -> None:
    """Simulate what crypto.js does: hybrid encrypt + POST to broker."""
    # Import agent's public key
    public_key_der = base64.b64decode(public_key_b64)
    public_key = serialization.load_der_public_key(public_key_der)

    # 1. Generate random AES-256 key
    aes_key = AESGCM.generate_key(bit_length=256)

    # 2. Encrypt credentials with AES-256-GCM
    iv = b"\x00" * 12  # In production: random 12 bytes
    aesgcm = AESGCM(aes_key)
    plaintext = json.dumps(credentials).encode()
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    # 3. Wrap AES key with RSA-OAEP
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 4. Combine into JSON payload (same format as crypto.js)
    payload = {
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    ciphertext_b64 = base64.b64encode(json.dumps(payload).encode()).decode()

    # 5. Submit to broker
    resp = httpx.post(f"{BROKER_URL}/connect/{code}/complete", json={
        "ciphertext": ciphertext_b64,
        "algorithm": "RSA-OAEP-256+AES-256-GCM",
    })
    assert resp.status_code == 204, f"Complete failed: {resp.text}"


# ---------------------------------------------------------------------------
# Step 4: Agent polls for result
# ---------------------------------------------------------------------------

def poll_session(session_id: str, poll_token: str, timeout: int = 30) -> dict | None:
    """Poll until credentials are ready or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = httpx.get(
            f"{BROKER_URL}/sessions/{session_id}",
            headers={"Authorization": f"Bearer {poll_token}"},
        )
        resp.raise_for_status()
        data = resp.json()
        if data["status"] == "ready":
            return data
        time.sleep(1)
    return None


# ---------------------------------------------------------------------------
# Step 5: Agent decrypts credentials locally
# ---------------------------------------------------------------------------

def decrypt_credentials(private_key: rsa.RSAPrivateKey, ciphertext_b64: str) -> dict:
    """Decrypt the hybrid-encrypted payload using the agent's private key."""
    payload = json.loads(base64.b64decode(ciphertext_b64))

    # 1. Unwrap AES key with RSA-OAEP
    wrapped_key = base64.b64decode(payload["wrapped_key"])
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 2. Decrypt credentials with AES-256-GCM
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)

    return json.loads(plaintext)


# ---------------------------------------------------------------------------
# Main: Full roundtrip
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("LinkAuth — Basic Roundtrip Example")
    print("=" * 60)

    # Step 1: Generate keypair
    print("\n[Agent] Generating RSA-2048 keypair...")
    private_key, public_key_b64 = generate_keypair()
    print(f"  Public key: {public_key_b64[:40]}...")

    # Step 2: Create session
    print("\n[Agent] Creating session on broker...")
    session = create_session(public_key_b64, template="openai")
    print(f"  Session ID: {session['session_id'][:16]}...")
    print(f"  Code:       {session['code']}")
    print(f"  URL:        {session['url']}")
    print(f"  Poll Token: {session['poll_token'][:20]}...")

    # -----------------------------------------------------------------------
    # In a real scenario, the agent would now present the URL + code to the
    # user (via LLM, console, chat, etc.) and start polling.
    #
    # Here we simulate the user's browser actions directly.
    # -----------------------------------------------------------------------

    # Step 3a: User confirms the code
    print(f"\n[User]  Opening {session['url']} ...")
    print(f"[User]  Sees code '{session['code']}' — confirms it matches.")
    simulate_browser_confirm(session["code"])
    print("  Code confirmed.")

    # Step 3b: User enters credentials, browser encrypts and submits
    fake_credentials = {"api_key": "sk-fake-openai-key-1234567890"}
    print(f"\n[User]  Entering credentials: {fake_credentials}")
    print("[User]  Browser encrypts with agent's public key and submits...")
    simulate_browser_encrypt_and_submit(
        session["code"], public_key_b64, fake_credentials
    )
    print("  Credentials encrypted and submitted.")

    # Step 4: Agent polls
    print("\n[Agent] Polling for result...")
    result = poll_session(session["session_id"], session["poll_token"])
    if not result:
        print("  ERROR: Timeout waiting for credentials.")
        return
    print(f"  Status:     {result['status']}")
    print(f"  Algorithm:  {result['algorithm']}")
    print(f"  Ciphertext: {result['ciphertext'][:40]}...")

    # Step 5: Decrypt
    print("\n[Agent] Decrypting with private key...")
    credentials = decrypt_credentials(private_key, result["ciphertext"])
    print(f"  Decrypted:  {credentials}")

    print("\n" + "=" * 60)
    print("Roundtrip complete. Broker never saw the plaintext.")
    print("=" * 60)


if __name__ == "__main__":
    main()
