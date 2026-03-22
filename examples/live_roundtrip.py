"""
LinkAuth — Live Roundtrip Test

Creates a session on a running broker, waits for a real user to
complete the form in their browser, then polls and decrypts the result.

Unlike basic_roundtrip.py (which simulates the browser), this script
tests the full end-to-end flow including Web Crypto encryption.

Prerequisites:
  pip install cryptography httpx

Usage:
  python examples/live_roundtrip.py
  python examples/live_roundtrip.py --broker https://broker.linkauth.io --api-key YOUR_KEY
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_keypair() -> tuple[rsa.RSAPrivateKey, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, base64.b64encode(pub_der).decode()


def decrypt_credentials(private_key: rsa.RSAPrivateKey, ciphertext_b64: str) -> dict:
    """Decrypt the hybrid-encrypted payload (RSA-OAEP + AES-256-GCM)."""
    envelope = json.loads(base64.b64decode(ciphertext_b64))

    wrapped_key = base64.b64decode(envelope["wrapped_key"])
    iv = base64.b64decode(envelope["iv"])
    ciphertext = base64.b64decode(envelope["ciphertext"])

    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    plaintext = AESGCM(aes_key).decrypt(iv, ciphertext, None)
    return json.loads(plaintext)


def main():
    parser = argparse.ArgumentParser(description="LinkAuth live roundtrip test")
    parser.add_argument("--broker", default="http://localhost:8080",
                        help="Broker base URL (default: http://localhost:8080)")
    parser.add_argument("--api-key", default=None,
                        help="X-API-Key for agent endpoints (omit if auth is disabled)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Polling timeout in seconds (default: 300)")
    args = parser.parse_args()

    base = args.broker.rstrip("/")
    headers = {"Content-Type": "application/json"}
    if args.api_key:
        headers["X-API-Key"] = args.api_key

    # 1. Generate keypair
    print("[Agent] Generating RSA-2048 keypair...")
    private_key, pub_b64 = generate_keypair()

    # 2. Create session
    print("[Agent] Creating session...")
    r = httpx.post(f"{base}/v1/sessions", headers=headers, json={
        "public_key": pub_b64,
        "display_name": "Live Roundtrip Test",
        "fields": [
            {"name": "api_key", "label": "API Key", "type": "password"},
        ],
    })
    if r.status_code != 201:
        print(f"  FAILED: {r.status_code} — {r.text}")
        sys.exit(1)

    data = r.json()
    session_id = data["session_id"]
    poll_token = data["poll_token"]
    url = data["url"]
    code = data["code"]

    print(f"  Code: {code}")
    print(f"  URL:  {url}")
    print(f"\n  Open the URL above in your browser,")
    print(f"  confirm the code, and submit credentials.\n")

    # 3. Poll
    poll_headers = dict(headers)
    poll_headers["Authorization"] = f"Bearer {poll_token}"
    interval = data.get("interval", 5)
    deadline = time.time() + args.timeout

    while time.time() < deadline:
        time.sleep(interval)
        r = httpx.get(f"{base}/v1/sessions/{session_id}", headers=poll_headers)

        if r.status_code == 429:
            interval = r.json().get("interval", interval + 5)
            print(f"  Poll: slow_down (interval now {interval}s)")
            continue

        result = r.json()
        status = result.get("status", "unknown")
        print(f"  Poll: {status}")

        if status == "ready":
            break

        if "interval" in result:
            interval = result["interval"]
    else:
        print("\n  TIMEOUT — session expired before completion.")
        sys.exit(1)

    # 4. Decrypt
    print("\n[Agent] Decrypting credentials...")
    credentials = decrypt_credentials(private_key, result["ciphertext"])
    print(f"  Algorithm: {result['algorithm']}")
    print(f"  Decrypted: {json.dumps(credentials, indent=2)}")
    print("\n  Roundtrip complete. The broker never saw the plaintext.")


if __name__ == "__main__":
    main()
