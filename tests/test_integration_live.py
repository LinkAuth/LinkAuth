"""Integration tests against the live broker at broker.linkauth.io.

Run with: python -m pytest tests/test_integration_live.py -v
"""

from __future__ import annotations

import base64
import json
import time

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_URL = "https://broker.linkauth.io"
API_KEY = "lZs7nJQr9wpDC_RGvmeCXkjmv-hBiCDeefV6KcB3E2Y"
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}


def _generate_keypair() -> tuple[rsa.RSAPrivateKey, str]:
    """Generate an RSA keypair and return (private_key, base64_der_public_key)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, base64.b64encode(pub_der).decode()


def _decrypt_payload(private_key: rsa.RSAPrivateKey, ciphertext_b64: str) -> dict:
    """Decrypt a hybrid-encrypted payload (RSA-OAEP-256 + AES-256-GCM)."""
    outer = json.loads(base64.b64decode(ciphertext_b64))
    wrapped_key = base64.b64decode(outer["wrapped_key"])
    iv = base64.b64decode(outer["iv"])
    ciphertext = base64.b64decode(outer["ciphertext"])

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


# ---------------------------------------------------------------------------
# 1. Health Check
# ---------------------------------------------------------------------------

def test_health():
    r = httpx.get(f"{BASE_URL}/health", timeout=10)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# 2. Auth / Security
# ---------------------------------------------------------------------------

def test_missing_api_key():
    r = httpx.post(f"{BASE_URL}/v1/sessions", json={"public_key": "x"}, timeout=10)
    assert r.status_code == 401
    assert "API Key Required" in r.json()["detail"]["title"]


def test_invalid_api_key():
    r = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers={"X-API-Key": "wrong-key", "Content-Type": "application/json"},
        json={"public_key": "x"},
        timeout=10,
    )
    assert r.status_code == 403
    assert "Invalid API Key" in r.json()["detail"]["title"]


# ---------------------------------------------------------------------------
# 3. Session Creation — Validation
# ---------------------------------------------------------------------------

def test_create_session_invalid_public_key():
    r = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=HEADERS,
        json={"public_key": "not-valid-base64!!!"},
        timeout=10,
    )
    assert r.status_code == 400
    assert "public_key" in r.json()["detail"].lower()


def test_create_session_empty_public_key():
    r = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=HEADERS,
        json={"public_key": ""},
        timeout=10,
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# 4. Full Session Lifecycle (Create → Confirm → Complete → Poll → Consume)
# ---------------------------------------------------------------------------

def test_full_session_lifecycle():
    private_key, pub_b64 = _generate_keypair()

    # Step 1: Create session
    r = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=HEADERS,
        json={"public_key": pub_b64, "template": "api_key"},
        timeout=10,
    )
    assert r.status_code == 201, f"Create failed: {r.text}"
    session = r.json()
    assert "session_id" in session
    assert "code" in session
    assert "poll_token" in session
    assert "url" in session
    assert "expires_at" in session
    assert session["url"].startswith("https://broker.linkauth.io/connect/")

    session_id = session["session_id"]
    code = session["code"]
    poll_token = session["poll_token"]

    # Step 2: Poll — should be PENDING
    r = httpx.get(
        f"{BASE_URL}/v1/sessions/{session_id}",
        headers={"Authorization": f"Bearer {poll_token}"},
        timeout=10,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "pending"

    # Step 3: Get session info (frontend endpoint)
    r = httpx.get(f"{BASE_URL}/v1/connect/{code}", timeout=10)
    assert r.status_code == 200
    info = r.json()
    assert info["status"] == "pending"
    assert info["code"] == code
    assert info["template_type"] == "form"

    # Step 4: Confirm code
    r = httpx.post(f"{BASE_URL}/v1/connect/{code}/confirm", timeout=10)
    assert r.status_code == 200
    confirm = r.json()
    assert "connect_token" in confirm
    connect_token = confirm["connect_token"]

    # Step 5: Confirm again should fail (already confirmed)
    r = httpx.post(f"{BASE_URL}/v1/connect/{code}/confirm", timeout=10)
    assert r.status_code == 409

    # Step 6: Encrypt credentials (simulate browser) and complete
    credentials = {"api_key": "sk-test-integration-12345"}
    aes_key = AESGCM.generate_key(bit_length=256)
    iv = b'\x00' * 12  # simple IV for testing
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(iv, json.dumps(credentials).encode(), None)

    pub_key = private_key.public_key()
    wrapped = pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    payload = {
        "wrapped_key": base64.b64encode(wrapped).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }
    ciphertext_b64 = base64.b64encode(json.dumps(payload).encode()).decode()

    r = httpx.post(
        f"{BASE_URL}/v1/connect/{code}/complete",
        json={
            "ciphertext": ciphertext_b64,
            "algorithm": "RSA-OAEP-256+AES-256-GCM",
            "connect_token": connect_token,
        },
        timeout=10,
    )
    assert r.status_code == 204, f"Complete failed: {r.text}"

    # Step 7: Poll — should be READY with ciphertext
    time.sleep(1)
    r = httpx.get(
        f"{BASE_URL}/v1/sessions/{session_id}",
        headers={"Authorization": f"Bearer {poll_token}"},
        timeout=10,
    )
    assert r.status_code == 200
    result = r.json()
    assert result["status"] == "ready"
    assert result["ciphertext"] is not None
    assert result["algorithm"] == "RSA-OAEP-256+AES-256-GCM"

    # Step 8: Decrypt and verify
    decrypted = _decrypt_payload(private_key, result["ciphertext"])
    assert decrypted == credentials

    # Step 9: Poll again — should be consumed (one-time retrieval)
    time.sleep(6)  # respect poll interval
    r = httpx.get(
        f"{BASE_URL}/v1/sessions/{session_id}",
        headers={"Authorization": f"Bearer {poll_token}"},
        timeout=10,
    )
    # After consumption, session is gone or shows consumed
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert r.json()["status"] in ("consumed", "pending")


# ---------------------------------------------------------------------------
# 5. Proxy Endpoint
# ---------------------------------------------------------------------------

def test_proxy_get_public_api():
    """Proxy a GET request to a public API."""
    r = httpx.post(
        f"{BASE_URL}/v1/proxy",
        headers=HEADERS,
        json={
            "method": "GET",
            "url": "https://httpbin.org/get",
            "timeout": 15,
        },
        timeout=20,
    )
    assert r.status_code == 200, f"Proxy failed: {r.text}"
    data = r.json()
    assert data["status_code"] == 200
    body = json.loads(data["body"])
    assert "headers" in body


def test_proxy_post_echo():
    """Proxy a POST to httpbin and verify the body is forwarded."""
    payload = json.dumps({"test": "integration", "timestamp": time.time()})
    r = httpx.post(
        f"{BASE_URL}/v1/proxy",
        headers=HEADERS,
        json={
            "method": "POST",
            "url": "https://httpbin.org/post",
            "headers": {"Content-Type": "application/json"},
            "body": payload,
            "timeout": 15,
        },
        timeout=20,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status_code"] == 200
    body = json.loads(data["body"])
    assert body["data"] == payload


def test_proxy_ssrf_blocked():
    """Proxy to a private IP should be blocked."""
    r = httpx.post(
        f"{BASE_URL}/v1/proxy",
        headers=HEADERS,
        json={
            "method": "GET",
            "url": "http://169.254.169.254/latest/meta-data/",
            "timeout": 5,
        },
        timeout=15,
    )
    # Should be blocked — either 403 (SSRF blocked) or 502 (connection refused)
    assert r.status_code in (403, 502), f"Expected SSRF block, got {r.status_code}: {r.text}"


def test_proxy_invalid_method():
    """Invalid HTTP method should return 422."""
    r = httpx.post(
        f"{BASE_URL}/v1/proxy",
        headers=HEADERS,
        json={"method": "HACK", "url": "https://example.com"},
        timeout=10,
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# 6. Webhook Relay
# ---------------------------------------------------------------------------

def test_webhook_relay_full_flow():
    """Create session with webhook, POST to webhook URL, poll for encrypted result."""
    private_key, pub_b64 = _generate_keypair()

    # Step 1: Create session with webhook enabled
    r = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=HEADERS,
        json={
            "public_key": pub_b64,
            "template": "custom",
            "display_name": "Webhook Test",
            "fields": [{"name": "status", "label": "Status", "type": "text"}],
            "enable_webhook": True,
        },
        timeout=10,
    )
    assert r.status_code == 201, f"Create failed: {r.text}"
    session = r.json()
    assert session["webhook_url"] is not None
    webhook_url = session["webhook_url"]
    session_id = session["session_id"]
    poll_token = session["poll_token"]

    assert "token=wt_" in webhook_url

    # Step 2: POST a webhook payload (simulating external service)
    webhook_payload = {"type": "payment.success", "id": "evt_test_123", "amount": 4999}
    r = httpx.post(
        webhook_url,
        json=webhook_payload,
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    assert r.status_code == 200, f"Webhook relay failed: {r.text}"
    assert r.json()["status"] == "accepted"

    # Step 3: Poll for the encrypted webhook payload
    time.sleep(1)
    r = httpx.get(
        f"{BASE_URL}/v1/sessions/{session_id}",
        headers={"Authorization": f"Bearer {poll_token}"},
        timeout=10,
    )
    assert r.status_code == 200
    result = r.json()
    assert result["status"] == "ready"
    assert result["ciphertext"] is not None

    # Step 4: Decrypt and verify the webhook payload
    decrypted = _decrypt_payload(private_key, result["ciphertext"])
    assert decrypted["content_type"] == "application/json"
    body = json.loads(decrypted["body"])
    assert body["type"] == "payment.success"
    assert body["id"] == "evt_test_123"
    assert body["amount"] == 4999


def test_webhook_wrong_token():
    """Webhook with wrong token should be rejected."""
    private_key, pub_b64 = _generate_keypair()

    r = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=HEADERS,
        json={
            "public_key": pub_b64,
            "template": "api_key",
            "enable_webhook": True,
        },
        timeout=10,
    )
    assert r.status_code == 201
    session = r.json()
    session_id = session["session_id"]

    # Use wrong token
    r = httpx.post(
        f"{BASE_URL}/v1/sessions/{session_id}/webhook?token=wt_wrong_token",
        json={"test": True},
        timeout=10,
    )
    assert r.status_code == 403


def test_webhook_no_token():
    """Webhook without token should be rejected."""
    private_key, pub_b64 = _generate_keypair()

    r = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=HEADERS,
        json={
            "public_key": pub_b64,
            "template": "api_key",
            "enable_webhook": True,
        },
        timeout=10,
    )
    assert r.status_code == 201
    session_id = r.json()["session_id"]

    r = httpx.post(
        f"{BASE_URL}/v1/sessions/{session_id}/webhook",
        json={"test": True},
        timeout=10,
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# 7. Callback URL Validation
# ---------------------------------------------------------------------------

def test_callback_url_requires_https():
    """Non-localhost HTTP callback URL should be rejected."""
    _, pub_b64 = _generate_keypair()

    r = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=HEADERS,
        json={
            "public_key": pub_b64,
            "template": "api_key",
            "callback_url": "http://evil.example.com/callback",
        },
        timeout=10,
    )
    assert r.status_code == 400
    assert "HTTPS" in r.json()["detail"] or "https" in r.json()["detail"].lower()


def test_callback_url_https_accepted():
    """HTTPS callback URL should be accepted."""
    _, pub_b64 = _generate_keypair()

    r = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=HEADERS,
        json={
            "public_key": pub_b64,
            "template": "api_key",
            "callback_url": "https://my-agent.example.com/ready",
        },
        timeout=10,
    )
    assert r.status_code == 201
    session = r.json()
    assert session["callback_secret"] is not None
    assert session["callback_secret"].startswith("cs_")


# ---------------------------------------------------------------------------
# 8. Poll Token Security
# ---------------------------------------------------------------------------

def test_poll_wrong_token():
    """Polling with wrong token should be rejected."""
    _, pub_b64 = _generate_keypair()

    r = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=HEADERS,
        json={"public_key": pub_b64, "template": "api_key"},
        timeout=10,
    )
    assert r.status_code == 201
    session_id = r.json()["session_id"]

    r = httpx.get(
        f"{BASE_URL}/v1/sessions/{session_id}",
        headers={"Authorization": "Bearer pt_wrong_token"},
        timeout=10,
    )
    assert r.status_code == 403


def test_poll_missing_auth():
    """Polling without Authorization header should be rejected."""
    _, pub_b64 = _generate_keypair()

    r = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=HEADERS,
        json={"public_key": pub_b64, "template": "api_key"},
        timeout=10,
    )
    assert r.status_code == 201
    session_id = r.json()["session_id"]

    r = httpx.get(f"{BASE_URL}/v1/sessions/{session_id}", timeout=10)
    assert r.status_code == 401
