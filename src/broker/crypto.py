"""Public key validation for incoming session requests."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key


def validate_public_key(public_key_b64: str, min_key_size: int = 2048) -> str | None:
    """Validate that the provided string is a valid RSA public key (base64-encoded DER).

    Returns None on success, or an error message string on failure.
    """
    if not public_key_b64 or not public_key_b64.strip():
        return "public_key is required and must not be empty."

    try:
        der_bytes = base64.b64decode(public_key_b64, validate=True)
    except Exception:
        return "public_key is not valid base64. Expected base64-encoded DER (SubjectPublicKeyInfo)."

    try:
        key = load_der_public_key(der_bytes)
    except Exception:
        return "public_key is not a valid public key. Expected RSA SubjectPublicKeyInfo in DER format."

    if not isinstance(key, rsa.RSAPublicKey):
        return f"public_key must be an RSA key, got {type(key).__name__}."

    if key.key_size < min_key_size:
        return f"RSA key too small ({key.key_size} bits). Minimum is {min_key_size} bits."

    return None
