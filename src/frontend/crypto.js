/**
 * LinkAuth — Client-side hybrid encryption (RSA-OAEP + AES-256-GCM)
 *
 * 1. Generate random AES-256 key
 * 2. Encrypt credentials with AES-256-GCM
 * 3. Wrap AES key with agent's RSA-OAEP public key
 * 4. Return combined payload as base64
 */

/**
 * Import an RSA public key from base64-encoded SPKI/PEM format.
 */
async function importPublicKey(base64Key) {
  // Strip PEM headers if present
  const stripped = base64Key
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");

  const binaryDer = Uint8Array.from(atob(stripped), (c) => c.charCodeAt(0));

  return crypto.subtle.importKey(
    "spki",
    binaryDer.buffer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["wrapKey"]
  );
}

/**
 * Encrypt credentials using hybrid encryption.
 * Returns a base64-encoded JSON payload containing the wrapped key + ciphertext.
 */
async function encryptCredentials(publicKeyBase64, credentialsObj) {
  const rsaKey = await importPublicKey(publicKeyBase64);

  // 1. Generate random AES-256-GCM key
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true, // extractable (needed for wrapping)
    ["encrypt"]
  );

  // 2. Encrypt credentials with AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(credentialsObj));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    plaintext
  );

  // 3. Wrap AES key with RSA-OAEP
  const wrappedKey = await crypto.subtle.wrapKey("raw", aesKey, rsaKey, {
    name: "RSA-OAEP",
  });

  // 4. Combine into a single JSON payload, base64-encoded
  const payload = {
    wrapped_key: arrayBufferToBase64(wrappedKey),
    iv: arrayBufferToBase64(iv),
    ciphertext: arrayBufferToBase64(ciphertext),
  };

  return btoa(JSON.stringify(payload));
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
