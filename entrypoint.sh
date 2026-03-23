#!/bin/sh
set -e

# Fix ownership of mounted volumes (runs as root)
chown -R linkauth:linkauth /app/data /app/logs

if [ -z "$LINKAUTH_API_KEYS" ]; then
    LINKAUTH_API_KEYS=$(.venv/bin/python -c "import secrets; print(secrets.token_urlsafe(32))")
    export LINKAUTH_API_KEYS
    echo ""
    echo "=========================================="
    echo "  Auto-generated API key (no LINKAUTH_API_KEYS set):"
    echo "  $LINKAUTH_API_KEYS"
    echo ""
    echo "  Use this in your agent requests:"
    echo "  X-API-Key: $LINKAUTH_API_KEYS"
    echo "=========================================="
    echo ""
fi

# Drop privileges and run as linkauth
exec gosu linkauth .venv/bin/uvicorn broker.main:app --host 0.0.0.0 --port 8080
