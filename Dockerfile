FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Dependencies first (cache layer — doesn't install the project itself)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --extra oauth --no-install-project

# Application code + install project
COPY src/ ./src/
COPY config.yaml entrypoint.sh ./
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh && uv sync --frozen --no-dev --extra oauth

# Data directory for SQLite + non-root user
RUN mkdir -p /app/data && \
    adduser --disabled-password --no-create-home linkauth && \
    chown -R linkauth:linkauth /app/data

USER linkauth

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD [".venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]

ENTRYPOINT ["./entrypoint.sh"]
