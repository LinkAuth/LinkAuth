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

# curl for lightweight healthcheck + gosu for privilege drop + non-root user
RUN apt-get update && apt-get install -y --no-install-recommends curl gosu && rm -rf /var/lib/apt/lists/* && \
    mkdir -p /app/data /app/logs && \
    adduser --disabled-password --no-create-home linkauth

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["curl", "-sf", "http://localhost:8080/health", "-o", "/dev/null"]

ENTRYPOINT ["./entrypoint.sh"]
