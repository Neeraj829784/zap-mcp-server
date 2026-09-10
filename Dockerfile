# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Do not buffer stdout/stderr so logs appear promptly in `docker logs`.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# curl is used by the container healthcheck below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source (policy.py is required and must be included).
COPY config.py policy.py zap_client.py server.py ./
COPY tools/ ./tools/

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Non-secret defaults only. ZAP_API_KEY is injected at runtime via compose/.env;
# it is intentionally NOT baked into the image.
ENV ZAP_BASE_URL="http://zap:8080" \
    MCP_HOST="0.0.0.0" \
    MCP_PORT="8000"

# Liveness: the MCP streamable-http endpoint must accept connections. A bare GET
# to /mcp returns HTTP 400 (protocol negotiation is required), which still proves
# the app is serving; we therefore accept any HTTP response and only fail on a
# connection error (curl exit 7) by omitting -f.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -s -o /dev/null "http://localhost:${MCP_PORT}/mcp" || exit 1

CMD ["python", "server.py"]
