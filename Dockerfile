# ============================================================================
# DAST Standalone — Production Dockerfile
# ============================================================================
# Multi-stage build: deps -> nuclei -> runtime
#
# Usage:
#   UI mode:      docker run -p 5000:5000 dast-standalone
#   Headless:     docker run dast-standalone --headless --target http://example.com
#   With report:  docker run -v $(pwd)/reports:/reports dast-standalone \
#                   --headless --target http://example.com --output /reports/scan.json
# ============================================================================

# ── Stage 1: Python dependencies ────────────────────────────────────────────
FROM python:3.11-slim AS deps

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install \
    -r requirements.txt \
    sqlmap \
    playwright

# ── Stage 2: Nuclei binary ─────────────────────────────────────────────────
FROM golang:1.22-alpine AS nuclei-builder

RUN apk add --no-cache curl jq \
    && NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name') \
    && NUCLEI_VERSION_NUM=${NUCLEI_VERSION#v} \
    && ARCH=$(case "$(uname -m)" in x86_64) echo "amd64";; aarch64) echo "arm64";; *) echo "amd64";; esac) \
    && curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION_NUM}_linux_${ARCH}.zip" -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /tmp/nuclei-bin \
    && chmod +x /tmp/nuclei-bin/nuclei

# ── Stage 3: Runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="DAST Standalone"
LABEL org.opencontainers.image.description="Production DAST security scanner with nmap, sqlmap, nuclei, and Playwright"
LABEL org.opencontainers.image.source="https://github.com/dast-standalone"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DAST_ALLOW_DEFAULT_LOGIN=0 \
    DAST_CSRF_PROTECT=1 \
    DAST_COOKIE_SAMESITE=Strict

# System dependencies: nmap + chromium deps for Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    unzip \
    # Chromium runtime deps (Playwright needs these)
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libatspi2.0-0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libwayland-client0 \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python packages from deps stage
COPY --from=deps /install/lib /usr/local/lib
COPY --from=deps /install/bin /usr/local/bin

# Copy nuclei binary
COPY --from=nuclei-builder /tmp/nuclei-bin/nuclei /usr/local/bin/nuclei

# Install Playwright browsers (chromium only to save space)
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
RUN playwright install chromium --with-deps 2>/dev/null || playwright install chromium || true

# Copy application code
COPY modules/ modules/
COPY wordlists/ wordlists/
COPY templates/ templates/
COPY data/ data/
COPY main.py .
COPY app.py* ./
COPY cli.py .
COPY test_target.py .

# Create non-root user with home dir for tool configs
RUN useradd -m -s /bin/sh dast \
    && mkdir -p /reports /app/dast-results \
    && chown -R dast:dast /app /reports

# Nuclei templates (run as dast user so config is in right place)
USER dast
RUN nuclei -update-templates 2>/dev/null || true

EXPOSE 5000

# Healthcheck: in UI mode, check Flask; in headless, just check process
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/ 2>/dev/null || pgrep -f "python3 main.py" > /dev/null

# Default: UI mode on port 5000
# Override for headless: docker run <image> --headless --target http://...
ENTRYPOINT ["python3", "main.py"]
CMD ["--port", "5000"]
