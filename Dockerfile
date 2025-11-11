# NexusController v2.0 Enhanced Production Docker Image
# Multi-stage build for security and minimal attack surface

#########################################
# Build Stage
#########################################
FROM python:3.11-slim as builder

# Set build-time variables
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=2.0.0

# Add labels for metadata
LABEL org.opencontainers.image.title="NexusController"
LABEL org.opencontainers.image.description="Enterprise Infrastructure Management Platform"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.vendor="NexusController Team"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.url="https://github.com/nexuscontroller/nexuscontroller"
LABEL org.opencontainers.image.source="https://github.com/nexuscontroller/nexuscontroller"

# Install system dependencies for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for faster package installation
RUN pip install --no-cache-dir uv

# Set working directory
WORKDIR /build

# Copy dependency files
COPY requirements.txt pyproject.toml ./

# Create virtual environment and install dependencies
RUN uv venv /opt/venv && \
    . /opt/venv/bin/activate && \
    uv pip install --no-cache-dir -r requirements.txt

#########################################
# Runtime Stage
#########################################
FROM python:3.11-slim as runtime

# Install runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    dumb-init \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create non-root user with specific UID/GID
RUN groupadd -r -g 1000 nexus && \
    useradd -r -g nexus -u 1000 -m -d /app -s /bin/bash nexus

# Set working directory
WORKDIR /app

# Create necessary directories with proper permissions
RUN mkdir -p \
    /app/data \
    /app/logs \
    /app/plugins \
    /app/security_reports \
    /tmp/nexus \
    && chown -R nexus:nexus /app /tmp/nexus \
    && chmod 755 /app \
    && chmod 700 /app/data /app/security_reports \
    && chmod 755 /app/logs /app/plugins

# Copy application files
COPY --chown=nexus:nexus . .

# Set proper permissions for executables
RUN chmod +x scripts/*.sh || true

# Switch to non-root user
USER nexus

# Set environment variables
ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8000 \
    HOST=0.0.0.0 \
    ENVIRONMENT=production \
    LOG_LEVEL=INFO \
    DATABASE_URL=postgresql+asyncpg://nexus:password@db:5432/nexusdb \
    REDIS_URL=redis://redis:6379/0

# Expose port
EXPOSE 8000

# Health check with proper timeout and retries
HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Use dumb-init as PID 1 for proper signal handling
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Default command - run enhanced API server as module
CMD ["python", "-m", "nexuscontroller"]

#########################################
# Development Stage
#########################################
FROM runtime as development

USER root

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    vim \
    htop \
    postgresql-client \
    redis-tools \
    && rm -rf /var/lib/apt/lists/*

# Install development Python packages
RUN . /opt/venv/bin/activate && \
    pip install --no-cache-dir \
    pytest \
    pytest-asyncio \
    pytest-cov \
    ruff \
    mypy \
    ipython \
    debugpy

USER nexus

# Override health check for development (more frequent)
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=2 \
    CMD curl -f http://localhost:8000/health || exit 1

# Development command with auto-reload
CMD ["python", "-m", "uvicorn", "nexus_api_server_enhanced:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]