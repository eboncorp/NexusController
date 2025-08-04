# NexusController v2.0 Docker Image
FROM python:3.11-slim

LABEL maintainer="NexusController Team"
LABEL version="2.0.0"
LABEL description="Enterprise Infrastructure Management Platform"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    openssh-client \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 nexus && \
    mkdir -p /app && \
    chown nexus:nexus /app

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p data logs plugins keys && \
    chown -R nexus:nexus /app && \
    chmod 700 data keys

# Switch to app user
USER nexus

# Expose ports
EXPOSE 8080 8765 8081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["python3", "nexus_controller_v2.py"]