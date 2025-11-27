# Dockerfile for Derusted Test Environment
# Derusted is a library - this container runs the test suite

FROM rust:1.83-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Create directories
RUN mkdir -p /workspace/certs /workspace/logs

# Default: Run test suite
CMD ["cargo", "test", "--lib"]
