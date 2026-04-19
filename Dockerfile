# --- Build Stage ---
FROM rust:1-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/rln
COPY . .

# Build the application
# Using --release for production-ready binary
RUN cargo build --release

# --- Runtime Stage ---
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libsqlite3-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create data directory for SQLite and config
RUN mkdir -p /data
VOLUME /data

# Copy the binary from the builder stage
COPY --from=builder /usr/src/rln/target/release/lan-asin /usr/local/bin/lan-asin

# Set environment variables
ENV RLN_DATA_DIR=/data

# Entrypoint
ENTRYPOINT ["lan-asin"]
CMD ["--dashboard"]
