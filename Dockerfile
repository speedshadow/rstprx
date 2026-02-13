FROM rust:1.93-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies by building with empty src first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && cargo build --release 2>/dev/null || true \
    && rm -rf src

COPY src ./src
COPY templates ./templates

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/rama-elite-proxy /usr/local/bin/rama-elite-proxy
COPY templates ./templates

# Do NOT bake config.yaml into the image — mount it at runtime:
#   docker run -v /path/to/config.yaml:/app/config.yaml ...
# A sample config.yaml is provided in the repo root.

RUN mkdir -p /app/data /app/logs /app/certs

RUN useradd --system --create-home --home-dir /home/proxy --shell /usr/sbin/nologin proxy \
    && chown -R proxy:proxy /app /home/proxy

VOLUME ["/app/data", "/app/logs", "/app/certs"]

EXPOSE 8443

ENV RUST_LOG=info

USER proxy

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD pgrep -x rama-elite-proxy >/dev/null || exit 1

CMD ["rama-elite-proxy", "--config", "/app/config.yaml"]
