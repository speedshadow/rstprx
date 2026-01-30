FROM rust:1.75-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/rama-elite-proxy /usr/local/bin/rama-elite-proxy
COPY config.yaml /app/config.yaml

RUN mkdir -p /app/data /app/logs /app/certs

EXPOSE 8443

ENV RUST_LOG=info

CMD ["rama-elite-proxy", "--config", "/app/config.yaml"]
