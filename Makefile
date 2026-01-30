.PHONY: build run test clean release docker help

help:
	@echo "Elite Rama Proxy - Makefile Commands"
	@echo "===================================="
	@echo "make build      - Build debug version"
	@echo "make release    - Build optimized release version"
	@echo "make run        - Run the proxy server"
	@echo "make test       - Run all tests"
	@echo "make clean      - Clean build artifacts"
	@echo "make docker     - Build Docker image"
	@echo "make lint       - Run clippy linter"
	@echo "make fmt        - Format code"
	@echo "make check      - Check compilation"

build:
	cargo build

release:
	cargo build --release
	@echo "✅ Release build complete: target/release/rama-elite-proxy"

run:
	cargo run -- --config config.yaml

test:
	cargo test --all

clean:
	cargo clean
	rm -rf data/ logs/ certs/*.pem certs/*.key

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

check:
	cargo check --all

docker:
	docker build -t elite-rama-proxy:latest .

install:
	cargo install --path .

dev:
	RUST_LOG=debug cargo run -- --config config.yaml

validate:
	cargo run -- --config config.yaml --validate

benchmark:
	cargo bench

watch:
	cargo watch -x run

all: clean fmt lint test release
	@echo "✅ All tasks completed successfully"
