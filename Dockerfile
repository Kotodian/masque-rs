# MASQUE server — multi-stage build
# Stage 1: build
FROM rust:1.86 AS builder

RUN apt-get update && apt-get install -y cmake golang-go && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Dependency caching layer: copy manifests + stub sources, build deps first.
COPY Cargo.toml Cargo.lock ./
COPY tests/e2e/masque-e2e/Cargo.toml tests/e2e/masque-e2e/Cargo.toml
RUN mkdir -p src tests/e2e/masque-e2e/src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && echo "fn main() {}" > tests/e2e/masque-e2e/src/main.rs \
    && cargo build --release -p masque 2>/dev/null || true \
    && rm -rf src tests/e2e/masque-e2e/src

# Copy real source and build.
COPY src/ src/
COPY tests/e2e/masque-e2e/ tests/e2e/masque-e2e/
RUN cargo build --release -p masque

# Stage 2: minimal runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates iproute2 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/masque /usr/local/bin/masque

EXPOSE 4433/udp

ENTRYPOINT ["masque"]
