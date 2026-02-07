FROM rustlang/rust:nightly as builder

WORKDIR /app

# Copy workspace manifests
COPY Cargo.toml ./
COPY quantumzero_rust_sdk/Cargo.toml ./quantumzero_rust_sdk/
COPY issuer_app/Cargo.toml ./issuer_app/

# Copy source code
COPY quantumzero_rust_sdk/src ./quantumzero_rust_sdk/src
COPY quantumzero_rust_sdk/benches ./quantumzero_rust_sdk/benches
COPY issuer_app/src ./issuer_app/src
COPY issuer_app/static ./issuer_app/static

# Build the application
RUN cargo build --release --package issuer_app

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary
COPY --from=builder /app/target/release/issuer_app /app/issuer_app

# Copy static files
COPY issuer_app/static /app/static

ENV RUST_LOG=info
ENV ISSUANCE_API_URL=http://issuance-api:8081
ENV BIND_ADDRESS=0.0.0.0:8090

EXPOSE 8090

CMD ["/app/issuer_app"]
