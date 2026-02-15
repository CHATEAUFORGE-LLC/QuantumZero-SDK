FROM rustlang/rust:nightly as builder

WORKDIR /app

# Copy workspace manifests
COPY Cargo.toml ./
COPY quantumzero_rust_sdk/Cargo.toml ./quantumzero_rust_sdk/
COPY issuer_app/Cargo.toml ./issuer_app/
COPY verifier_app/Cargo.toml ./verifier_app/

# Copy source code
COPY quantumzero_rust_sdk/src ./quantumzero_rust_sdk/src
COPY quantumzero_rust_sdk/benches ./quantumzero_rust_sdk/benches
COPY issuer_app/src ./issuer_app/src
COPY issuer_app/static ./issuer_app/static
COPY verifier_app/src ./verifier_app/src
COPY verifier_app/static ./verifier_app/static

# Build the application
RUN cargo build --release --package verifier_app

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary
COPY --from=builder /app/target/release/verifier_app /app/verifier_app

# Copy static files
COPY verifier_app/static /app/static

ENV RUST_LOG=info
ENV VERIFICATION_API_URL=http://verification-api:8083
ENV BIND_ADDRESS=0.0.0.0:8091

EXPOSE 8091

CMD ["/app/verifier_app"]
