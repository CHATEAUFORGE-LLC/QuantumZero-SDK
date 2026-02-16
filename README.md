# QuantumZero-SDK
The QuantumZero-SDK repository provides reusable SDKs plus reference issuer/verifier apps and Docker tooling to integrate with the QuantumZero identity platform. The SDKs abstract cryptographic operations and Decentralized Identity (DID) workflows, allowing partners to perform authentication, validate Verifiable Credentials, and interact with Zero-Knowledge Proof (ZKP) challenges using simple, well-documented functions.

## SDK Components

### 1. Dart SDK (`quantumzero_dart_sdk`)
**Target Audience:** Mobile applications and Dart/Flutter developers

**Use Cases:**
- Mobile app DID generation
- Local key generation and secure storage
- Credential signing and verification on mobile devices
- Holder-side cryptographic operations

**Installation:**
```yaml
dependencies:
  quantumzero_dart_sdk:
    git:
      url: https://github.com/CHATEAUFORGE-LLC/QuantumZero-SDK
      path: quantumzero_dart_sdk
```

[View Dart SDK Documentation →](./quantumzero_dart_sdk/README.md)

### 2. Rust SDK (`quantumzero_rust_sdk`)
**Target Audience:** Issuers, verifiers, and backend service integrators

**Use Cases:**
- Issuer registration with QuantumZero service
- Credential schema definition and signing
- Credential issuance workflows
- Backend service DID operations
- Server-side verification

**Installation:**
```toml
[dependencies]
quantumzero_rust_sdk = { git = "https://github.com/CHATEAUFORGE-LLC/QuantumZero-SDK", branch = "main" }
```

[View Rust SDK Documentation →](./quantumzero_rust_sdk/README.md)

## Android Native Library Build (Rust SDK)
This section documents how to build the Android `.so` library (`libquantumzero_rust_sdk.so`) from the Rust SDK and deploy it to the Flutter app.

### Prerequisites
- Android NDK 28.2.13676358 or later
- Rust target `aarch64-linux-android`

Install the NDK (Android Studio SDK Manager or `sdkmanager`):
```bash
sdkmanager --install "ndk;28.2.13676358"
```
Default NDK location: `/home/<user>/Android/Sdk/ndk/28.2.13676358`

Add the Rust target:
```bash
rustup target add aarch64-linux-android
```
Verify the target is installed:
```bash
rustup target list | grep aarch64-linux-android
```

### Build Steps
1. Set environment variables for the NDK toolchain:
```bash
export NDK_HOME=/home/<user>/Android/Sdk/ndk/28.2.13676358
export PATH="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
export CC_aarch64_linux_android=aarch64-linux-android34-clang
export AR_aarch64_linux_android=llvm-ar
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android34-clang
```

2. Optional clean build:
```bash
cd /path/to/QuantumZero-sdk/quantumzero_rust_sdk
cargo clean
```

3. Build the Android library:
```bash
cd /path/to/QuantumZero-sdk/quantumzero_rust_sdk
cargo build --release --target aarch64-linux-android
```

Full command with inline environment variables:
```bash
cd /path/to/QuantumZero-sdk/quantumzero_rust_sdk && NDK_HOME=/home/<user>/Android/Sdk/ndk/28.2.13676358 PATH="/home/<user>/Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH" CC_aarch64_linux_android=aarch64-linux-android34-clang AR_aarch64_linux_android=llvm-ar CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android34-clang cargo build --release --target aarch64-linux-android
```

### Output Location
This repository is a Cargo workspace. The build output is placed in the workspace root `target/` directory, not inside the package subdirectory.

Expected location:
```
/path/to/QuantumZero-sdk/target/aarch64-linux-android/release/libquantumzero_rust_sdk.so
```

Find the library if needed:
```bash
find /path/to/QuantumZero-sdk -name "libquantumzero_rust_sdk.so" -type f
```

### Deploy to Flutter App
1. Copy the library to the Android `jniLibs` directory:
```bash
cp /path/to/QuantumZero-sdk/target/aarch64-linux-android/release/libquantumzero_rust_sdk.so    /path/to/QuantumZero-Mobile/android/app/src/main/jniLibs/arm64-v8a/
```

2. Verify the file is present:
```bash
ls -lh /path/to/QuantumZero-Mobile/android/app/src/main/jniLibs/arm64-v8a/libquantumzero_rust_sdk.so
```

3. Rebuild the Flutter app (hot reload is not sufficient for native libraries):
```bash
cd /path/to/QuantumZero-Mobile
flutter clean
flutter run
```

### Verification
Look for logs in the Flutter console such as:
```
[FFI] Mapped pres_req referent 'X' to wallet cred 'Y'
[AnonCredsFFI] Presentation generated successfully
```

### Troubleshooting
- `error: linker cc not found`: ensure the `CC_aarch64_linux_android` and `CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER` env vars are set.
- `No such file or directory` after build: confirm you are checking the workspace root `target/` directory.
- OpenSSL build errors: build with `--features vendored`.
- Wrong NDK version: verify with `ls ~/Android/Sdk/ndk/`.

### Architecture Notes
| Flutter/Android | Rust Target | JNI Directory |
|----------------|-------------|---------------|
| arm64-v8a | aarch64-linux-android | `jniLibs/arm64-v8a/` |
| armeabi-v7a | armv7-linux-androideabi | `jniLibs/armeabi-v7a/` |
| x86_64 | x86_64-linux-android | `jniLibs/x86_64/` |

Currently only `arm64-v8a` is built and shipped.

## Reference Apps

### Issuer App (`issuer_app`)
- Web UI for DID creation, issuer onboarding, schema/cred-def staging, and issuance
- ACA-Py issuer agent integration with endorser flow support
- QR/OOB invitations for mobile wallet connections
- Sends wallet telemetry to the Issuance API

### Verifier App (`verifier_app`)
- Web UI for proof requests and verification
- ACA-Py verifier agent integration with QR deep links for mobile
- Sends verifier telemetry to the Issuance API

## Interoperability

Both SDKs are designed to be **fully interoperable**:
- Same cryptographic algorithms (Ed25519, SHA-256)
- W3C DID-compliant key generation
- Cross-platform signature verification
- Compatible with QuantumZero service protocols

**Example Workflow:**
1. Issuer uses Rust SDK to generate keys and issue credentials
2. Mobile app uses Dart SDK to generate holder DID and receive credentials
3. Verifier uses either SDK to verify presentations
4. All parties can verify each other's signatures

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                  QuantumZero Service                    │
│                  (Rust Server)                          │
└─────────────────────────────────────────────────────────┘
                         ↕
        ┌────────────────┴────────────────┐
        ↓                                  ↓
┌──────────────────┐              ┌──────────────────┐
│   Rust SDK       │              │   Dart SDK       │
│   (Issuers)      │              │   (Mobile Apps)  │
│                  │              │                  │
│ - Registration   │              │ - DID Generation │
│ - Schema Def     │              │ - Key Storage    │
│ - Credential     │              │ - Signing        │
│   Issuance       │              │ - Verification   │
└──────────────────┘              └──────────────────┘
```

## Primary Features
- **W3C DID-Compliant:** Generates `did:key` compatible key pairs
- **Ed25519 Signing:** Fast, secure elliptic curve cryptography
- **SHA-256 Hashing:** Content addressing and ZKP inputs
- **Hardware Key Support:** P-256 signature verification for Android StrongBox (Rust SDK)
- **Cross-Platform:** Native performance on both Rust and Dart platforms
- **Standardized API:** Consistent interface across languages
- **Reference Apps:** Issuer + verifier portals with ACA-Py integration
- **Well-Tested:** 26+ comprehensive tests and performance benchmarks

## Development Status

| Component | Status | Version |
|-----------|--------|---------|
| Dart SDK  | Stable | 1.0.0 |
| Rust SDK  | Stable | 1.0.0 |
| Issuer App | Preview | 0.1.0 |
| Verifier App | Preview | 0.1.0 |

## Local Dev Stack (Docker Compose)

This repository includes a Docker Compose stack for the issuer/verifier apps, ACA-Py agents, and a tails server for revocation.

**Prereqs:** QuantumZero Server running (Issuance API), Indy ledger network (`indy`), Docker.

**Quick start:**
```bash
# Bash
./deploy.sh
# or
docker compose up -d --build
```

**Access points:**
- Issuer Portal: http://localhost:3030
- Verifier Portal: http://localhost:3031
- Issuer ACA-Py Admin: http://localhost:11001
- Verifier ACA-Py Admin: http://localhost:11002
- Tails Server: http://localhost:6543

**Optional env vars:**
- `QZ_PUBLIC_AGENT_URL` - public issuer agent URL for mobile connections
- `QZ_PUBLIC_VERIFIER_URL` - public verifier agent URL for mobile connections
- `QZ_MOBILE_APP_SCHEME` - deep link scheme (default `quantumzero`)

## Getting Started

### For Mobile Developers
If you're building a mobile application for credential holders:
1. Use the **Dart SDK** ([documentation](./quantumzero_dart_sdk/README.md))
2. Add it to your Flutter project's `pubspec.yaml`
3. Generate DIDs and sign presentations

### For Issuers/Backend Developers
If you're building an issuer service or backend integration:
1. Use the **Rust SDK** ([documentation](./quantumzero_rust_sdk/README.md))
2. Add it to your Rust project's `Cargo.toml`
3. Register with QuantumZero and issue credentials

## Example Use Cases

### Mobile App (Dart SDK)
```dart
import 'package:quantumzero_dart_sdk/src/crypto_core.dart';

final crypto = CryptoCore();
final keyPair = await crypto.generateKeyPair();
final signature = await crypto.signData(data, keyPair);
```

### Issuer Service (Rust SDK)
```rust
use quantumzero_rust_sdk::CryptoCore;

let crypto = CryptoCore::new();
let key_pair = crypto.generate_key_pair();
let signature = crypto.sign_data(&credential_data, &key_pair);
```

## Contributing

This is a private capstone project. For questions or collaboration inquiries, contact ChateauForge LLC.

## License
Private Capstone Project - National University
