# QuantumZero Dart SDK

A specialized Dart library for the QuantumZero Identity Platform. This SDK handles W3C-compliant cryptographic operations, including Ed25519 key generation and signing, to support Decentralized Identity (DID) workflows.

## Features

- **W3C Compliance:** Generates `Ed25519` key pairs compatible with `did:key` standards.
- **Cryptographic Primitives:**
  - **Signing:** Ed25519 (Edwards-curve Digital Signature Algorithm).
  - **Hashing:** SHA-256 (for content addressing and ZKP inputs).
- **Performance Benchmarking:** Includes a built-in validation runner to verify library performance on target devices.

## Getting Started

This package is intended for use within the QuantumZero ecosystem (Mobile App & Backend).

### Prerequisites
- Dart SDK 3.0.0 or higher.

### Installation
Add the dependency to your `pubspec.yaml`:

``` yaml
dependencies:
  quantumzero_dart_sdk:
    path: ./  # Local path if developing locally

```

## Usage

### Generating a Key Pair
```dart
import 'package:quantumzero_dart_sdk/src/crypto_core.dart';

final crypto = CryptoCore();

// Generate a secure, W3C-compliant key pair
final keyPair = await crypto.generateKeyPair();
```

### Signing Data
```dart
final data = [1, 2, 3, 4, 5];
final signature = await crypto.signData(data, keyPair);

print('Signature bytes: ${signature.bytes}');
```

## Validation & Benchmarking
To validate that the cryptographic libraries meet the performance requirements for the QuantumZero project, run the included validation script:

```bash
dart run example/validation_runner.dart
```

## License
Private Capstone Project - National University
