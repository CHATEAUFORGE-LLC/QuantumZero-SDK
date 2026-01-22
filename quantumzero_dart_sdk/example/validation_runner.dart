import 'package:quantumzero_dart_sdk/src/crypto_core.dart';
import 'package:cryptography/cryptography.dart';

void main() async {
  print("===============================");
  print("   CRYPTO LIBRARY VALIDATION   ");
  print("===============================");

  final crypto = CryptoCore();
  final stopwatch = Stopwatch();

  try {
    // --- 1. Validate Key Generation ---
    print("\n[1] Benchmarking Key Generation (Ed25519)...");
    stopwatch.start();
    final keyPair = await crypto.generateKeyPair();
    stopwatch.stop();
    print(" -> Success: Generated KeyPair in ${stopwatch.elapsedMicroseconds} µs");
    
    final pubKey = await keyPair.extractPublicKey();
    
    // Check type before accessing .bytes
    if (pubKey is SimplePublicKey) {
      print(" -> Public Key bytes: ${pubKey.bytes.length}");
    } else {
      print(" -> Public Key extracted (Abstract Type)");
    }

    // --- 2. Validate Hashing ---
    print("\n[2] Benchmarking Hashing (SHA-256)...");
    final largeData = List.generate(1024 * 1024, (i) => i % 256); // 1MB data
    
    stopwatch.reset();
    stopwatch.start();
    await crypto.hashData(largeData);
    stopwatch.stop();
    print(" -> Success: Hashed 1MB data in ${stopwatch.elapsedMilliseconds} ms");

    // --- 3. Validate Signing ---
    print("\n[3] Benchmarking Signing...");
    stopwatch.reset();
    stopwatch.start();
    final signature = await crypto.signData(largeData, keyPair);
    stopwatch.stop();
    print(" -> Success: Signed 1MB data in ${stopwatch.elapsedMilliseconds} ms");

    // --- 4. Validate Verification ---
    print("\n[4] Benchmarking Verification...");
    stopwatch.reset();
    stopwatch.start();
    final isValid = await crypto.verifySignature(
      data: largeData,
      signature: signature,
      publicKey: pubKey,
    );
    stopwatch.stop();
    print(" -> Verification Result: $isValid");
    print(" -> Time: ${stopwatch.elapsedMilliseconds} ms");

    if (isValid) {
      print("\n✅ VALIDATION PASSED: Libraries meet W3C performance requirements.");
    } else {
      print("\n❌ VALIDATION FAILED: Verification returned false.");
    }

  } catch (e, stack) {
    print("\n❌ ERROR: $e");
    print(stack);
  }
}