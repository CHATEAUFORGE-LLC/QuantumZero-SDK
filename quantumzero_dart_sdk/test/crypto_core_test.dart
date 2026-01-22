import 'package:test/test.dart';
import 'package:quantumzero_dart_sdk/src/crypto_core.dart';
import 'package:cryptography/cryptography.dart';

void main() {
  group('CryptoCore Unit Tests', () {
    late CryptoCore crypto;

    setUp(() {
      crypto = CryptoCore();
    });

    test('generateKeyPair creates a valid Ed25519 key pair', () async {
      final keyPair = await crypto.generateKeyPair();
      final pubKey = await keyPair.extractPublicKey();

      // Ed25519 public keys should always be 32 bytes
      if (pubKey is SimplePublicKey) {
         expect(pubKey.bytes.length, equals(32));
      } else {
         fail('Public key was not of expected type SimplePublicKey');
      }
    });

    test('hashData produces a correct SHA-256 hash length', () async {
      final data = [1, 2, 3, 4, 5];
      final hash = await crypto.hashData(data);
      
      // SHA-256 hashes are always 32 bytes (256 bits)
      expect(hash.length, equals(32));
    });

    test('Sign and Verify workflow returns true for valid data', () async {
      final keyPair = await crypto.generateKeyPair();
      final data = [10, 20, 30, 40, 50];

      // 1. Sign
      final signature = await crypto.signData(data, keyPair);
      expect(signature.bytes, isNotEmpty);

      // 2. Verify
      final pubKey = await keyPair.extractPublicKey();
      final isValid = await crypto.verifySignature(
        data: data,
        signature: signature,
        publicKey: pubKey,
      );

      expect(isValid, isTrue);
    });

    test('Verify workflow returns false for tampered data', () async {
      final keyPair = await crypto.generateKeyPair();
      final data = [10, 20, 30];
      final tamperedData = [10, 20, 31]; // Changed last byte

      final signature = await crypto.signData(data, keyPair);
      final pubKey = await keyPair.extractPublicKey();

      final isValid = await crypto.verifySignature(
        data: tamperedData,
        signature: signature,
        publicKey: pubKey,
      );

      expect(isValid, isFalse);
    });
  });
}