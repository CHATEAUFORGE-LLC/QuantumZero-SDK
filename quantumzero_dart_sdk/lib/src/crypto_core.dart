import 'package:cryptography/cryptography.dart';

class CryptoCore {
  final SignatureAlgorithm _signingAlgorithm = Ed25519();
  final HashAlgorithm _hashingAlgorithm = Sha256();

  /// Generates a KeyPair compliant with W3C DID standards
  Future<KeyPair> generateKeyPair() async {
    return await _signingAlgorithm.newKeyPair();
  }

  /// Hashes data using SHA-256
  Future<List<int>> hashData(List<int> data) async {
    final hash = await _hashingAlgorithm.hash(data);
    return hash.bytes;
  }

  /// Signs data using the private key
  Future<Signature> signData(List<int> data, KeyPair keyPair) async {
    return await _signingAlgorithm.sign(
      data,
      keyPair: keyPair,
    );
  }

  /// Verifies a signature using the public key
  Future<bool> verifySignature({
    required List<int> data,
    required Signature signature,
    required PublicKey publicKey,
  }) async {
    final signatureWithKey = Signature(
      signature.bytes,
      publicKey: publicKey,
    );

    return await _signingAlgorithm.verify(
      data,
      signature: signatureWithKey,
    );
  }
}