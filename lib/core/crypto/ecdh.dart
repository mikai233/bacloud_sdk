import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/export.dart';

class ECDH {
  static final algorithm = X25519();

  static Future<SimpleKeyPair> genKeyPair() async {
    return algorithm.newKeyPair();
  }

  static Future<SecretKey> calculateShareKey(
      KeyPair keyPair, Uint8List remotePublicKey) async {
    return algorithm.sharedSecretKey(
        keyPair: keyPair,
        remotePublicKey:
            SimplePublicKey(remotePublicKey, type: KeyPairType.x25519));
  }
}

String requestDigest(int userId, String deviceId, String token,
    String publicKey, int timestamp) {
  final md5 = MD5Digest();
  final content = "$userId:$deviceId:$token:$publicKey:$timestamp";
  final bytes = utf8.encode(content);
  final result = md5.process(Uint8List.fromList(bytes));
  final text = hex.encode(result);
  return text;
}

String responseDigest(int userId, String publicKey, int timestamp) {
  final md5 = MD5Digest();
  final content = "$userId:$publicKey:$timestamp";
  final bytes = utf8.encode(content);
  final result = md5.process(Uint8List.fromList(bytes));
  final text = hex.encode(result);
  return text;
}

void main() async {
  var t = responseDigest(1, "1", 1);
  print(t);
}
