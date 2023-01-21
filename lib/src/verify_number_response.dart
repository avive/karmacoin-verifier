import 'dart:typed_data';
import 'package:kc_verifier/src/proto/types.pb.dart' as types;
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:kc_verifier/src/proto/types.pb.dart';
import 'package:protobuf/protobuf.dart';

/// An extension class over types.VerifyNumberRequest to support signing and verification
class VerifyNumberResponse {
  final types.VerifyNumberResponse response;
  VerifyNumberResponse(this.response);

  // Sign the response using provided private key
  void sign(ed.PrivateKey privateKey,
      {keyScheme = KeyScheme.KEY_SCHEME_ED25519}) {
    Uint8List signature = ed.sign(privateKey, response.writeToBuffer());
    response.signature =
        Signature(scheme: keyScheme, signature: signature.toList());
  }

  /// verify the signature using the provided verifier public key known to client from genesis config
  bool verifySignature(ed.PublicKey publicKey) {
    types.VerifyNumberResponse message = response.deepCopy();
    message.clearSignature();

    return ed.verify(publicKey, message.writeToBuffer(),
        Uint8List.fromList(response.signature.signature));
  }
}
