import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:fixnum/fixnum.dart';
import 'package:grpc/grpc.dart';
import 'package:kc_verifier/src/proto/types.pb.dart' as t;
import 'package:kc_verifier/src/proto/verifier.pbgrpc.dart' as vt;
import 'package:firebase_admin/firebase_admin.dart';
import 'package:firebase_admin/src/auth/user_record.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:quiver/collection.dart';
import 'package:yaml/yaml.dart';
import 'verify_number_request.dart';
import 'verify_number_response.dart';

import 'package:cli_util/cli_logging.dart';

class VerifierService extends vt.VerifierServiceBase {
  App? _firebase_app;
  ed.KeyPair? _verifier_key_pair;
  Logger? _logger;
  Map<String, dynamic> _config = {};

  Future<void> init(Map<String, dynamic> config, logger) async {
    _config = config;
    _logger = logger;

    // todo: get path to creds file from an env var or from config file
    Credential cred = FirebaseAdmin.instance.certFromPath(_config['credsFile']);

    // create an app
    _firebase_app = FirebaseAdmin.instance.initializeApp(
        AppOptions(credential: cred, projectId: _config['projectId']));

    // sanity check
    try {
      UserRecord v =
          await _firebase_app!.auth().getUserByPhoneNumber("+972549805381");
      _logger!.stdout('accountId base64: ${v.displayName}');
    } on FirebaseAuthError catch (e) {
      _logger!.stdout('firebase user not found: ${e.message}');
    } on FirebaseException catch (e) {
      _logger!.stdout('firebase api result: ${e.message}');
    }

    // todo: generate from private key from config file
    _verifier_key_pair = ed.generateKey();

    _logger!.stdout('server initialized.');
  }

  @override
  Future<t.VerifyNumberResponse> verifyNumber(
      ServiceCall call, vt.VerifyNumberRequest request) async {
    VerifyNumberRequest req = VerifyNumberRequest(request);
    bool verified =
        await req.verify(ed.PublicKey(request.accountId.data as Uint8List));

    if (!verified) {
      throw GrpcError.invalidArgument('Invalid reuqset signature');
    }

    String? accunt_id_base64;

    if (_firebase_app == null) {
      throw GrpcError.internal('Firebase app not initialized');
    }

    try {
      UserRecord v = await _firebase_app!
          .auth()
          .getUserByPhoneNumber(request.mobileNumber.number);
      accunt_id_base64 = v.displayName;
    } on FirebaseAuthError catch (e) {
      _logger!.stdout('No firebase user found for phone number. ${e.message}');
      throw GrpcError.invalidArgument('Phone number not registered');
    } on FirebaseException catch (e) {
      _logger!.stdout('getUserByPhoneNumber result: ${e.message}');
      throw GrpcError.internal('Firebase error: ${e.message}');
    }

    if (accunt_id_base64 == null) {
      throw GrpcError.invalidArgument('Phone number not registered');
    }

    // account id registered on firebase db
    Uint8List verified_account_id = base64Decode(accunt_id_base64);

    if (!listsEqual(verified_account_id, request.accountId.data)) {
      throw GrpcError.invalidArgument(
          'Registered account id does not match the one in the request');
    }

    t.VerifyNumberResponse response = t.VerifyNumberResponse();
    t.AccountId verifier_account_id = t.AccountId();
    verifier_account_id.data = _verifier_key_pair!.publicKey.bytes.toList();
    response.verifierAccountId = verifier_account_id;
    response.accountId = request.accountId;
    response.mobileNumber = request.mobileNumber;
    response.userName = request.requestedUserName;

    // todo: remove result from response - if we send a response it means the number is verified
    response.result = t.VerifyNumberResult.VERIFY_NUMBER_RESULT_VERIFIED;

    response.timestamp = DateTime.now().microsecondsSinceEpoch as Int64;

    VerifyNumberResponse respWrapper = VerifyNumberResponse(response);
    respWrapper.sign(_verifier_key_pair!.privateKey);

    return respWrapper.response;
  }
}

Future<void> main(List<String> args) async {
  Logger logger = Logger.standard();

  // default config values
  Map<String, dynamic> config = {
    "credsFile":
        '/Users/avive/dev/karmacoin-83d45-firebase-adminsdk-5ebsq-19a3b0c61a.json',
    "projectId": 'karmacoin-83d45',
    "serverPort": 8080,
  };

  // override with config file
  String path = 'config.yaml';
  File file = new File(path);
  if (file.existsSync()) {
    logger.stdout('loaded config from file: $path');
    config = loadYaml(file.readAsStringSync());
  }

  VerifierService service = VerifierService();
  await service.init(config, logger);

  final server = Server(
    [service],
    [],
    CodecRegistry(codecs: const [GzipCodec(), IdentityCodec()]),
  );

  // todo: read port from config file
  await server.serve(port: config['serverPort']);
  logger.stdout('Server listening on port ${server.port}...');
}
