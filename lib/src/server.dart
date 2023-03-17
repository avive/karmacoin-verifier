import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:grpc/grpc.dart';
import 'package:hex/hex.dart';
import 'package:kc_authenticator/src/proto/auth.pbgrpc.dart';
import 'package:firebase_admin/firebase_admin.dart';
import 'package:firebase_admin/src/auth/user_record.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:quiver/collection.dart';
import 'package:yaml/yaml.dart';

import 'package:cli_util/cli_logging.dart';

class AuthService extends AuthServiceBase {
  App? _firebase_app;
  ed.KeyPair? _verifier_key_pair;
  Logger _logger;
  Map<String, dynamic> _config;

  AuthService(this._logger, this._config);

  Future<void> init() async {
    // todo: get path to creds file from an env var or from config file
    Credential cred = FirebaseAdmin.instance.certFromPath(_config['credsFile']);

    // create an app
    _firebase_app = FirebaseAdmin.instance.initializeApp(
        AppOptions(credential: cred, projectId: _config['projectId']));

    // sanity check
    _logger.stdout('sanity check...');
    try {
      UserRecord v =
          await _firebase_app!.auth().getUserByPhoneNumber("+972549805381");
      _logger.stdout('accountId base64: ${v.displayName}');
    } on FirebaseAuthError catch (e) {
      _logger.stdout('firebase user not found: ${e.message} for +972549805381');
    } on FirebaseException catch (e) {
      _logger.stdout('firebase api result: ${e.message}');
    }

    try {
      UserRecord v =
          await _firebase_app!.auth().getUserByPhoneNumber("+972549805380");
      _logger.stdout('accountId base64: ${v.displayName} for +972549805380');
    } on FirebaseAuthError catch (e) {
      _logger.stdout('firebase user not found: ${e.message}');
    } on FirebaseException catch (e) {
      _logger.stdout('firebase api result: ${e.message}');
    }

    ed.PrivateKey privateKey =
        ed.PrivateKey(HEX.decode(_config['validatorId']));
    ed.PublicKey publicKey = ed.public(privateKey);
    _verifier_key_pair = ed.KeyPair(privateKey, publicKey);

    _logger.stdout(
        'Validator public id: ${HEX.encode(_verifier_key_pair!.publicKey.bytes.toList())}');

    _logger.stdout('Auth server initialized');
  }

  @override
  Future<AuthResponse> authenticate(
      ServiceCall call, AuthRequest request) async {
    _logger.stdout('new request: ${request.toString()}');

    if ((_config['whiteList'] as List<String>).contains(request.phoneNumber)) {
      // Skip whitelisted numbers used in dev testing
      _logger.stdout('White listed number - skipping firebase check');
      AuthResponse response = AuthResponse();
      response.result = AuthResult.AUTH_RESULT_USER_AUTHENTICATED;
      return response;
    }

    if (_firebase_app == null) {
      _logger.stdout('Internal error - firebase app not initialized');
      throw GrpcError.internal('Firebase app not initialized');
    }

    AuthResponse response = AuthResponse();
    String? accunt_id_base64;

    try {
      UserRecord v =
          await _firebase_app!.auth().getUserByPhoneNumber(request.phoneNumber);
      accunt_id_base64 = v.displayName;
    } on FirebaseAuthError catch (e) {
      _logger.stdout('No firebase user found for phone number. ${e.message}');
      response.result = AuthResult.AUTH_RESULT_USER_NOT_FOUND;
    } on FirebaseException catch (e) {
      _logger.stdout('getUserByPhoneNumber result: ${e.message}');
      throw GrpcError.internal('Firebase error: ${e.message}');
    }

    if (accunt_id_base64 == null) {
      _logger.stdout('Phone number not reigstered on firebase');
      response.result = AuthResult.AUTH_RESULT_USER_NOT_FOUND;
    }

    // account id registered on firebase db
    Uint8List verified_account_id = base64Decode(accunt_id_base64!);

    if (!listsEqual(verified_account_id, request.accountId.data)) {
      _logger
          .stdout('Verified account id doesn\'t match the one in the request');
      response.result = AuthResult.AUTH_RESULT_ACCOUNT_ID_MISMATCH;
    }

    _logger.stdout('Verified ${request.phoneNumber}. Returning response...');
    return response;
  }
}

Future<void> main(List<String> args) async {
  Logger logger = Logger.standard();

  // default config values for dev mode. Production config data comes from a file
  Map<String, dynamic> config = {
    'credsFile':
        './creds.json',
    'projectId': 'karmacoin-83d45',
    'validatorId':
        'dcd5e679f97f8fd93186effbf155cc55751ee8f5bc394a19de28d5f901f5455da885bf7ac670b0f01a3551740020e115641005a93f59472002bfd1dc665f4a4e',
    'serverPort': 8080,
    'whiteList': ["+972539805381", "+972549805381", "+972549805382"],
  };

  // override with config file
  String path = 'config.yaml';
  File file = new File(path);
  if (file.existsSync()) {
    logger.stdout('loaded config from file: $path');
    config = loadYaml(file.readAsStringSync());
  }

  AuthService service = AuthService(logger, config);
  await service.init();

  // todo: set secure server for production with cert
  final server = Server(
    [service],
    [],
    CodecRegistry(codecs: const [GzipCodec(), IdentityCodec()]),
  );

  await server.serve(port: config['serverPort']);
  logger.stdout('Auth service grpc server listening on port ${server.port}...');
}
