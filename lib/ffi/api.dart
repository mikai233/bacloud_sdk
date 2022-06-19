import 'dart:ffi';

import 'package:bacloud_sdk/ffi/bridge_generated.dart';

class Api {
  late AkkaImSdkRustImpl sdk;

  Api._internal() {
    final dylibPath =
        '/Users/mikai/CLionProjects/akka_im_sdk_rust/target/release/libim_sdk.dylib';
    final dylib = DynamicLibrary.open(dylibPath);
    sdk = AkkaImSdkRustImpl(dylib);
  }

  factory Api() => _instance;

  static final Api _instance = Api._internal();
}
