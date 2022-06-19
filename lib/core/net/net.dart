import 'dart:io';
import 'dart:typed_data';

import 'package:bacloud_sdk/core/net/constant.dart';
import 'package:bacloud_sdk/core/tea.dart';
import 'package:bacloud_sdk/tool/conversions.dart';
import 'package:event_bus/event_bus.dart';
import 'package:protobuf/protobuf.dart';

class BacloudNet {
  late SecureSocket _socket;

  late WebSocket _webSocket;

  var _socketConnected = false;

  var _wsSocketConnected = false;

  final List<int> _readBuffer = [];

  Uint8List _shareKey = Uint8List(0);

  final eventBus = EventBus(sync: true);

  final Map<int, Function(List<int>, ExtensionRegistry)> reqProtoIdToParser;

  final Map<Type, int> reqProtoTypeToProtoId;

  final Map<int, Function(List<int>, ExtensionRegistry)> respProtoIdToParser;

  final Map<Type, int> respProtoTypeToProtoId;

  BacloudNet(
      {required this.reqProtoIdToParser,
      required this.reqProtoTypeToProtoId,
      required this.respProtoIdToParser,
      required this.respProtoTypeToProtoId});

  Future<void> connectSocket(host, int port,
      {sourceAddress, int sourcePort = 0, Duration? timeout}) async {
    if (_wsSocketConnected) {
      throw Exception("socket already connected");
    }
    _socketConnected = true;
    _socket = await SecureSocket.connect(host, port, timeout: timeout,
        onBadCertificate: (c) {
      return true;
    });
    _socket.listen(_onData, onError: _onError, onDone: _onDone);
  }

  Future<void> connectWSSocket(String url,
      {Iterable<String>? protocols,
      Map<String, dynamic>? headers,
      CompressionOptions compression = CompressionOptions.compressionDefault,
      HttpClient? customClient}) async {
    if (_socketConnected) {
      throw Exception("web socket already connected");
    }
    _wsSocketConnected = true;
    _webSocket = await WebSocket.connect(url,
        protocols: protocols,
        headers: headers,
        compression: compression,
        customClient: customClient);
  }

  Future<dynamic> closeSocket() async {
    await _socket.flush();
    _socket.listen((event) {});
    return _socket.close();
  }

  Future<dynamic> closeWSSocket([int? code, String? reason]) async {
    return _webSocket.close();
  }

  setShareKey(Uint8List shareKey) {
    _shareKey = shareKey;
  }

  writeMessage(GeneratedMessage msg) async {
    if (!_socketConnected && !_wsSocketConnected) {
      throw Exception('socket not connect');
    }
    final protoId = reqProtoTypeToProtoId[msg.runtimeType];
    if (protoId == null) {
      throw Exception("msg:${msg.runtimeType} proto id not found");
    }
    final protobufData =
        Uint8List.fromList(protoId.toUint8List() + msg.writeToBuffer());
    // final lz4EncodedData = await Api().sdk.lz4Encode(data: protobufData);
    // final lz4Data =
    //     Uint8List.fromList(protobufData.length.toUint8List() + lz4EncodedData);
    final lz4Data =
        Uint8List.fromList(protobufData.length.toUint8List() + protobufData);
    final encrypted =
        _shareKey.isNotEmpty ? TEA.encrypt(lz4Data, _shareKey) : lz4Data;
    final finalPacket = Uint8List.fromList(
        (nettyPackageHeaderLen + encrypted.length).toUint8List() + encrypted);
    _socket.add(finalPacket);
  }

  _onData(Uint8List data) {
    _readBuffer.addAll(data);
    _decodeMessage();
  }

  _onError(Object err) {
    print("error:$err");
  }

  _onDone() {
    print("done");
  }

  _decodeMessage() async {
    while (_readBuffer.length >= nettyPackageHeaderLen) {
      final byteData = Uint8List.fromList(_readBuffer).buffer.asByteData();
      final packageLen = byteData.getInt32(0);
      if (byteData.lengthInBytes < packageLen) {
        return;
      }
      final packetBody = byteData.buffer.asUint8List(nettyPackageHeaderLen);
      final decrypted = _shareKey.isNotEmpty
          ? TEA.decrypt(packetBody, _shareKey)
          : Uint8List.fromList(packetBody);
      // final decoded = await Api()
      //     .sdk
      //     .lz4Decode(data: decrypted.buffer.asUint8List(lz4HeaderLen));
      final decoded = decrypted.buffer.asUint8List(lz4HeaderLen);
      final protoId = decoded.buffer.asByteData().getInt32(lz4HeaderLen);
      final parser = respProtoIdToParser[protoId] ??
          (throw Exception("proto id:$protoId parser not found"));
      final messageBytes = decoded.sublist(nettyPackageHeaderLen);
      final message = parser.call(messageBytes, ExtensionRegistry.EMPTY);
      eventBus.fire(message);
      // await handler.dispatchMessage(message);
      _readBuffer.removeRange(0, packageLen);
    }
  }
}
