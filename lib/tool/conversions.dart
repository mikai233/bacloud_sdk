import 'dart:typed_data';

Uint8List int32BigEndianBytes(int value) =>
    Uint8List(4)..buffer.asByteData().setInt32(0, value, Endian.big);

extension ExtInt on int {
  Uint8List toUint8List() {
    var bd = ByteData(4)..setInt32(0, this);
    return bd.buffer.asUint8List();
  }
}
