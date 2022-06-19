import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:bacloud_sdk/tool/conversions.dart';

class DecryptionFailedException implements Exception {
  final String? message;

  DecryptionFailedException([this.message]);

  @override
  String toString() {
    return message ?? "DecryptionFailedException";
  }
}

class TEA {
  static const uint32Mask = 0xffffffff;

  static Uint8List _doOption(
      Uint8List data, Uint8List key, int length, bool encrypt) {
    Uint8List mOutput = Uint8List(0);
    Uint8List mInBlock = Uint8List(0);
    int mIndexPos;
    Uint8List mIV = Uint8List(0);
    var mOutPos = 0;
    var mPreOutPos = 0;
    var isFirstBlock = true;
    final mKey = Int64List(4);
    for (var i = 0; i <= 3; i++) {
      mKey[i] = key.pack(i * 4, 4);
    }

    int rand() => Random().nextInt(1 << 32);

    Uint8List encode(Uint8List bytes) {
      var v0 = bytes.pack(0, 4);
      var v1 = bytes.pack(4, 4);
      var sum = 0;
      final delta = 0x9e3779b9;
      for (var i = 0; i <= 15; i++) {
        sum = sum + delta & uint32Mask;
        v0 += (v1 << 4) + mKey[0] ^ v1 + sum ^ (v1 >>> 5) + mKey[1];
        v0 = v0 & uint32Mask;
        v1 += (v0 << 4) + mKey[2] ^ v0 + sum ^ (v0 >>> 5) + mKey[3];
        v1 = v1 & uint32Mask;
      }
      return Uint8List.fromList(
          int32BigEndianBytes(v0) + int32BigEndianBytes(v1));
    }

    Uint8List decode(Uint8List bytes, int offset) {
      var v0 = bytes.pack(offset, 4);
      var v1 = bytes.pack(offset + 4, 4);
      final delta = 0x9e3779b9;
      var sum = delta << 4 & uint32Mask;
      for (var i = 0; i <= 15; i++) {
        v1 -= (v0 << 4) + mKey[2] ^ v0 + sum ^ (v0 >>> 5) + mKey[3];
        v1 = v1 & uint32Mask;
        v0 -= (v1 << 4) + mKey[0] ^ v1 + sum ^ (v1 >>> 5) + mKey[1];
        v0 = v0 & uint32Mask;
        sum = sum - delta & uint32Mask;
      }
      return Uint8List.fromList(
          int32BigEndianBytes(v0) + int32BigEndianBytes(v1));
    }

    encodeOneBlock() {
      mIndexPos = 0;
      while (mIndexPos < 8) {
        mInBlock[mIndexPos] = isFirstBlock
            ? mInBlock[mIndexPos]
            : (mInBlock[mIndexPos] ^ mOutput[mPreOutPos + mIndexPos]);
        mIndexPos++;
      }

      List.copyRange(mOutput, mOutPos, encode(mInBlock), 0, 8);
      mIndexPos = 0;
      while (mIndexPos < 8) {
        var outPos = mOutPos + mIndexPos;
        mOutput[outPos] = (mOutput[outPos] ^ mIV[mIndexPos]);
        mIndexPos++;
      }
      List.copyRange(mIV, 0, mInBlock, 0, 8);
      mPreOutPos = mOutPos;
      mOutPos += 8;
      mIndexPos = 0;
      isFirstBlock = false;
    }

    bool decodeOneBlock(Uint8List ciphertext, int offset, int len) {
      mIndexPos = 0;
      while (mIndexPos < 8) {
        if (mOutPos + mIndexPos < len) {
          mIV[mIndexPos] =
              (mIV[mIndexPos] ^ ciphertext[mOutPos + offset + mIndexPos]);
          mIndexPos++;
          continue;
        }
        return true;
      }
      mIV = decode(mIV, 0);
      mOutPos += 8;
      mIndexPos = 0;
      return true;
    }

    Uint8List internalEncrypt(Uint8List plaintext, int offset, int len) {
      var l = len;
      var o = offset;
      mInBlock = Uint8List(8);
      mIV = Uint8List(8);
      mOutPos = 0;
      mPreOutPos = 0;
      isFirstBlock = true;
      mIndexPos = (l + 10) % 8;
      if (mIndexPos != 0) {
        mIndexPos = 8 - mIndexPos;
      }
      mOutput = Uint8List(mIndexPos + l + 10);
      mInBlock[0] = (rand() & 0xf8 | mIndexPos);
      for (var i = 1; i <= 7; i++) {
        mInBlock[i] = (rand() & 0xff);
      }
      ++mIndexPos;
      for (var i = 0; i <= 7; i++) {
        mIV[i] = 0;
      }

      var g = 0;
      while (g < 2) {
        if (mIndexPos < 8) {
          mInBlock[mIndexPos++] = (rand() & 0xff);
          ++g;
        }
        if (mIndexPos == 8) {
          encodeOneBlock();
        }
      }

      while (l > 0) {
        if (mIndexPos < 8) {
          mInBlock[mIndexPos++] = plaintext[o++];
        }
        if (mIndexPos == 8) {
          encodeOneBlock();
        }
        l--;
      }
      g = 0;
      while (g < 7) {
        if (mIndexPos < 8) {
          mInBlock[mIndexPos++] = 0;
        }
        if (mIndexPos == 8) {
          encodeOneBlock();
        }
        g++;
      }
      return mOutput;
    }

    Uint8List internalDecrypt(Uint8List cipherText, int offset, int len) {
      mIV = decode(cipherText, offset);
      mIndexPos = (mIV[0] & 7).toInt();
      var plen = len - mIndexPos - 10;
      isFirstBlock = true;
      if (plen < 0) {
        _fail();
      }
      mOutput = Uint8List(plen);
      mPreOutPos = 0;
      mOutPos = 8;
      ++mIndexPos;
      var g = 0;
      while (g < 2) {
        if (mIndexPos < 8) {
          ++mIndexPos;
          ++g;
        }
        if (mIndexPos == 8) {
          isFirstBlock = false;
          if (!decodeOneBlock(cipherText, offset, len)) {
            _fail();
          }
        }
      }

      var outpos = 0;
      while (plen != 0) {
        if (mIndexPos < 8) {
          mOutput[outpos++] = isFirstBlock
              ? mIV[mIndexPos]
              : (cipherText[mPreOutPos + offset + mIndexPos] ^ mIV[mIndexPos]);
          ++mIndexPos;
        }
        if (mIndexPos == 8) {
          mPreOutPos = mOutPos - 8;
          isFirstBlock = false;
          if (!decodeOneBlock(cipherText, offset, len)) {
            _fail();
          }
        }
        plen--;
      }
      g = 0;
      while (g < 7) {
        if (mIndexPos < 8) {
          if (cipherText[mPreOutPos + offset + mIndexPos] ^
                  (mIV[mIndexPos]).toInt() !=
              0) {
            _fail();
          } else {
            ++mIndexPos;
          }
        }

        if (mIndexPos == 8) {
          mPreOutPos = mOutPos;
          if (!decodeOneBlock(cipherText, offset, len)) {
            _fail();
          }
        }
        g++;
      }
      return mOutput;
    }

    return encrypt
        ? internalEncrypt(data, 0, length)
        : internalDecrypt(data, 0, length);
  }

  static _fail() {
    throw DecryptionFailedException();
  }

  static Uint8List encrypt(Uint8List source, Uint8List key, {int? length}) =>
      _doOption(source, key, length ?? source.length, true);

  static Uint8List encryptString(String content, Uint8List key) {
    final source = Uint8List.fromList(utf8.encode(content));
    return encrypt(source, key);
  }

  static Uint8List decrypt(Uint8List source, Uint8List key, {int? length}) {
    final len = length ?? source.length;
    if (len % 8 != 0 || len < 16) {
      throw Exception("data must len % 8 == 0 && len >= 16 but given $len");
    }
    return _doOption(source, key, length ?? source.length, false);
  }

  static String decryptString(Uint8List source, Uint8List key) {
    final content = decrypt(source, key);
    return utf8.decode(content);
  }
}

extension TEAExtension on Uint8List {
  int pack(int offset, int len) {
    var result = 0;
    final maxOffset = len > 8 ? offset + 8 : offset + len;
    for (var index = offset; index < maxOffset; index++) {
      result = result << 8 | (this[index] & 0xff);
    }
    return result >> 32 | (result & TEA.uint32Mask);
  }
}
