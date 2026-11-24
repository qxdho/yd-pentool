import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// Windows CNG（bcrypt）原生哈希。
///
/// 为什么不用 package:crypto：纯 Dart 实现只有约 50 MB/s，
/// 1 GB 镜像算 4 个哈希要 80 秒。CNG 走系统实现，约 500 MB/s~1 GB/s，
/// 同样 4 个哈希只需几秒。
///
/// 任何一步失败（非 Windows、bcrypt 不可用、算法不支持）都返回 null，
/// 调用方回退到 package:crypto，保证功能不丢。
class CngHasher {
  CngHasher._(this._alg, this._hash, this._object, this._buffer, this._bufferLen);

  final int _alg;
  final int _hash;
  final Pointer<Uint8> _object;
  final Pointer<Uint8> _buffer;
  final int _bufferLen;

  static DynamicLibrary? _lib;
  static bool _probed = false;
  static bool _available = false;

  static const String _bcrypt = 'bcrypt.dll';

  static DynamicLibrary get _dll => _lib ??= DynamicLibrary.open(_bcrypt);

  static bool get available {
    if (!_probed) {
      _probed = true;
      if (!Platform.isWindows) {
        _available = false;
      } else {
        try {
          // 用一个最小实例探测是否可用
          final probe = create('SHA256');
          probe?.dispose();
          _available = probe != null;
        } catch (_) {
          _available = false;
        }
      }
    }
    return _available;
  }

  static int _status(int hr) => hr & 0xffffffff;

  /// 传入 `MD5` / `SHA1` / `SHA256`。失败返回 null。
  static CngHasher? create(String algName) {
    if (!Platform.isWindows) return null;
    try {
      final lib = _dll;
      final open = lib.lookupFunction<
          Int32 Function(Pointer<IntPtr>, Pointer<Utf16>, Pointer<Utf16>, Uint32),
          int Function(Pointer<IntPtr>, Pointer<Utf16>, Pointer<Utf16>, int)>(
        'BCryptOpenAlgorithmProvider',
      );
      final getProp = lib.lookupFunction<
          Int32 Function(IntPtr, Pointer<Utf16>, Pointer<Uint8>, Uint32,
              Pointer<Uint32>, Uint32),
          int Function(
              int, Pointer<Utf16>, Pointer<Uint8>, int, Pointer<Uint32>, int)>(
        'BCryptGetProperty',
      );
      final createHash = lib.lookupFunction<
          Int32 Function(IntPtr, Pointer<IntPtr>, Pointer<Uint8>, Uint32,
              Pointer<Uint8>, Uint32, Uint32),
          int Function(
              int, Pointer<IntPtr>, Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
        'BCryptCreateHash',
      );

      final hAlgPtr = calloc<IntPtr>();
      final algPtr = algName.toNativeUtf16();
      try {
        final st = open(hAlgPtr, algPtr, nullptr, 0);
        if (_status(st) != 0) return null;

        final propName = 'ObjectLength'.toNativeUtf16();
        final sizeOut = calloc<Uint32>();
        final resOut = calloc<Uint32>();
        try {
          final ps = getProp(hAlgPtr.value, propName, sizeOut.cast(),
              sizeOf<Uint32>(), resOut, 0);
          if (_status(ps) != 0) return null;
          final objectLen = sizeOut.value;
          final object = calloc<Uint8>(objectLen);
          final hHashPtr = calloc<IntPtr>();
          final cs = createHash(hAlgPtr.value, hHashPtr, object, objectLen,
              nullptr, 0, 0);
          if (_status(cs) != 0) {
            calloc.free(object);
            return null;
          }
          const bufLen = 4 << 20;
          final buffer = calloc<Uint8>(bufLen);
          return CngHasher._(hAlgPtr.value, hHashPtr.value, object, buffer, bufLen);
        } finally {
          calloc.free(propName);
          calloc.free(sizeOut);
          calloc.free(resOut);
        }
      } finally {
        calloc.free(hAlgPtr);
        calloc.free(algPtr);
      }
    } catch (_) {
      return null;
    }
  }

  /// 追加数据（复用一块 4 MB 原生缓冲，避免每次 add 都分配内存）。
  bool add(Uint8List data) {
    if (data.isEmpty) return true;
    try {
      final hashData = _dll.lookupFunction<
          Int32 Function(IntPtr, Pointer<Uint8>, Uint32, Uint32),
          int Function(int, Pointer<Uint8>, int, int)>('BCryptHashData');
      var offset = 0;
      while (offset < data.length) {
        final take = (data.length - offset) < _bufferLen
            ? data.length - offset
            : _bufferLen;
        _buffer.asTypedList(take).setRange(0, take, data, offset);
        final st = hashData(_hash, _buffer, take, 0);
        if (_status(st) != 0) return false;
        offset += take;
      }
      return true;
    } catch (_) {
      return false;
    }
  }
  /// 直接从原生内存追加（零拷贝，供文件读入原生缓冲后使用）。
  bool addPointer(Pointer<Uint8> data, int length) {
    if (length <= 0) return true;
    try {
      final hashData = _dll.lookupFunction<
          Int32 Function(IntPtr, Pointer<Uint8>, Uint32, Uint32),
          int Function(int, Pointer<Uint8>, int, int)>('BCryptHashData');
      final st = hashData(_hash, data, length, 0);
      return _status(st) == 0;
    } catch (_) {
      return false;
    }
  }
  /// 结束并返回十六进制摘要；失败返回 null。
  String? finish(int digestBytes) {
    try {
      final lib = _dll;
      final finishShot = lib.lookupFunction<
          Int32 Function(IntPtr, Pointer<Uint8>, Uint32, Uint32),
          int Function(int, Pointer<Uint8>, int, int)>('BCryptFinishHash');
      final out = calloc<Uint8>(digestBytes);
      try {
        final st = finishShot(_hash, out, digestBytes, 0);
        if (_status(st) != 0) return null;
        final buf = StringBuffer();
        for (var i = 0; i < digestBytes; i++) {
          buf.write(out[i].toRadixString(16).padLeft(2, '0'));
        }
        return buf.toString();
      } finally {
        calloc.free(out);
      }
    } catch (_) {
      return null;
    }
  }

  void dispose() {
    try {
      final lib = _dll;
      final destroy = lib.lookupFunction<Int32 Function(IntPtr), int Function(int)>(
          'BCryptDestroyHash');
      final close = lib.lookupFunction<Int32 Function(IntPtr, Uint32),
          int Function(int, int)>('BCryptCloseAlgorithmProvider');
      destroy(_hash);
      close(_alg, 0);
    } catch (_) {}
    calloc.free(_object);
  }

  /// 每种算法的摘要字节数。
  static int digestLength(String algName) => switch (algName) {
        'MD5' => 16,
        'SHA1' => 20,
        'SHA256' => 32,
        _ => 32,
      };
}
