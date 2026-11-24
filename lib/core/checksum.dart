import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math' as math;

import 'package:crypto/crypto.dart';
import 'package:ffi/ffi.dart';

import 'cng_hash.dart';

/// 一次流式扫描同时产出整包校验与分段校验，避免 1GB 文件读多遍。
class ChecksumReport {
  ChecksumReport({
    required this.fileSize,
    required this.totalMd5,
    required this.totalSha1,
    required this.totalSha256,
    required this.endPositions,
    required this.segmentMd5,
    required this.elapsed,
    required this.usedCng,
  });

  final int fileSize;
  final String totalMd5;
  final String totalSha1;
  final String totalSha256;
  final List<int> endPositions;

  /// 与 OTA 响应里 `segmentMd5[].md5` 一一对应。
  final List<String> segmentMd5;

  /// 实际耗时，用于日志。
  final Duration elapsed;

  /// 是否走了 Windows CNG 原生哈希。
  final bool usedCng;

  /// 可直接粘进 `YDPen.js` 的 `segmentMd5` 数组片段。
  String segmentJson() {
    if (segmentMd5.isEmpty) return '[]';
    final parts = <String>[];
    var start = 0;
    for (var i = 0; i < segmentMd5.length; i++) {
      final end = i < endPositions.length ? endPositions[i] : fileSize;
      parts.add('{"num":$i,"startpos":$start,"md5":"${segmentMd5[i]}","endpos":$end}');
      start = end;
    }
    return '[${parts.join(',')}]';
  }
}

class _DigestSink implements Sink<Digest> {
  String value = '';

  @override
  void add(Digest data) => value = data.toString();

  @override
  void close() {}
}

const int _readChunk = 4 << 20;

typedef _Digests = ({String md5, String sha1, String sha256, List<String> segments});

/// 计算整包与分段校验。
///
/// 优先用 Windows CNG 原生哈希（约 200~400 MB/s），
/// 拿不到就回退到 package:crypto（约 60 MB/s），保证功能不丢。
Future<ChecksumReport> computeChecksums(
  File file, {
  List<int> endPositions = const [],
  void Function(int done, int total)? onProgress,
}) async {
  final total = await file.length();
  final sw = Stopwatch()..start();

  var usedCng = false;
  _Digests result;
  if (CngHasher.available) {
    final cng = await _computeWithCng(file, total, endPositions, onProgress);
    if (cng != null) {
      result = cng;
      usedCng = true;
    } else {
      result = await _computeWithCrypto(file, total, endPositions, onProgress);
    }
  } else {
    result = await _computeWithCrypto(file, total, endPositions, onProgress);
  }

  sw.stop();
  return ChecksumReport(
    fileSize: total,
    totalMd5: result.md5,
    totalSha1: result.sha1,
    totalSha256: result.sha256,
    endPositions: endPositions,
    segmentMd5: result.segments,
    elapsed: sw.elapsed,
    usedCng: usedCng,
  );
}

/// CNG 路径：文件直接读进原生缓冲，哈希时零拷贝。失败返回 null。
Future<_Digests?> _computeWithCng(
  File file,
  int total,
  List<int> ends,
  void Function(int, int)? onProgress,
) async {
  final md5H = CngHasher.create('MD5');
  final sha1H = CngHasher.create('SHA1');
  final sha256H = CngHasher.create('SHA256');
  if (md5H == null || sha1H == null || sha256H == null) {
    md5H?.dispose();
    sha1H?.dispose();
    sha256H?.dispose();
    return null;
  }

  final segments = <String>[];
  var segIdx = 0;
  var segH = ends.isEmpty ? null : CngHasher.create('MD5');
  if (ends.isNotEmpty && segH == null) {
    md5H.dispose();
    sha1H.dispose();
    sha256H.dispose();
    return null;
  }

  final bufPtr = calloc<Uint8>(_readChunk);
  final view = bufPtr.asTypedList(_readChunk);
  final raf = await file.open();
  var read = 0;
  var lastPct = -1;

  try {
    while (true) {
      final n = await raf.readInto(view);
      if (n <= 0) break;

      md5H.addPointer(bufPtr, n);
      sha1H.addPointer(bufPtr, n);
      sha256H.addPointer(bufPtr, n);

      if (segH != null) {
        var pos = 0;
        while (pos < n && segH != null) {
          final abs = read + pos;
          final limit = ends[segIdx];
          final take = math.min(n - pos, limit - abs);
          if (take > 0) {
            segH.addPointer(bufPtr + pos, take);
            pos += take;
          }
          if (abs + take >= limit) {
            segments.add(segH.finish(16) ?? '');
            segH.dispose();
            segIdx++;
            segH = segIdx < ends.length ? CngHasher.create('MD5') : null;
          }
        }
      }

      read += n;
      final pct = total == 0 ? 0 : read * 100 ~/ total;
      if (onProgress != null && pct != lastPct && pct % 5 == 0) {
        lastPct = pct;
        onProgress(read, total);
      }
    }

    // 注意：摘要必须在 dispose 之前取，否则拿到空值
    final md5Hex = md5H.finish(16) ?? '';
    final sha1Hex = sha1H.finish(20) ?? '';
    final sha256Hex = sha256H.finish(32) ?? '';
    return (
      md5: md5Hex,
      sha1: sha1Hex,
      sha256: sha256Hex,
      segments: segments,
    );
  } catch (_) {
    return null;
  } finally {
    await raf.close();
    calloc.free(bufPtr);
    md5H.dispose();
    sha1H.dispose();
    sha256H.dispose();
    segH?.dispose();
  }
}

/// 回退路径：package:crypto。
Future<_Digests> _computeWithCrypto(
  File file,
  int total,
  List<int> ends,
  void Function(int, int)? onProgress,
) async {
  final md5Sink = _DigestSink();
  final md5In = md5.startChunkedConversion(md5Sink);
  final sha1Sink = _DigestSink();
  final sha1In = sha1.startChunkedConversion(sha1Sink);
  final sha256Sink = _DigestSink();
  final sha256In = sha256.startChunkedConversion(sha256Sink);

  final segments = <String>[];
  var segIdx = 0;
  _DigestSink? segSink;
  ByteConversionSink? segIn;

  void startSegment() {
    segSink = _DigestSink();
    segIn = md5.startChunkedConversion(segSink!);
  }

  if (ends.isNotEmpty) startSegment();

  var read = 0;
  var lastPct = -1;
  await for (final chunk in file.openRead()) {
    md5In.add(chunk);
    sha1In.add(chunk);
    sha256In.add(chunk);

    var rest = chunk;
    while (ends.isNotEmpty && rest.isNotEmpty && segIdx < ends.length) {
      final chunkStart = read;
      final pos = chunk.length - rest.length;
      final abs = chunkStart + pos;
      final limit = ends[segIdx];
      final available = limit - abs;
      if (available <= 0) {
        segIn!.close();
        segments.add(segSink!.value);
        segIdx++;
        if (segIdx >= ends.length) {
          segIn = null;
          segSink = null;
          break;
        }
        startSegment();
        continue;
      }
      final take = rest.length < available ? rest.length : available;
      segIn!.add(rest.sublist(0, take));
      rest = rest.sublist(take);
    }

    read += chunk.length;
    final pct = total == 0 ? 0 : read * 100 ~/ total;
    if (onProgress != null && pct != lastPct && pct % 5 == 0) {
      lastPct = pct;
      onProgress(read, total);
    }
  }

  md5In.close();
  sha1In.close();
  sha256In.close();
  final byteSink = segIn;
  final digestSink = segSink;
  if (ends.isNotEmpty && byteSink != null && digestSink != null) {
    byteSink.close();
    segments.add(digestSink.value);
  }

  return (
    md5: md5Sink.value,
    sha1: sha1Sink.value,
    sha256: sha256Sink.value,
    segments: segments,
  );
}

/// 解析用户输入的 `endpos` 列表（支持逗号/空格/换行分隔）。
List<int> parseEndPositions(String input) {
  final parts = input.split(RegExp(r'[\s,;]+')).where((s) => s.trim().isNotEmpty);
  final result = <int>[];
  for (final p in parts) {
    final v = int.tryParse(p.trim());
    if (v == null || v <= 0) {
      throw FormatException('无法解析分段边界: $p');
    }
    result.add(v);
  }
  result.sort();
  return result;
}
