import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

/// 一次流式扫描同时产出整包校验与分段校验，避免 1GB 文件读多遍。
class ChecksumReport {
  ChecksumReport({
    required this.fileSize,
    required this.totalMd5,
    required this.totalSha1,
    required this.totalSha256,
    required this.endPositions,
    required this.segmentMd5,
  });

  final int fileSize;
  final String totalMd5;
  final String totalSha1;
  final String totalSha256;
  final List<int> endPositions;

  /// 与 OTA 响应里 `segmentMd5[].md5` 一一对应。
  final List<String> segmentMd5;

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

Future<ChecksumReport> computeChecksums(
  File file, {
  List<int> endPositions = const [],
}) async {
  final md5Sink = _DigestSink();
  final md5In = md5.startChunkedConversion(md5Sink);
  final sha1Sink = _DigestSink();
  final sha1In = sha1.startChunkedConversion(sha1Sink);
  final sha256Sink = _DigestSink();
  final sha256In = sha256.startChunkedConversion(sha256Sink);

  final segResults = <String>[];
  var segIdx = 0;
  _DigestSink? segSink;
  ByteConversionSink? segIn;

  void startSegment() {
    segSink = _DigestSink();
    segIn = md5.startChunkedConversion(segSink!);
  }

  if (endPositions.isNotEmpty) startSegment();

  var consumed = 0;
  await for (final chunk in file.openRead()) {
    md5In.add(chunk);
    sha1In.add(chunk);
    sha256In.add(chunk);
    if (endPositions.isEmpty) continue;

    var rest = chunk;
    while (rest.isNotEmpty) {
      if (segIdx >= endPositions.length) {
        // 所有分段都已结束，剩余数据不再计入分段
        break;
      }
      final limit = endPositions[segIdx];
      final available = limit - consumed;
      if (available <= 0) {
        segIn!.close();
        segResults.add(segSink!.value);
        segIdx++;
        if (segIdx >= endPositions.length) {
          segIn = null;
          segSink = null;
          break;
        }
        startSegment();
        continue;
      }
      final take = rest.length < available ? rest.length : available;
      segIn!.add(_sliceOf(rest, 0, take));
      consumed += take;
      rest = rest.sublist(take);
    }
  }

  md5In.close();
  sha1In.close();
  sha256In.close();

  if (endPositions.isNotEmpty && segIn != null && segSink != null) {
    segIn!.close();
    segResults.add(segSink!.value);
  }

  return ChecksumReport(
    fileSize: await file.length(),
    totalMd5: md5Sink.value,
    totalSha1: sha1Sink.value,
    totalSha256: sha256Sink.value,
    endPositions: endPositions,
    segmentMd5: segResults,
  );
}

List<int> _sliceOf(List<int> src, int start, int end) => src.sublist(start, end);

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
