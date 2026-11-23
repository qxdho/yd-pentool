import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'auth_script.dart';
import 'hash_util.dart';

class ScanResult {
  ScanResult({
    required this.path,
    required this.fileSize,
    required this.container,
    required this.versionString,
    required this.rkafOffset,
    required this.candidates,
    required this.notes,
  });

  final String path;
  final int fileSize;

  /// `RKFW` / `RAW`
  final String container;
  final String versionString;
  final int rkafOffset;
  final List<AuthScript> candidates;
  final List<String> notes;

  bool get ok => candidates.isNotEmpty;
}

/// 目前已知三代鉴权实现的定位标记。新增机型时优先加标记，而不是加偏移。
const List<String> kAuthMarkers = [
  '/tmp/.adb_auth_verified',
  '/usr/bin/adbd_auth.sh',
  '/usr/bin/adb_auth.sh',
  'adbd_auth.sh',
  'adb_auth.sh',
  'adb shell auth',
  'CherryYoudao',
];

const int _chunk = 8 << 20;
const int _overlap = 8 << 10;
const int _windowBefore = 1 << 10;
const int _windowAfter = 3 << 10;

Future<ScanResult> scanFirmware(File file) async {
  final size = await file.length();
  final notes = <String>[];

  final head = await _readAt(file, 0, 64);
  final magic = head.length >= 4 ? latin1.decode(head.sublist(0, 4), allowInvalid: true) : '';
  final container = magic == 'RKFW' ? 'RKFW' : 'RAW';
  if (container == 'RAW') {
    notes.add('未识别到 RKFW 头，按裸镜像处理（仍可能可用）。');
  }

  var versionString = '';
  var rkafOffset = -1;
  if (container == 'RKFW') {
    versionString = _asciiRun(head, 0x10, 0x60);
    rkafOffset = await _findFirst(file, 'RKAF', limit: 4 << 20);
    if (rkafOffset < 0) notes.add('RKFW 头里没找到 RKAF 区，包结构可能不同。');
  }

  // ---- 扫描标记（字符串搜索，比逐字节比对快两个数量级）----
  final hits = <({int offset, String marker})>[];
  final seen = <String>{};
  final raf = await file.open();
  try {
    var pos = 0;
    var carry = '';
    while (pos < size) {
      await raf.setPosition(pos);
      final buf = await raf.read(_chunk);
      if (buf.isEmpty) break;
      final text = carry + latin1.decode(buf, allowInvalid: true);
      final base = pos - carry.length;
      for (final marker in kAuthMarkers) {
        var idx = text.indexOf(marker);
        while (idx >= 0) {
          final abs = base + idx;
          if (seen.add('$marker@$abs')) {
            hits.add((offset: abs, marker: marker));
          }
          idx = text.indexOf(marker, idx + 1);
        }
      }
      carry = text.length > _overlap ? text.substring(text.length - _overlap) : text;
      pos += buf.length;
    }
  } finally {
    await raf.close();
  }

  // ---- 逐个候选解析 ----
  final candidates = <AuthScript>[];
  final byHashOffset = <int>{};
  for (final hit in hits) {
    if (candidates.length >= 12) break;
    final start = hit.offset - _windowBefore < 0 ? 0 : hit.offset - _windowBefore;
    final raw = await _readAt(file, start, _windowBefore + _windowAfter);
    if (raw.isEmpty) continue;
    final window = latin1.decode(raw, allowInvalid: true);
    final parsed = parseAuthScript(
      window: window,
      windowBase: start,
      marker: hit.marker,
      markerOffset: hit.offset,
    );
    if (parsed == null) continue;
    if (!byHashOffset.add(parsed.hashOffset)) continue;
    candidates.add(parsed);
  }

  if (candidates.isEmpty) {
    notes.add('没有解析出鉴权脚本。常见原因：固件已改 HTTPS、脚本被压缩、或该机型机制不同。');
  } else {
    final best = candidates.first;
    notes.add('找到 ${candidates.length} 个候选，最可能是 ${best.algorithm.label}'
        '（偏移 ${best.offsetHex}，置信度 ${best.confidence}%）。');
    if (!best.trailingNewline) {
      notes.add('脚本使用 echo -n：计算哈希时不要附加换行符。');
    }
  }

  return ScanResult(
    path: file.path,
    fileSize: size,
    container: container,
    versionString: versionString,
    rkafOffset: rkafOffset,
    candidates: candidates,
    notes: notes,
  );
}

Future<Uint8List> _readAt(File file, int offset, int length) async {
  final raf = await file.open();
  try {
    await raf.setPosition(offset);
    final data = await raf.read(length);
    return Uint8List.fromList(data);
  } finally {
    await raf.close();
  }
}

Future<int> _findFirst(File file, String needle, {required int limit}) async {
  final raf = await file.open();
  try {
    var pos = 0;
    var carry = '';
    while (pos < limit) {
      await raf.setPosition(pos);
      final buf = await raf.read(_chunk);
      if (buf.isEmpty) break;
      final text = carry + latin1.decode(buf, allowInvalid: true);
      final idx = text.indexOf(needle);
      if (idx >= 0) return pos - carry.length + idx;
      carry = text.length > 16 ? text.substring(text.length - 16) : text;
      pos += buf.length;
    }
  } finally {
    await raf.close();
  }
  return -1;
}

String _asciiRun(Uint8List bytes, int start, int end) {
  final buf = StringBuffer();
  for (var i = start; i < end && i < bytes.length; i++) {
    final b = bytes[i];
    if (b >= 0x20 && b < 0x7f) {
      buf.writeCharCode(b);
    } else if (buf.isNotEmpty) {
      break;
    }
  }
  return buf.toString();
}
