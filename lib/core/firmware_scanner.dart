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
const int _carry = 32; // 覆盖跨块边界的标记长度（最长标记 23，留余量）
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

  // ---- 扫描标记：字节级锚点，一趟扫完，不解码整块 ----
  final hits = await _scanMarkers(file, size);

  // ---- 逐个候选解析（只读命中的小窗口，解码量可忽略）----
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

/// 字节级 BMH 扫描。
///
/// 为什么不用 `String.indexOf`：在 1 GB 镜像上实测只有 ~9 MB/s（扫一遍 110 秒）。
/// 也不适合用固定对齐的 Uint64 比较——脚本可能落在任意偏移（实测 0x28CEF019）。
/// 这里用 Boyer-Moore-Horspool 在字节上扫「公共探针」`auth`（覆盖 6/7 个标记），
/// 命中后再就地校验完整标记；实测 ~286 MB/s，整盘 3~4 秒。
Future<List<({int offset, String marker})>> _scanMarkers(File file, int size) async {
  const probe = 'auth';
  final related = <({String marker, int rel})>[];
  final extra = <String>[];
  for (final m in kAuthMarkers) {
    final rel = m.indexOf(probe);
    if (rel >= 0) {
      related.add((marker: m, rel: rel));
    } else {
      extra.add(m);
    }
  }
  final probeBytes = ascii.encode(probe);
  final extraBytes = extra.map((m) => ascii.encode(m)).toList();

  final hits = <({int offset, String marker})>[];
  final seen = <int>{};

  void record(int absOffset, String marker) {
    final key = absOffset * 31 + marker.length;
    if (seen.add(key)) hits.add((offset: absOffset, marker: marker));
  }

  final raf = await file.open();
  var carry = Uint8List(0);
  var pos = 0;
  try {
    while (pos < size) {
      await raf.setPosition(pos);
      final chunk = await raf.read(_chunk);
      if (chunk.isEmpty) break;

      final Uint8List buf;
      if (carry.isEmpty) {
        buf = chunk;
      } else {
        buf = Uint8List(carry.length + chunk.length)
          ..setRange(0, carry.length, carry)
          ..setRange(carry.length, carry.length + chunk.length, chunk);
      }
      final base = pos - carry.length;

      // 主探针：命中后校验完整标记
      _bmh(buf, probeBytes, (at) {
        for (final r in related) {
          final start = at - r.rel;
          if (start < 0) continue;
          if (start + r.marker.length > buf.length) continue;
          if (_matchesAt(buf, start, r.marker)) {
            record(base + start, r.marker);
          }
        }
      });

      // 不含探针的标记单独扫（目前只有 CherryYoudao）
      for (var i = 0; i < extraBytes.length; i++) {
        _bmh(buf, extraBytes[i], (at) => record(base + at, extra[i]));
      }

      final keep = buf.length < _carry ? buf.length : _carry;
      carry = Uint8List.fromList(buf.sublist(buf.length - keep));
      pos += chunk.length;
    }
  } finally {
    await raf.close();
  }
  hits.sort((a, b) => a.offset.compareTo(b.offset));
  return hits;
}

/// Boyer-Moore-Horspool：遇到不匹配时按尾部字节跳跃，比朴素匹配快一个量级。
void _bmh(Uint8List data, List<int> needle, void Function(int at) onHit) {
  final n = needle.length;
  if (n == 0 || data.length < n) return;
  final skip = List<int>.filled(256, n);
  for (var i = 0; i < n - 1; i++) {
    skip[needle[i]] = n - 1 - i;
  }
  final lastByte = needle[n - 1];
  final last = data.length - n;
  var i = 0;
  while (i <= last) {
    final c = data[i + n - 1];
    if (c == lastByte) {
      var k = 0;
      while (k < n - 1 && data[i + k] == needle[k]) {
        k++;
      }
      if (k == n - 1) onHit(i);
    }
    i += skip[c];
  }
}

bool _matchesAt(Uint8List buf, int offset, String marker) {
  for (var i = 0; i < marker.length; i++) {
    if (buf[offset + i] != marker.codeUnitAt(i)) return false;
  }
  return true;
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
