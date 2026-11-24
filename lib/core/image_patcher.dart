import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'auth_script.dart';
import 'hash_util.dart';

int _lastPatchPct = -1;

class PatchResult {
  PatchResult({
    required this.offset,
    required this.oldHash,
    required this.newHash,
    required this.outputPath,
    required this.fileSize,
    required this.backupPath,
    required this.verified,
    required this.inPlace,
  });

  final int offset;
  final String oldHash;
  final String newHash;

  /// 改写后的镜像路径（默认是新文件，原镜像保持不变）。
  final String outputPath;

  final int fileSize;
  final String? backupPath;
  final bool verified;
  final bool inPlace;

  String get offsetHex => '0x${offset.toRadixString(16).toUpperCase()}';
}

class PatchException implements Exception {
  PatchException(this.message);
  final String message;
  @override
  String toString() => message;
}

const int _copyChunk = 4 << 20;

/// 把新口令的哈希写进镜像。
///
/// 实现要点（踩过的坑）：
/// Dart 的 `FileMode.write` 会 **truncate** 文件，直接随机写会把镜像清零。
/// 所以这里走"流式复制 + 在偏移处替换字节"的方式，全程内存占用与文件大小无关。
///
/// 默认 `inPlace = false`：生成 `<原文件>.patched`，原文件一个字节都不动，最安全。
/// `inPlace = true` 时会先备份为 `.bak`，再用新文件替换原文件。
Future<PatchResult> patchImage({
  required File image,
  required AuthScript script,
  required String newPassword,
  bool inPlace = false,
  void Function(int done, int total)? onProgress,
}) async {
  if (newPassword.isEmpty) {
    throw PatchException('口令不能为空');
  }
  final newHash = hashPassword(
    password: newPassword,
    algorithm: script.algorithm,
    trailingNewline: script.trailingNewline,
  );
  if (newHash.length != script.storedHash.length) {
    throw PatchException(
      '哈希长度不一致：原 ${script.storedHash.length} 字符，新 ${newHash.length} 字符。'
      '明文校验的老固件要求新口令与原口令等长。',
    );
  }

  final sizeBefore = await image.length();
  if (script.hashOffset + script.storedHash.length > sizeBefore) {
    throw PatchException('哈希偏移超出文件范围，镜像可能不完整。');
  }

  final outputPath = inPlace ? image.path : '${image.path}.patched';
  final tmpPath = '$outputPath.tmp';
  final tmpFile = File(tmpPath);
  if (await tmpFile.exists()) await tmpFile.delete();

  final src = await image.open();
  final dst = await tmpFile.open(mode: FileMode.writeOnly);
  final newBytes = Uint8List.fromList(ascii.encode(newHash));

  try {
    var pos = 0;
    while (pos < sizeBefore) {
      final want = (sizeBefore - pos) < _copyChunk ? (sizeBefore - pos) : _copyChunk;
      await src.setPosition(pos);
      final buf = await src.read(want);
      if (buf.isEmpty) break;

      final hashEnd = script.hashOffset + newBytes.length;
      final chunkEnd = pos + buf.length;
      if (script.hashOffset < chunkEnd && hashEnd > pos) {
        final rel = script.hashOffset - pos;
        for (var i = 0; i < newBytes.length; i++) {
          final idx = rel + i;
          if (idx >= 0 && idx < buf.length) buf[idx] = newBytes[i];
        }
      }
      await dst.writeFrom(buf);
      pos += buf.length;
      if (onProgress != null) {
        final pct = sizeBefore == 0 ? 0 : pos * 100 ~/ sizeBefore;
        if (pct % 10 == 0 && pct != _lastPatchPct) {
          _lastPatchPct = pct;
          onProgress(pos, sizeBefore);
        }
      }
    }
    await dst.flush();
  } finally {
    await src.close();
    await dst.close();
  }

  // ---- 输出校验 ----
  final outLen = await tmpFile.length();
  if (outLen != sizeBefore) {
    await tmpFile.delete();
    throw PatchException('输出大小不一致（$sizeBefore → $outLen），已删除临时文件。');
  }

  var readBack = '';
  final check = await tmpFile.open();
  try {
    await check.setPosition(script.hashOffset);
    readBack = ascii.decode(await check.read(newBytes.length), allowInvalid: true);
  } finally {
    await check.close();
  }
  if (readBack != newHash) {
    await tmpFile.delete();
    throw PatchException('回读校验失败（读到 "$readBack"），已删除临时文件。');
  }

  // ---- 落盘 ----
  String? backupPath;
  final outFile = File(outputPath);
  if (inPlace) {
    final bak = File('${image.path}.bak');
    await image.copy(bak.path);
    backupPath = bak.path;
    await image.delete();
  } else if (await outFile.exists()) {
    await outFile.delete();
  }
  await tmpFile.rename(outputPath);

  return PatchResult(
    offset: script.hashOffset,
    oldHash: script.storedHash,
    newHash: newHash,
    outputPath: outputPath,
    fileSize: outLen,
    backupPath: backupPath,
    verified: true,
    inPlace: inPlace,
  );
}
