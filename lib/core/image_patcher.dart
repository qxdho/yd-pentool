import 'dart:convert';
import 'dart:io';

import 'auth_script.dart';
import 'hash_util.dart';

class PatchResult {
  PatchResult({
    required this.offset,
    required this.oldHash,
    required this.newHash,
    required this.bytesWritten,
    required this.fileSizeBefore,
    required this.fileSizeAfter,
    required this.backupPath,
    required this.verified,
  });

  final int offset;
  final String oldHash;
  final String newHash;
  final int bytesWritten;
  final int fileSizeBefore;
  final int fileSizeAfter;
  final String? backupPath;
  final bool verified;

  String get offsetHex => '0x${offset.toRadixString(16).toUpperCase()}';
}

class PatchException implements Exception {
  PatchException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// 把新口令的哈希等长写回镜像。
///
/// 硬性约束（照抄官方流程的结论）：
/// 1. 只替换哈希本身，长度必须与原来完全一致；
/// 2. 文件大小不允许变化；
/// 3. 写完必须回读校验，且只允许目标区间发生变化。
Future<PatchResult> patchImage({
  required File image,
  required AuthScript script,
  required String newPassword,
  bool makeBackup = true,
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
  String? backupPath;
  if (makeBackup) {
    final bak = File('${image.path}.bak');
    if (!await bak.exists()) {
      await image.copy(bak.path);
      backupPath = bak.path;
    } else {
      backupPath = bak.path;
    }
  }

  final raf = await image.open(mode: FileMode.write);
  try {
    await raf.setPosition(script.hashOffset);
    await raf.writeFrom(ascii.encode(newHash));
    await raf.flush();
  } finally {
    await raf.close();
  }

  final sizeAfter = await image.length();
  if (sizeAfter != sizeBefore) {
    throw PatchException('文件大小发生变化（$sizeBefore → $sizeAfter），已中止，请用备份恢复。');
  }

  // 回读校验
  final check = await image.open();
  String readBack;
  try {
    await check.setPosition(script.hashOffset);
    final bytes = await check.read(newHash.length);
    readBack = ascii.decode(bytes, allowInvalid: true);
  } finally {
    await check.close();
  }
  final verified = readBack == newHash;

  return PatchResult(
    offset: script.hashOffset,
    oldHash: script.storedHash,
    newHash: newHash,
    bytesWritten: newHash.length,
    fileSizeBefore: sizeBefore,
    fileSizeAfter: sizeAfter,
    backupPath: backupPath,
    verified: verified,
  );
}
