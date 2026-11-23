import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

/// 支持的口令校验算法。`plaintext` 用于极老固件（明文比对，如 CherryYoudao）。
enum HashAlgorithm { md5, sha1, sha256, sha512, plaintext }

extension HashAlgorithmX on HashAlgorithm {
  String get label => switch (this) {
        HashAlgorithm.md5 => 'MD5',
        HashAlgorithm.sha1 => 'SHA1',
        HashAlgorithm.sha256 => 'SHA256',
        HashAlgorithm.sha512 => 'SHA512',
        HashAlgorithm.plaintext => '明文',
      };

  int get hexLength => switch (this) {
        HashAlgorithm.md5 => 32,
        HashAlgorithm.sha1 => 40,
        HashAlgorithm.sha256 => 64,
        HashAlgorithm.sha512 => 128,
        HashAlgorithm.plaintext => 0,
      };

  Hash get _hash => switch (this) {
        HashAlgorithm.md5 => md5,
        HashAlgorithm.sha1 => sha1,
        HashAlgorithm.sha256 => sha256,
        HashAlgorithm.sha512 => sha512,
        HashAlgorithm.plaintext => md5,
      };

  /// 由哈希长度反推算法（用于脚本里拿不到 `xxxsum` 命令时兜底）。
  static HashAlgorithm? fromHexLength(int len) => switch (len) {
        32 => HashAlgorithm.md5,
        40 => HashAlgorithm.sha1,
        64 => HashAlgorithm.sha256,
        128 => HashAlgorithm.sha512,
        _ => null,
      };
}

/// 按脚本语义计算口令哈希。
///
/// 关键点：`echo $PASSWD | md5sum` 会把换行符一起哈希，官方教程里大量失败
/// 都是漏了这一步。`echo -n` 则不带换行。
String hashPassword({
  required String password,
  required HashAlgorithm algorithm,
  required bool trailingNewline,
}) {
  if (algorithm == HashAlgorithm.plaintext) return password;
  final payload = trailingNewline ? '$password\n' : password;
  return algorithm._hash.convert(utf8.encode(payload)).toString();
}

class _DigestSink implements Sink<Digest> {
  Digest? value;

  @override
  void add(Digest data) => value = data;

  @override
  void close() {}
}

/// 流式计算整文件摘要（内存占用与文件大小无关）。
Future<Digest> digestFile(File file, Hash hash) async {
  final sink = _DigestSink();
  final input = hash.startChunkedConversion(sink);
  await for (final chunk in file.openRead()) {
    input.add(chunk);
  }
  input.close();
  return sink.value!;
}

/// 按 [endPositions] 切段计算每段摘要。
///
/// `endPositions` 来自 OTA 响应里的 `segmentMd5[].endpos`，词典笔会逐段校验，
/// 段边界算错就会卡在下载进度条。
Future<List<String>> segmentDigests(
  File file,
  Hash hash,
  List<int> endPositions,
) async {
  final results = <String>[];
  final raf = await file.open();
  try {
    var start = 0;
    final total = await file.length();
    for (final end in endPositions) {
      final stop = end > total ? total : end;
      final length = stop - start;
      if (length <= 0) {
        results.add(hash.convert(const []).toString());
        continue;
      }
      await raf.setPosition(start);
      final sink = _DigestSink();
      final input = hash.startChunkedConversion(sink);
      var remaining = length;
      while (remaining > 0) {
        final n = remaining > 1 << 20 ? 1 << 20 : remaining;
        final buf = await raf.read(n);
        if (buf.isEmpty) break;
        input.add(buf);
        remaining -= buf.length;
      }
      input.close();
      results.add((sink.value ?? hash.convert(const [])).toString());
      start = stop;
    }
  } finally {
    await raf.close();
  }
  return results;
}
