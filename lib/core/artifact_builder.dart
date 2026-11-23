import 'dart:convert';
import 'dart:io';

import 'auth_script.dart';
import 'checksum.dart';
import 'image_patcher.dart';
import 'ota_capture.dart';
import 'ota_proxy.dart';

/// 一键生成的产物清单。
class BuiltArtifacts {
  BuiltArtifacts({
    required this.dir,
    required this.imagePath,
    required this.responsePath,
    required this.reportPath,
    required this.capturePath,
    required this.hashOffset,
    required this.newHash,
    required this.fileSize,
    required this.md5,
    required this.sha256,
    required this.segmentCount,
    required this.usedCapture,
  });

  final String dir;

  /// 改写后的镜像（等价于用户当年的 mod.img）
  final String imagePath;

  /// 可直接给服务器用的 OTA 响应（等价于用户当年改好的 full.json）
  final String responsePath;

  /// 构建报告：偏移、哈希、分段、来源抓包
  final String reportPath;

  /// 本次使用/抓到的原始响应
  final String? capturePath;

  final int hashOffset;
  final String newHash;
  final int fileSize;
  final String md5;
  final String sha256;
  final int segmentCount;
  final bool usedCapture;

  String get hashOffsetHex => '0x${hashOffset.toRadixString(16).toUpperCase()}';
}

class ArtifactException implements Exception {
  ArtifactException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// 把「原镜像 + 口令 + 抓包」变成一套可以刷机的东西。
///
/// 产出（默认放在 `<原镜像>.build\`）：
///   mod.img          — 改写后的全量固件
///   ota_response.json— 改好校验值的 OTA 响应（本地服务器直接返回这个）
///   build_report.json— 全部中间值，便于复现与排查
///   captured.json    — 本次使用的原始抓包（有就存一份）
Future<BuiltArtifacts> buildArtifacts({
  required File original,
  required AuthScript script,
  required String newPassword,
  required String localIp,
  String? capturedJsonText,
  int port = 80,
  int? segmentSizeOverride,
  String? outputDir,
}) async {
  if (newPassword.isEmpty) throw ArtifactException('口令不能为空');
  final sizeBefore = await original.length();
  final dirPath = outputDir ?? '${original.path}.build';
  final dir = Directory(dirPath);
  if (!await dir.exists()) await dir.create(recursive: true);

  // 1) 改写镜像
  final patch = await patchImage(
    image: original,
    script: script,
    newPassword: newPassword,
  );
  final patched = File('$dirPath/mod.img');
  if (await patched.exists()) await patched.delete();
  await File(patch.outputPath).rename(patched.path);
  if (await File(patch.outputPath).exists()) {
    await File(patch.outputPath).delete();
  }
  if (await patched.length() != sizeBefore) {
    throw ArtifactException('改写后大小异常：${await patched.length()} != $sizeBefore');
  }

  // 2) 分段边界：优先用抓包，其次用指定值，最后按 50MB 兜底
  OtaCapture? capture;
  if (capturedJsonText != null && capturedJsonText.trim().isNotEmpty) {
    try {
      capture = OtaCapture.parse(capturedJsonText);
    } on FormatException catch (e) {
      throw ArtifactException('抓包解析失败：$e');
    }
    if (capture.encrypted) {
      throw ArtifactException('该抓包响应已加密（encKey 非空），此设备已修复漏洞。');
    }
    if (capture.fileSize != 0 && capture.fileSize != sizeBefore) {
      throw ArtifactException(
        '抓包与镜像不匹配：抓包声明 ${capture.fileSize} 字节，镜像 $sizeBefore 字节。',
      );
    }
  }

  final segSize = segmentSizeOverride ?? capture?.firstSegmentSize ?? 50 << 20;
  final ends = <int>[];
  if (capture != null) {
    ends.addAll(capture.endPositions);
  } else {
    var p = segSize;
    while (p < sizeBefore) {
      ends.add(p);
      p += segSize;
    }
    ends.add(sizeBefore);
  }
  if (ends.isEmpty || ends.last < sizeBefore) ends.add(sizeBefore);

  // 3) 校验
  final report = await computeChecksums(patched, endPositions: ends);

  // 4) 生成响应 JSON
  final cfg = OtaRewriteConfig(
    imageUrl: 'http://$localIp:$port/mod.img',
    fileSize: report.fileSize,
    md5: report.totalMd5,
    sha256: report.totalSha256,
    segmentMd5: report.segmentMd5,
  );

  Map<String, dynamic> response;
  if (capturedJsonText != null && capturedJsonText.trim().isNotEmpty) {
    final root = jsonDecode(capturedJsonText);
    if (root is! Map<String, dynamic>) {
      throw ArtifactException('抓包根节点不是对象');
    }
    response = rewriteOtaResponse(root, cfg);
  } else {
    response = _synthesizeResponse(cfg, report);
  }

  final responseFile = File('$dirPath/ota_response.json');
  await responseFile.writeAsString(
    const JsonEncoder.withIndent('  ').convert(response),
    flush: true,
  );

  // 5) 存一份原始抓包
  String? capturePath;
  if (capturedJsonText != null && capturedJsonText.trim().isNotEmpty) {
    capturePath = '$dirPath/captured.json';
    await File(capturePath).writeAsString(capturedJsonText, flush: true);
  }

  // 6) 构建报告
  final reportFile = File('$dirPath/build_report.json');
  await reportFile.writeAsString(
    const JsonEncoder.withIndent('  ').convert({
      'tool': 'yd-pentool',
      'generatedAt': DateTime.now().toIso8601String(),
      'patch': {
        'scriptOffset': '0x${script.scriptStart.toRadixString(16).toUpperCase()}',
        'hashOffset': '0x${script.hashOffset.toRadixString(16).toUpperCase()}',
        'algorithm': script.algorithm.name,
        'trailingNewline': script.trailingNewline,
        'dashSuffix': script.dashSuffix,
        'oldHash': script.storedHash,
        'newHash': patch.newHash,
      },
      'checksum': {
        'fileSize': report.fileSize,
        'md5': report.totalMd5,
        'sha1': report.totalSha1,
        'sha256': report.totalSha256,
        'segments': report.segmentMd5,
        'endPositions': report.endPositions,
      },
      'source': {
        'image': original.path,
        'size': sizeBefore,
        'capture': capturePath,
        'captureUsed': capture != null,
      },
    }),
    flush: true,
  );

  return BuiltArtifacts(
    dir: dirPath,
    imagePath: patched.path,
    responsePath: responseFile.path,
    reportPath: reportFile.path,
    capturePath: capturePath,
    hashOffset: script.hashOffset,
    newHash: patch.newHash,
    fileSize: report.fileSize,
    md5: report.totalMd5,
    sha256: report.totalSha256,
    segmentCount: report.segmentMd5.length,
    usedCapture: capture != null,
  );
}

Map<String, dynamic> _synthesizeResponse(
  OtaRewriteConfig cfg,
  ChecksumReport report,
) {
  final segments = <Map<String, dynamic>>[];
  var start = 0;
  for (var i = 0; i < report.segmentMd5.length; i++) {
    final end = i < report.endPositions.length ? report.endPositions[i] : report.fileSize;
    segments.add({
      'num': i,
      'startpos': start,
      'md5': report.segmentMd5[i],
      'endpos': end,
    });
    start = end;
  }
  return {
    'status': 1000,
    'msg': 'success',
    'data': {
      'releaseNotes': {
        'version': '99.99.91',
        'publishDate': DateTime.now().toIso8601String().split('T').first,
        'content': '[]',
      },
      'safe': {'encKey': null, 'isEncrypt': 0},
      'sha256': cfg.sha256,
      'version': {
        'bakUrl': cfg.imageUrl,
        'deltaUrl': cfg.imageUrl,
        'fileSize': cfg.fileSize,
        'md5sum': cfg.md5,
        'sha': cfg.sha256,
        'segmentMd5': jsonEncode(segments),
        'versionName': '99.99.91',
        'versionAlias': '',
        'deltaID': '0',
      },
    },
  };
}
