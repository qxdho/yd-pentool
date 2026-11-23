import 'dart:convert';

/// 抓包得到的 OTA `checkVersion` 响应，解析成改写需要的参数。
///
/// 有了它就不用再手工抄 `endpos`：直接读真实响应，分段边界、原始校验值全部现成。
class OtaCapture {
  OtaCapture({
    required this.fileSize,
    required this.md5,
    required this.sha,
    required this.deltaUrl,
    required this.endPositions,
    required this.segmentMd5,
    required this.encrypted,
    required this.versionName,
  });

  final int fileSize;
  final String md5;
  final String sha;
  final String deltaUrl;
  final List<int> endPositions;
  final List<String> segmentMd5;
  final bool encrypted;
  final String versionName;

  int get segmentCount => endPositions.length;

  /// 分段大小（取第一段），用于展示"50 MB 还是 100 MB"。
  int? get firstSegmentSize => endPositions.isEmpty ? null : endPositions.first;

  static OtaCapture parse(String jsonText) {
    final root = jsonDecode(jsonText);
    if (root is! Map) throw const FormatException('根节点不是对象');
    final data = root['data'];
    if (data is! Map) throw const FormatException('缺少 data 字段');
    final version = data['version'];
    if (version is! Map) throw const FormatException('缺少 data.version');

    final safe = data['safe'];
    final encrypted = safe is Map && safe['encKey'] != null;

    var segs = version['segmentMd5'];
    if (segs is String) segs = jsonDecode(segs);
    if (segs is! List) throw const FormatException('缺少 segmentMd5');

    final endPositions = <int>[];
    final hashes = <String>[];
    for (final s in segs) {
      if (s is! Map) continue;
      final end = s['endpos'];
      final md5v = s['md5'];
      if (end is int) endPositions.add(end);
      if (md5v is String) hashes.add(md5v);
    }

    return OtaCapture(
      fileSize: (version['fileSize'] as num?)?.toInt() ?? 0,
      md5: version['md5sum'] as String? ?? '',
      sha: version['sha'] as String? ?? '',
      deltaUrl: version['deltaUrl'] as String? ?? '',
      endPositions: endPositions,
      segmentMd5: hashes,
      encrypted: encrypted,
      versionName: version['versionName'] as String? ?? '',
    );
  }

  /// 用本地镜像核对抓包是否匹配。返回 null 表示一致，否则返回问题描述。
  String? verifyAgainst({required int localSize, required String localMd5}) {
    if (encrypted) {
      return '该响应已加密（encKey 非空），此设备已修复漏洞，无法用本方法解锁。';
    }
    if (fileSize != 0 && localSize != 0 && fileSize != localSize) {
      return '文件大小不一致：抓包声明 $fileSize，本地镜像 $localSize。可能不是同一版本固件。';
    }
    if (md5.isNotEmpty && localMd5.isNotEmpty && md5 != localMd5) {
      return 'MD5 不一致：抓包声明 $md5，本地镜像 $localMd5。这份镜像不是该响应对应的原始包。';
    }
    return null;
  }
}
