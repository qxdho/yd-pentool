import 'dart:convert';
import 'dart:io';

import 'real_dns.dart';

/// 教程第 2 步：把抓到的那次检查更新请求重新发一遍。
///
/// 关键手法来自社区教程：官方在"设备已是最新"时只回
/// `No new updates were found`，拿不到包；把请求体里的 `version`
/// 报成极低值（99.99.90）就会返回完整全量包信息。
class OtaPackageInfo {
  OtaPackageInfo({
    required this.versionName,
    required this.fileSize,
    required this.md5,
    required this.sha256,
    required this.deltaUrl,
    required this.endPositions,
    required this.rawJson,
    required this.forced,
  });

  final String versionName;
  final int fileSize;
  final String md5;
  final String sha256;
  final String deltaUrl;
  final List<int> endPositions;

  /// 可直接存成 captured.json 的完整响应
  final String rawJson;

  /// 是否是"报低版本号"后拿到的
  final bool forced;

  int get segmentCount => endPositions.length;
  int get firstSegmentSize => endPositions.isEmpty ? 0 : endPositions.first;
}

class OtaApiException implements Exception {
  OtaApiException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// 解析响应正文；没有 segmentMd5 时返回 null（说明服务器说"无更新"）。
OtaPackageInfo? parsePackageResponse(String jsonText, {bool forced = false}) {
  final root = jsonDecode(jsonText);
  if (root is! Map) return null;
  final data = root['data'];
  if (data is! Map) return null;
  final version = data['version'];
  if (version is! Map) return null;
  var segs = version['segmentMd5'];
  if (segs is String) segs = jsonDecode(segs);
  if (segs is! List || segs.isEmpty) return null;
  final ends = <int>[];
  for (final s in segs) {
    if (s is Map && s['endpos'] is int) ends.add(s['endpos'] as int);
  }
  return OtaPackageInfo(
    versionName: version['versionName'] as String? ?? '',
    fileSize: (version['fileSize'] as num?)?.toInt() ?? 0,
    md5: version['md5sum'] as String? ?? '',
    sha256: version['sha'] as String? ?? '',
    deltaUrl: version['deltaUrl'] as String? ?? '',
    endPositions: ends,
    rawJson: jsonText,
    forced: forced,
  );
}

/// 用抓到的请求重发一次。先按原样问，若"无更新"再自动报低版本重问。
///
/// [path] 例如 `/product/1729062311/5787033ad10172cb/ota/checkVersion`
/// [body] 笔当时发的请求体（含 timestamp/sign/mid/productId/version）
Future<OtaPackageInfo> fetchPackageInfo({
  required String path,
  required String body,
  String host = 'iotapi.abupdate.com',
  String forceVersion = '99.99.90',
}) async {
  final client = createHostsBypassClient();
  try {
    final uri = Uri.https(host, path);

    final first = await _post(client, uri, body);
    final direct = first == null ? null : parsePackageResponse(first);
    if (direct != null) return direct;

    String? second;
    final lowered = body.replaceAll(
      RegExp(r'"version"\s*:\s*"[^"]*"'),
      '"version":"$forceVersion"',
    );
    if (lowered != body) {
      second = await _post(client, uri, lowered);
      final forced = second == null ? null : parsePackageResponse(second, forced: true);
      if (forced != null) return forced;
    }
    final raw = first ?? second ?? '';
    final preview = raw.length > 200 ? '${raw.substring(0, 200)}…' : raw;
    throw OtaApiException(
      '服务器没有返回包信息。可能该 productId 已停止分发，或接口已改为 HTTPS/加密。'
      '原始响应：${preview.isEmpty ? '（无）' : preview}',
    );
  } finally {
    client.close(force: true);
  }
}

Future<String?> _post(HttpClient client, Uri uri, String body) async {
  try {
    final req = await client.postUrl(uri);
    req.headers.contentType = ContentType.json;
    req.write(body);
    final resp = await req.close();
    final text = await resp.transform(utf8.decoder).join();
    return resp.statusCode == 200 ? text : null;
  } catch (_) {
    return null;
  }
}
