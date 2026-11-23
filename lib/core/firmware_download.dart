import 'dart:io';

class DownloadResult {
  DownloadResult({
    required this.path,
    required this.bytes,
    required this.elapsed,
  });
  final String path;
  final int bytes;
  final Duration elapsed;
}

class DownloadException implements Exception {
  DownloadException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// 从 OTA 给出的 `deltaUrl` 流式下载全量包。
///
/// 走系统代理（如果设置了 HTTP_PROXY/HTTPS_PROXY），下载过程实时回调进度。
Future<DownloadResult> downloadFirmware({
  required String url,
  required String savePath,
  void Function(int received, int? total)? onProgress,
  HttpClient? client,
}) async {
  final uri = Uri.parse(url);
  final http = client ?? HttpClient();
  final sw = Stopwatch()..start();
  final tmp = File('$savePath.part');

  final env = Platform.environment;
  final proxy = env['HTTPS_PROXY'] ?? env['https_proxy'] ?? env['HTTP_PROXY'] ?? env['http_proxy'];
  if (client == null && proxy != null && proxy.isNotEmpty) {
    http.findProxy = (_) => 'PROXY ${proxy.replaceFirst(RegExp(r'^\w+://'), '')}';
  }

  try {
    final req = await http.getUrl(uri);
    req.headers.set(HttpHeaders.userAgentHeader, 'yd-pentool');
    final resp = await req.close();
    if (resp.statusCode != 200) {
      throw DownloadException('下载失败：HTTP ${resp.statusCode}（$url）');
    }
    final total = resp.contentLength > 0 ? resp.contentLength : null;
    final sink = tmp.openWrite();
    var received = 0;
    await for (final chunk in resp) {
      sink.add(chunk);
      received += chunk.length;
      onProgress?.call(received, total);
    }
    await sink.close();
    if (total != null && received != total) {
      throw DownloadException('下载不完整：$received / $total');
    }
    if (await File(savePath).exists()) await File(savePath).delete();
    await tmp.rename(savePath);
    return DownloadResult(path: savePath, bytes: received, elapsed: sw.elapsed);
  } catch (e) {
    if (await tmp.exists()) await tmp.delete();
    rethrow;
  } finally {
    http.close(force: true);
  }
}

/// 探本机局域网 IPv4：优先 192.168/10./172.16-31，跳过回环与虚拟网卡。
Future<String?> detectLanIp() async {
  try {
    final interfaces = await NetworkInterface.list(
      type: InternetAddressType.IPv4,
      includeLoopback: false,
    );
    final candidates = <String>[];
    for (final i in interfaces) {
      final name = i.name.toLowerCase();
      if (name.contains('vmware') || name.contains('virtualbox') || name.contains('vethernet')) {
        continue;
      }
      for (final a in i.addresses) {
        if (a.isLoopback) continue;
        candidates.add(a.address);
      }
    }
    for (final c in candidates) {
      if (c.startsWith('192.168.') || c.startsWith('10.')) return c;
    }
    for (final c in candidates) {
      final p = c.split('.');
      if (p.length == 4) {
        final second = int.tryParse(p[1]) ?? 0;
        if (p[0] == '172' && second >= 16 && second <= 31) return c;
      }
    }
    return candidates.isEmpty ? null : candidates.first;
  } catch (_) {
    return null;
  }
}
