import 'dart:convert';
import 'dart:io';

import 'checksum.dart';

/// OTA 响应里会被替换的字段。
class OtaRewriteConfig {
  OtaRewriteConfig({
    required this.imageUrl,
    required this.fileSize,
    required this.md5,
    required this.sha256,
    required this.segmentMd5,
  });

  final String imageUrl;
  final int fileSize;
  final String md5;
  final String sha256;

  /// 顺序必须与抓到的 `segmentMd5` 数组一致。
  final List<String> segmentMd5;
}

class OtaRewriteException implements Exception {
  OtaRewriteException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// 就地改写 OTA `checkVersion` 响应：把下载地址指到本机、把校验值换成改写后的。
///
/// 只改必须改的字段，其它字段（version/releaseNotes/policy…）原样保留，
/// 因为笔会拿它们做版本比较与安装策略判断。
Map<String, dynamic> rewriteOtaResponse(
  Map<String, dynamic> json,
  OtaRewriteConfig cfg,
) {
  // 归一化：真实响应来自 jsonDecode（Map<String, dynamic>），但调用方可能传入
  // 手工构造、类型更窄的 Map（例如 Map<String, int?>），直接赋值会抛类型错误；
  // 也避免就地修改调用方的对象。JSON 往返后所有嵌套都是 Map<String, dynamic>。
  final root = jsonDecode(jsonEncode(json)) as Map<String, dynamic>;
  final data = root['data'];
  if (data is! Map) {
    throw OtaRewriteException('响应里没有 data 字段，可能不是 checkVersion 的返回。');
  }
  final safe = data['safe'];
  if (safe is Map && safe['encKey'] != null) {
    throw OtaRewriteException('响应带 encKey，该固件已启用加密校验，无法用代理方式替换。');
  }

  final version = data['version'];
  if (version is! Map) {
    throw OtaRewriteException('响应里没有 data.version，无法定位下载地址。');
  }

  // 分段哈希：按 index 覆盖 md5，保留 num/startpos/endpos
  final segList = version['segmentMd5'];
  if (segList is String) {
    final decoded = jsonDecode(segList);
    if (decoded is List) {
      _replaceSegments(decoded, cfg);
      version['segmentMd5'] = jsonEncode(decoded);
    }
  } else if (segList is List) {
    _replaceSegments(segList, cfg);
  } else if (cfg.segmentMd5.isNotEmpty) {
    throw OtaRewriteException('响应里没有 segmentMd5，无法确定分段边界。');
  }

  version['deltaUrl'] = cfg.imageUrl;
  version['bakUrl'] = cfg.imageUrl;
  version['md5sum'] = cfg.md5;
  version['sha'] = cfg.sha256;
  version['fileSize'] = cfg.fileSize;
  data['version'] = version;
  root['data'] = data;
  return root;
}

void _replaceSegments(List<dynamic> segments, OtaRewriteConfig cfg) {
  for (var i = 0; i < segments.length; i++) {
    final seg = segments[i];
    if (seg is! Map) continue;
    final value = i < cfg.segmentMd5.length ? cfg.segmentMd5[i] : null;
    if (value == null) {
      throw OtaRewriteException(
        '分段数量不匹配：响应有 ${segments.length} 段，本地只算出 ${cfg.segmentMd5.length} 段。'
        '请确认 endpos 列表填对了。',
      );
    }
    seg['md5'] = value;
  }
}

/// 本机局域网 IPv4 探测见 firmware_download.dart 的 detectLanIp()。

/// 把请求体里的 version 改成极低值（"99.99.90" 是社区验证可用的值）。
/// 找不到 version 字段时返回 null。
String? _lowerVersionInBody(String body) {
  final re = RegExp(r'"version"\s*:\s*"[^"]*"');
  if (!re.hasMatch(body)) return null;
  return body.replaceAll(re, '"version":"99.99.90"');
}

/// 直接向上游 POST 一次，返回响应正文（失败返回 null）。
Future<String?> _postUpstream(HttpClient client, Uri uri, String body) async {
  try {
    final req = await client.postUrl(uri);
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json;charset=UTF-8');
    req.write(body);
    final resp = await req.close();
    final text = await resp.transform(utf8.decoder).join();
    return resp.statusCode == 200 ? text : null;
  } catch (e) {
    return null;
  }
}

/// 本地 OTA 服务：
///  - 任意 `*\/ota/checkVersion` 请求 → 转发真服务器 → 改写响应 → 返回
///  - 任意以 `.img` 结尾的路径 → 返回改写后的镜像（支持 Range）
class OtaProxyServer {
  OtaProxyServer({
    required this.listenPort,
    this.imagePath,
    this.config,
    this.fixedResponse,
    this.captureOnly = false,
    this.upstreamHost = 'iotapi.abupdate.com',
    this.onLog,
    this.onCapture,
  });

  /// 改写后的镜像路径；抓包模式下可为 null。
  final String? imagePath;
  final OtaRewriteConfig? config;

  /// 直接返回这段 JSON（用 buildArtifacts 生成的 ota_response.json）。
  final String? fixedResponse;

  /// true = 只抓包：把上游响应原样返回并回调 onCapture，不改写。
  final bool captureOnly;

  final int listenPort;
  final String upstreamHost;
  final void Function(String line)? onLog;

  /// 抓到的原始响应（路径 + 响应正文）。
  final void Function(String path, String body)? onCapture;

  HttpServer? _server;
  String? lastRequestPath;
  String? lastResponseBody;
  String? lastError;

  bool get running => _server != null;

  void _log(String line) => onLog?.call(line);

  Future<void> start() async {
    if (_server != null) return;
    // 双栈监听：笔可能优先走 IPv6，只绑 IPv4 会漏掉请求。
    try {
      _server = await HttpServer.bind(
        InternetAddress.anyIPv6,
        listenPort,
        v6Only: false,
      );
    } on SocketException {
      _server = await HttpServer.bind(InternetAddress.anyIPv4, listenPort);
    }
    _log('[ota] 监听 :$listenPort（${_server!.address.address}）');
    _server!.listen(_handle, onError: (Object e) => _log('[ota] 错误: $e'));
  }

  Future<void> stop() async {
    await _server?.close(force: true);
    _server = null;
    _log('[ota] 已停止');
  }

  Future<void> _handle(HttpRequest req) async {
    try {
      final path = req.uri.path;
      // 每个请求都记一行，未知路径也要能看到
      _log('[ota] ${req.method} $path  host=${req.headers.host ?? '-'}');
      if (path.endsWith('.img')) {
        await _serveImage(req);
      } else {
        // 有道 OTA 不止 /ota/checkVersion：实测还有 /register/<id> 等，
        // 所以除镜像外一律按"转发 + 抓取响应"处理，绝不 404。
        await _proxyUpstream(req);
      }
    } catch (e) {
      lastError = '$e';
      _log('[ota] 处理失败: $e');
      try {
        req.response.statusCode = 500;
        req.response.write('$e');
        await req.response.close();
      } catch (_) {}
    }
  }

  /// 转发任意路径到上游，并按模式决定"原样返回 / 替换"。
  Future<void> _proxyUpstream(HttpRequest req) async {
    lastRequestPath = req.uri.toString();
    final body = await req.fold<List<int>>([], (a, b) => a..addAll(b));
    final bodyText = utf8.decode(body, allowMalformed: true);
    if (bodyText.isNotEmpty) _log('[ota] 请求体: $bodyText');

    final isOtaCheck = req.uri.path.contains('checkVersion') ||
        req.uri.path.contains('register');

    // 回灌模式：只替换 OTA 那一条，其它（如注册）照常转发
    final preset = fixedResponse;
    if (!captureOnly && preset != null && isOtaCheck) {
      lastResponseBody = preset;
      req.response.headers.contentType = ContentType.json;
      req.response.write(preset);
      await req.response.close();
      _log('[ota] 已返回生成好的 OTA 响应（${preset.length} 字符）');
      return;
    }

    final client = HttpClient();
    try {
      final upstream = Uri.https(
        req.headers.host ?? upstreamHost,
        req.uri.path,
        req.uri.queryParameters.isEmpty ? null : req.uri.queryParameters,
      );
      final upReq = await client.openUrl(req.method, upstream);
      upReq.headers.set(HttpHeaders.contentTypeHeader,
          req.headers.contentType?.toString() ?? 'application/json;charset=UTF-8');
      upReq.add(body);
      final upResp = await upReq.close();
      final text = await upResp.transform(utf8.decoder).join();
      lastResponseBody = text;
      _log('[ota] 上游 ${upResp.statusCode}，${text.length} 字符');

      // 抓包模式：原样返回给笔，但"抓取"时做一步增强
      if (captureOnly) {
        var toCapture = text;
        if (upResp.statusCode == 200 && !text.contains('segmentMd5')) {
          // 笔已是最新版时，服务器只回 "No new updates were found"，
          // 里面没有任何包信息。官方教程的做法是把 version 报低，
          // 逼服务器返回全量包信息——这里自动做一次，且不影响笔本身。
          final forcedBody = _lowerVersionInBody(bodyText);
          if (forcedBody != null) {
            final forced = await _postUpstream(
              client,
              Uri.https(req.headers.host ?? upstreamHost, req.uri.path,
                  req.uri.queryParameters.isEmpty ? null : req.uri.queryParameters),
              forcedBody,
            );
            if (forced != null && forced.contains('segmentMd5')) {
              toCapture = forced;
              _log('[ota] 笔已是最新版；已用 version=99.99.90 重新询问，拿到全量包信息');
            }
          }
        }
        if (upResp.statusCode == 200) {
          onCapture?.call(req.uri.path, toCapture);
        }
        req.response.statusCode = upResp.statusCode;
        req.response.headers.contentType = ContentType.json;
        req.response.write(text);
        await req.response.close();
        return;
      }

      // 非回灌的普通模式：也是原样转发
      req.response.statusCode = upResp.statusCode;
      req.response.headers.contentType = ContentType.json;
      req.response.write(text);
      await req.response.close();
    } finally {
      client.close(force: true);
    }
  }

  Future<void> _serveImage(HttpRequest req) async {
    final path = imagePath;
    if (path == null) {
      req.response.statusCode = 404;
      await req.response.close();
      return;
    }
    final file = File(path);
    if (!await file.exists()) {
      req.response.statusCode = 404;
      await req.response.close();
      return;
    }
    final total = await file.length();
    final range = req.headers.value(HttpHeaders.rangeHeader);
    var start = 0;
    var end = total - 1;
    if (range != null && range.startsWith('bytes=')) {
      final spec = range.substring(6).split('-');
      start = int.tryParse(spec[0]) ?? 0;
      if (spec.length > 1 && spec[1].isNotEmpty) {
        end = int.tryParse(spec[1]) ?? (total - 1);
      }
      if (start > end || start >= total) {
        req.response.statusCode = HttpStatus.requestedRangeNotSatisfiable;
        await req.response.close();
        return;
      }
      req.response.statusCode = HttpStatus.partialContent;
      req.response.headers.set(
        HttpHeaders.contentRangeHeader,
        'bytes $start-$end/$total',
      );
    }
    req.response.headers.contentType = ContentType('application', 'octet-stream');
    req.response.contentLength = end - start + 1;

    final raf = await file.open();
    try {
      await raf.setPosition(start);
      var remaining = end - start + 1;
      const chunk = 1 << 20;
      while (remaining > 0) {
        final want = remaining < chunk ? remaining : chunk;
        final data = await raf.read(want);
        if (data.isEmpty) break;
        req.response.add(data);
        remaining -= data.length;
      }
      await req.response.close();
      _log('[ota] 已发送镜像字节 $start-$end/$total');
    } finally {
      await raf.close();
    }
  }
}

OtaRewriteConfig buildRewriteConfig({
  required ChecksumReport report,
  required String localIp,
  required String fileName,
  int filePort = 14514,
}) {
  final url = 'http://$localIp:$filePort/${Uri.encodeComponent(fileName)}';
  return OtaRewriteConfig(
    imageUrl: url,
    fileSize: report.fileSize,
    md5: report.totalMd5,
    sha256: report.totalSha256,
    segmentMd5: report.segmentMd5,
  );
}
