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

  /// 抓到的原始响应正文。
  final void Function(String body)? onCapture;

  HttpServer? _server;
  String? lastRequestPath;
  String? lastResponseBody;
  String? lastError;

  bool get running => _server != null;

  void _log(String line) => onLog?.call(line);

  Future<void> start() async {
    if (_server != null) return;
    _server = await HttpServer.bind(InternetAddress.anyIPv4, listenPort);
    _log('[ota] 监听 :$listenPort');
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
      if (path.endsWith('.img')) {
        await _serveImage(req);
      } else if (path.contains('/ota/checkVersion')) {
        await _proxyCheckVersion(req);
      } else {
        req.response.statusCode = 404;
        await req.response.close();
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

  Future<void> _proxyCheckVersion(HttpRequest req) async {
    lastRequestPath = req.uri.toString();
    _log('[ota] 收到请求 ${req.method} ${req.uri}');

    final body = await req.fold<List<int>>([], (a, b) => a..addAll(b));
    _log('[ota] 请求体: ${utf8.decode(body, allowMalformed: true)}');

    // 回灌模式：直接返回 buildArtifacts 生成好的响应，不再打扰上游
    final preset = fixedResponse;
    if (!captureOnly && preset != null) {
      lastResponseBody = preset;
      req.response.headers.contentType = ContentType.json;
      req.response.write(preset);
      await req.response.close();
      _log('[ota] 已返回生成好的响应（${preset.length} 字符）');
      return;
    }

    final client = HttpClient();
    try {
      final upstream = Uri.https(upstreamHost, req.uri.path);
      final upReq = await client.openUrl(req.method, upstream);
      upReq.headers.set(HttpHeaders.contentTypeHeader,
          req.headers.contentType?.toString() ?? 'application/json;charset=UTF-8');
      upReq.add(body);
      final upResp = await upReq.close();
      final text = await upResp.transform(utf8.decoder).join();
      lastResponseBody = text;
      _log('[ota] 上游状态 ${upResp.statusCode}（${text.length} 字符）');

      // 抓包模式：原样返回并回调保存
      if (captureOnly) {
        if (upResp.statusCode == 200) {
          onCapture?.call(text);
          _log('[ota] 已抓到原始响应，可直接生成 mod.img 与 ota_response.json');
        } else {
          _log('[!] 上游非 200，未保存');
        }
        req.response.statusCode = upResp.statusCode;
        req.response.headers.contentType = ContentType.json;
        req.response.write(text);
        await req.response.close();
        return;
      }

      if (upResp.statusCode != 200) {
        req.response.statusCode = upResp.statusCode;
        req.response.write(text);
        await req.response.close();
        return;
      }

      final cfg = config;
      if (cfg == null) {
        req.response.headers.contentType = ContentType.json;
        req.response.write(text);
        await req.response.close();
        _log('[!] 未提供改写配置，已原样返回');
        return;
      }

      final json = jsonDecode(text) as Map<String, dynamic>;
      // 先看能不能改，改不了就把原文返回，便于人工判断
      final rewritten = rewriteOtaResponse(json, cfg);
      req.response.headers.contentType = ContentType.json;
      req.response.write(jsonEncode(rewritten));
      await req.response.close();
      _log('[ota] 已返回改写后的响应（地址 → ${cfg.imageUrl}）');
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
