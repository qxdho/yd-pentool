import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

/// 绕开系统 hosts 的 DNS 解析。
///
/// 背景：抓包模式会把 iotapi.abupdate.com 写进 hosts 指到本机，
/// 结果程序自己去访问上游时也被劫持，连到自己的 443 端口，握手必然失败。
/// 所以这里直接用 UDP 问公共 DNS，拿到真实 IP 再连，SNI 仍用域名。
class _DnsAnswer {
  _DnsAnswer(this.ip, this.ttl);
  final String ip;
  final int ttl;
}

const List<String> _dnsServers = ['223.5.5.5', '119.29.29.29', '8.8.8.8'];
final Map<String, ({String ip, DateTime expire})> _cache = {};

Future<String?> resolveRealIp(String domain, {Duration timeout = const Duration(seconds: 3)}) async {
  final hit = _cache[domain];
  if (hit != null && hit.expire.isAfter(DateTime.now())) return hit.ip;

  for (final server in _dnsServers) {
    final ans = await _queryA(domain, server, timeout);
    if (ans != null) {
      final ttl = ans.ttl <= 0 ? 60 : ans.ttl;
      _cache[domain] = (
        ip: ans.ip,
        expire: DateTime.now().add(Duration(seconds: ttl.clamp(30, 600))),
      );
      return ans.ip;
    }
  }
  return null;
}

Future<_DnsAnswer?> _queryA(String domain, String server, Duration timeout) async {
  final id = Random().nextInt(0xffff);
  final b = BytesBuilder();
  b.add([id >> 8, id & 0xff]);
  b.add([0x01, 0x00]); // RD
  b.add([0x00, 0x01]); // QDCOUNT
  b.add([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR
  for (final label in domain.split('.')) {
    final bytes = ascii.encode(label);
    b.addByte(bytes.length);
    b.add(bytes);
  }
  b.addByte(0);
  b.add([0x00, 0x01, 0x00, 0x01]); // A / IN

  RawDatagramSocket? socket;
  try {
    socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    final addr = InternetAddress(server);
    socket.send(b.toBytes(), addr, 53);
    final completer = Completer<Uint8List?>();
    late final StreamSubscription<RawSocketEvent> sub;
    sub = socket.listen((event) {
      if (event != RawSocketEvent.read) return;
      final dg = socket!.receive();
      if (dg == null) return;
      if (!completer.isCompleted) completer.complete(dg.data);
    });
    final data = await completer.future.timeout(timeout, onTimeout: () => null);
    await sub.cancel();
    if (data == null) return null;
    return _parseA(data, id);
  } catch (_) {
    return null;
  } finally {
    socket?.close();
  }
}

_DnsAnswer? _parseA(Uint8List data, int id) {
  if (data.length < 12) return null;
  final respId = (data[0] << 8) | data[1];
  if (respId != id) return null;
  final qd = (data[4] << 8) | data[5];
  final an = (data[6] << 8) | data[7];

  var off = 12;
  for (var i = 0; i < qd; i++) {
    off = _skipName(data, off);
    off += 4; // QTYPE + QCLASS
    if (off > data.length) return null;
  }
  for (var i = 0; i < an; i++) {
    off = _skipName(data, off);
    if (off + 10 > data.length) return null;
    final type = (data[off] << 8) | data[off + 1];
    final ttl = (data[off + 4] << 24) |
        (data[off + 5] << 16) |
        (data[off + 6] << 8) |
        data[off + 7];
    final rdlen = (data[off + 8] << 8) | data[off + 9];
    off += 10;
    if (off + rdlen > data.length) return null;
    if (type == 1 && rdlen == 4) {
      final ip = '${data[off]}.${data[off + 1]}.${data[off + 2]}.${data[off + 3]}';
      return _DnsAnswer(ip, ttl);
    }
    off += rdlen;
  }
  return null;
}

int _skipName(Uint8List data, int off) {
  while (off < data.length) {
    final len = data[off];
    if (len == 0) return off + 1;
    if (len & 0xC0 == 0xC0) return off + 2; // 压缩指针
    off += 1 + len;
  }
  return off;
}

/// 创建一个"不吃系统 hosts"的 HttpClient。
///
/// 用于抓包模式下访问上游：先自己解析真实 IP，再连同域名做 SNI。
HttpClient createHostsBypassClient() {
  final client = HttpClient();
  client.connectionFactory = (Uri uri, String? proxyHost, int? proxyPort) async {
    final host = uri.host;
    final ip = await resolveRealIp(host) ?? host;
    final socket = await Socket.connect(ip, uri.port,
        timeout: const Duration(seconds: 10));
    if (uri.scheme == 'https') {
      final secure = await SecureSocket.secure(socket, host: host);
      return ConnectionTask.fromSocket(Future.value(secure), () {});
    }
    return ConnectionTask.fromSocket(Future.value(socket), () {});
  };
  return client;
}
