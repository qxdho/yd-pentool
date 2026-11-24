import 'dart:io';

/// 443 端口探测器。
///
/// 用来判断"笔是不是改用 HTTPS 了"——如果是，请求会打到 443，
/// 而 HTTP 服务在 80 上永远看不到，表现为"程序毫无反应"。
///
/// 这里不做 TLS 握手（自签证书对端可能不认），只接受连接、读首字节，
/// 记录对端地址与是否像 TLS ClientHello，然后断开。
class TlsProbe {
  TlsProbe({this.port = 443, this.onEvent});

  final int port;
  final void Function(String line)? onEvent;

  ServerSocket? _socket;

  bool get running => _socket != null;

  Future<bool> start() async {
    if (_socket != null) return true;
    try {
      _socket = await ServerSocket.bind(InternetAddress.anyIPv4, port);
      _socket!.listen(_handle, onError: (Object e) => onEvent?.call('[443] 错误: $e'));
      onEvent?.call('[443] 探测已就绪（如果笔走 HTTPS，这里会打印连接）');
      return true;
    } on SocketException catch (e) {
      onEvent?.call('[443] 无法监听 $port：${e.message}（可能被占用或需要管理员）');
      return false;
    }
  }

  Future<void> _handle(Socket socket) async {
    final peer = socket.remoteAddress.address;
    try {
      final buf = <int>[];
      await for (final chunk in socket.timeout(const Duration(seconds: 2))) {
        buf.addAll(chunk);
        if (buf.length >= 6) break;
      }
      final isTls = buf.length >= 3 && buf[0] == 0x16 && buf[1] == 0x03;
      if (isTls) {
        onEvent?.call('[443] ⚠ $peer 发来了 TLS 握手：笔在用 HTTPS，'
            'HTTP 抓包对它无效，需要换方案');
      } else {
        final preview = String.fromCharCodes(buf.take(40)).replaceAll(RegExp(r'[\r\n]'), ' ');
        onEvent?.call('[443] $peer 发了 ${buf.length} 字节明文：$preview');
      }
    } catch (_) {
      // 忽略
    } finally {
      try {
        socket.destroy();
      } catch (_) {}
    }
  }

  Future<void> stop() async {
    await _socket?.close();
    _socket = null;
  }
}
