import 'dart:io';

/// 检查热点上连了哪些客户端（用于回答"笔到底连没连上"）。
///
/// 直接读 Windows 的 ARP 邻居表：热点网段里出现非广播 MAC 就说明有设备在线。
class HotspotClients {
  /// 网关地址，如 192.168.137.1
  HotspotClients(this.gatewayIp);

  final String gatewayIp;

  String get _prefix {
    final parts = gatewayIp.split('.');
    if (parts.length != 4) return gatewayIp;
    return '${parts[0]}.${parts[1]}.${parts[2]}.';
  }

  /// 返回在线设备 IP 列表（排除网关自己与广播）。
  Future<List<String>> list() async {
    if (!Platform.isWindows) return const [];
    try {
      final r = await Process.run('arp', ['-a']);
      final text = '${r.stdout}${r.stderr}';
      final ips = <String>{};
      for (final line in text.split(RegExp(r'\r?\n'))) {
        final m = RegExp(
          r'^\s*(' + RegExp.escape(_prefix) + r'\d{1,3})\s+([0-9a-fA-F-]{17})\s',
        ).firstMatch(line);
        if (m == null) continue;
        final ip = m.group(1)!;
        final mac = m.group(2)!.toUpperCase();
        if (ip == gatewayIp) continue;
        if (mac == 'FF-FF-FF-FF-FF-FF' || mac == '00-00-00-00-00-00') continue;
        ips.add(ip);
      }
      return ips.toList()..sort();
    } catch (_) {
      return const [];
    }
  }
}
