import 'dart:io';

/// 封堵词典笔固件里内置的公共 DNS。
///
/// 背景（实测 2026-11-24）：笔的固件里写死了 `223.6.6.6` 这类公共 DNS。
/// 它同时向「ICS 下发的 192.168.137.1」和「公网 DNS」发查询，谁先回就用谁。
/// ICS 的冷查询要 ~900ms（要转发 AAAA 到上游），公网 DNS 只要 ~45ms，
/// 于是笔拿到真实 IP，直接连真服务器，hosts 劫持形同虚设。
///
/// 做法：给这些公网 DNS 加黑洞路由（下一跳指向热点网卡自身 = on-link），
/// 让转发给笔的查询收不到回应，笔只能回落到 ICS 的 DNS。
///
/// 注意：不要封堵程序自己解析上游用的 DNS（见 real_dns.dart 的 _dnsServers）。
const List<String> kBlockedDns = [
  '223.6.6.6',
  '114.114.114.114',
  '114.114.115.115',
  '8.8.8.8',
  '1.1.1.1',
  '180.76.76.76',
];

/// 找到热点网卡索引（黑洞路由必须绑在它上面，否则会影响本机上网）。
Future<int?> _hotspotIfIndex() async {
  try {
    final r = await Process.run('powershell', [
      '-NoProfile',
      '-Command',
      r"$a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'Wi-Fi Direct|Microsoft Wi-Fi' }; "
          r"if (-not $a) { $a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -match '本地连接\*' } }; "
          r"if ($a) { ($a | Select-Object -First 1).ifIndex }",
    ]);
    final text = '${r.stdout}'.trim();
    return int.tryParse(text);
  } catch (_) {
    return null;
  }
}

/// 加黑洞路由。返回成功添加的条数。
Future<int> blockPublicDns() async {
  if (!Platform.isWindows) return 0;
  final ifIndex = await _hotspotIfIndex();
  if (ifIndex == null) return 0;
  var added = 0;
  for (final ip in kBlockedDns) {
    try {
      await Process.run('route', ['delete', ip]);
      final r = await Process.run(
        'route',
        ['add', ip, 'mask', '255.255.255.255', '0.0.0.0', 'metric', '1', 'if', '$ifIndex'],
      );
      if (r.exitCode == 0) added++;
    } catch (_) {}
  }
  return added;
}

/// 撤销黑洞路由。
Future<int> unblockPublicDns() async {
  if (!Platform.isWindows) return 0;
  var removed = 0;
  for (final ip in kBlockedDns) {
    try {
      final r = await Process.run('route', ['delete', ip]);
      if (r.exitCode == 0) removed++;
    } catch (_) {}
  }
  return removed;
}

/// 预热 ICS 的 DNS 缓存：让笔的查询命中缓存（~11ms），抢在公网 DNS 之前。
Future<bool> prewarmIcsDns(String gateway, String domain) async {
  if (!Platform.isWindows) return false;
  try {
    final r = await Process.run('powershell', [
      '-NoProfile',
      '-Command',
      r'Resolve-DnsName $args[0] -Server $args[1] -DnsOnly -ErrorAction SilentlyContinue | Out-Null',
      domain,
      gateway,
    ]);
    return r.exitCode == 0;
  } catch (_) {
    return false;
  }
}