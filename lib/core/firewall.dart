import 'dart:io';

/// Windows 防火墙：放行本程序的入站端口。
///
/// 这是抓包最常见的静默失败原因——笔发来的 SYN 被防火墙丢掉，
/// 程序日志里一片空白，看起来像"笔没发请求"。
const String kFirewallRuleName = 'yd-pentool-capture';

class FirewallResult {
  FirewallResult({required this.ok, required this.detail});
  final bool ok;
  final String detail;

  @override
  String toString() => detail;
}

Future<bool> _ruleExists() async {
  try {
    final r = await Process.run('netsh', [
      'advfirewall',
      'firewall',
      'show',
      'rule',
      'name=$kFirewallRuleName',
    ]);
    return r.exitCode == 0 && r.stdout.toString().contains(kFirewallRuleName);
  } catch (_) {
    return false;
  }
}

/// 放行给定 TCP 端口的入站连接（所有网络配置文件）。需要管理员。
Future<FirewallResult> ensureInboundPortRule(int port) async {
  if (!Platform.isWindows) {
    return FirewallResult(ok: false, detail: '仅 Windows 需要处理防火墙');
  }
  if (await _ruleExists()) {
    return FirewallResult(ok: true, detail: '入站规则已存在（TCP $port）');
  }
  try {
    final r = await Process.run('netsh', [
      'advfirewall',
      'firewall',
      'add',
      'rule',
      'name=$kFirewallRuleName',
      'dir=in',
      'action=allow',
      'protocol=TCP',
      'localport=$port',
      'profile=any',
    ]);
    final out = '${r.stdout}${r.stderr}'.trim();
    if (r.exitCode == 0) {
      return FirewallResult(ok: true, detail: '已放行入站 TCP $port（$kFirewallRuleName）');
    }
    return FirewallResult(
      ok: false,
      detail: '添加防火墙规则失败（需要管理员）：$out',
    );
  } catch (e) {
    return FirewallResult(ok: false, detail: '调用 netsh 失败：$e');
  }
}

/// 清理本程序添加的规则。
Future<bool> removeInboundRule() async {
  if (!Platform.isWindows) return false;
  try {
    final r = await Process.run('netsh', [
      'advfirewall',
      'firewall',
      'delete',
      'rule',
      'name=$kFirewallRuleName',
    ]);
    return r.exitCode == 0;
  } catch (_) {
    return false;
  }
}
