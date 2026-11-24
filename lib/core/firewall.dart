import 'dart:convert';
import 'dart:io';

const String _ps51 = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';

/// 复杂脚本用 -EncodedCommand 传递，避免引号被 PowerShell 参数解析吃掉。
String _encodePsCommand(String script) {
  final bytes = <int>[];
  for (final unit in script.codeUnits) {
    bytes.add(unit & 0xff);
    bytes.add((unit >> 8) & 0xff);
  }
  return base64Encode(bytes);
}

List<String> _psArgs(String script) => [
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-NonInteractive',
      '-EncodedCommand',
      _encodePsCommand(script),
    ];

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

/// 清除系统为"本程序"自动添加的**阻止**规则。
///
/// 背景：首次监听端口时 Windows 会弹窗询问，用户如果直接关掉或点了"取消"，
/// 系统会给该程序加上 Block 规则（通常只针对公用网络）。
/// 而 Windows 防火墙里 **阻止优先于允许**，所以只加 Allow 规则是没用的，
/// 表现就是笔一直卡在"检测更新"——TCP 被静默丢弃。
///
/// 返回清除的条数。
Future<int> removeBlockRulesForSelf() async {
  if (!Platform.isWindows) return 0;
  final exe = Platform.resolvedExecutable;

  // 用按行拼装的方式构造脚本：多行原始字符串在部分工具链里会被误判。
  final script = <String>[
    "\$exe = '$exe'",
    r'$name = [IO.Path]::GetFileNameWithoutExtension($exe)',
    r'$removed = 0',
    r'$rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Block -ErrorAction SilentlyContinue)',
    r'foreach ($r in $rules) {',
    r'  $app = $null',
    r'  try { $app = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue } catch {}',
    r'  $hit = $false',
    r'  if ($app -and $app.Program) {',
    r'    if ($app.Program -eq $exe) { $hit = $true }',
    r'    elseif ([IO.Path]::GetFileNameWithoutExtension($app.Program) -eq $name) { $hit = $true }',
    r'  }',
    r'  if ($hit) {',
    r'    Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue',
    r'    $removed++',
    r'  }',
    r'}',
    r'Write-Output ("REMOVED=" + $removed)',
  ].join('\n');

  for (final psExe in <String>[_ps51, 'powershell.exe']) {
    try {
      final r = await Process.run(psExe, _psArgs(script));
      final out = '${r.stdout}${r.stderr}';
      final m = RegExp(r'REMOVED=(\d+)').firstMatch(out);
      if (m != null) return int.parse(m.group(1)!);
    } catch (_) {
      continue;
    }
  }
  return 0;
}

/// 放行给定 TCP 端口的入站连接（所有网络配置文件）。需要管理员。
Future<FirewallResult> ensureInboundPortRule(int port) async {
  if (!Platform.isWindows) {
    return FirewallResult(ok: false, detail: '仅 Windows 需要处理防火墙');
  }
  // 先清掉可能存在的阻止规则，否则允许规则不生效
  final removed = await removeBlockRulesForSelf();
  final prefix = removed > 0 ? '已清除 $removed 条阻止规则；' : '';
  if (await _ruleExists()) {
    return FirewallResult(ok: true, detail: '$prefix入站规则已存在（TCP $port）');
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
      return FirewallResult(
        ok: true,
        detail: '$prefix已放行入站 TCP $port（$kFirewallRuleName）',
      );
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
