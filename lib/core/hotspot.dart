import 'dart:convert';
import 'dart:io';

/// Windows 移动热点（ICS）探测与启动。
///
/// 全新词典笔没有任何权限可用，唯一入口是网络层：
/// 让笔连电脑开的移动热点，电脑就是它的网关/DNS，
/// 再把 iotapi.abupdate.com 指到网关 IP，请求就会落到本机服务上。
class HotspotInfo {
  HotspotInfo({
    required this.adapterName,
    required this.ipv4,
    this.prefixLength = 24,
  });

  final String adapterName;
  final String ipv4;
  final int prefixLength;

  @override
  String toString() => '$adapterName $ipv4/$prefixLength';
}

bool _looksLikeHotspotAdapter(String name) {
  final n = name.toLowerCase();
  return n.contains('local area connection') ||
      n.contains('wi-fi direct') ||
      n.contains('wifi direct') ||
      n.contains('mobile hotspot') ||
      n.contains('hotspot') ||
      n.contains('本地连接');
}

const String _ps51 = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';

/// 把脚本编码成 UTF-16LE base64，用 -EncodedCommand 执行。
///
/// 复杂脚本（带引号、换行、中文）通过 -Command 传参极易被 PowerShell
/// 的参数解析吃掉引号，这个方式是唯一稳妥的。
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

/// 探测已开启的移动热点。ICS 固定用 192.168.137.0/24。
///
/// 先走 Dart 的网卡枚举；枚举不到再用 PowerShell 查，避免某些虚拟网卡被隐藏。
Future<HotspotInfo?> detectHotspot() async {
  try {
    final interfaces = await NetworkInterface.list(
      type: InternetAddressType.IPv4,
      includeLoopback: false,
      includeLinkLocal: false,
    );
    HotspotInfo? fallback;
    for (final i in interfaces) {
      for (final a in i.addresses) {
        final ip = a.address;
        if (ip.startsWith('192.168.137.')) {
          return HotspotInfo(adapterName: i.name, ipv4: ip);
        }
        if (fallback == null && _looksLikeHotspotAdapter(i.name)) {
          fallback = HotspotInfo(adapterName: i.name, ipv4: ip);
        }
      }
    }
    if (fallback != null) return fallback;
  } catch (_) {}

  // 兜底：直接问系统要 192.168.137.x
  final ip = await _hotspotIpViaPowerShell();
  if (ip != null) return HotspotInfo(adapterName: '移动热点', ipv4: ip);
  return null;
}

Future<String?> _hotspotIpViaPowerShell() async {
  const script = r'''
$a = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
     Where-Object { $_.IPAddress -like '192.168.137.*' } |
     Select-Object -First 1
if ($a) { Write-Output $a.IPAddress }
''';
  try {
    final r = await Process.run(_ps51, _psArgs(script));
    final ip = r.stdout.toString().trim();
    if (ip.isNotEmpty && ip.contains('.')) return ip;
  } catch (_) {}
  return null;
}

/// 当前进程是否管理员（写 hosts、开关热点都需要）。
Future<bool> isElevated() async {
  if (!Platform.isWindows) return false;
  try {
    final r = await Process.run('whoami', ['/groups']);
    if (r.exitCode != 0) return false;
    // 高完整性级别 SID
    return r.stdout.toString().contains('S-1-16-12288');
  } catch (_) {
    return false;
  }
}

/// PowerShell 不能直接对 IAsyncOperation 调 GetResults()，
/// 必须用 WindowsRuntimeSystemExtensions.AsTask 包一层再等。
const String _hotspotScript = r'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction SilentlyContinue
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
  $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]
function Await($WinRtTask, $ResultType) {
  $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
  $netTask = $asTask.Invoke($null, @($WinRtTask))
  $netTask.Wait(-1) | Out-Null
  $netTask.Result
}
try {
  [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
  [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
  $p = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
  if ($null -eq $p) { Write-Output 'NO_PROFILE'; exit 2 }
  $mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($p)
  Write-Output ("STATE_BEFORE=" + $mgr.TetheringOperationalState)
  if ($mgr.TetheringOperationalState -ne 'On') {
    $r = Await ($mgr.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
    Write-Output ("STATUS=" + $r.Status)
    if ($r.AdditionalErrorMessage) { Write-Output ("DETAIL=" + $r.AdditionalErrorMessage) }
  }
  $cfg = $mgr.GetCurrentAccessPointConfiguration()
  Write-Output ("SSID=" + $cfg.Ssid)
  Write-Output ("KEY=" + $cfg.Passphrase)
  Write-Output ("STATE_AFTER=" + $mgr.TetheringOperationalState)
} catch {
  Write-Output ("ERR=" + $_.Exception.Message)
  exit 1
}
''';

/// 启动移动热点。返回 null 表示已就绪，否则是错误说明。
Future<String?> startHotspot() async {
  for (final exe in <String>[_ps51, 'powershell.exe']) {
    try {
      final r = await Process.run(exe, _psArgs(_hotspotScript));
      final out = '${r.stdout}${r.stderr}';
      if (out.contains('ERR=')) return out.split('ERR=').last.trim();
      if (out.contains('NO_PROFILE')) {
        return '电脑当前没有可用网络连接，热点无法共享（先连上 WiFi 或有线）。';
      }
      if (out.contains('STATE_AFTER=On')) return null;
      if (out.contains('STATUS=Success')) return null;
      final status = RegExp(r'STATUS=(\w+)').firstMatch(out)?.group(1);
      final detail = RegExp(r'DETAIL=(.+)').firstMatch(out)?.group(1);
      return '热点启动未成功${status == null ? '' : '（$status）'}'
          '${detail == null ? '' : '：$detail'}';
    } catch (_) {
      continue;
    }
  }
  return '无法调用系统热点接口，请在「设置 → 网络和 Internet → 移动热点」手动打开后再点一次。';
}

/// 热点上的 SSID / 密码，用于提示用户去笔上连接。
Future<({String? ssid, String? key})> hotspotCredentials() async {
  const script = r'''
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
try {
  $p = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
  $m = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($p)
  $c = $m.GetCurrentAccessPointConfiguration()
  Write-Output ("SSID=" + $c.Ssid)
  Write-Output ("KEY=" + $c.Passphrase)
} catch { }
''';
  try {
    final r = await Process.run(_ps51, _psArgs(script));
    String? ssid;
    String? key;
    for (final line in r.stdout.toString().split(RegExp(r'\r?\n'))) {
      final t = line.trim();
      if (t.startsWith('SSID=')) ssid = t.substring(5);
      if (t.startsWith('KEY=')) key = t.substring(4);
    }
    return (ssid: ssid, key: key);
  } catch (_) {
    return (ssid: null, key: null);
  }
}
