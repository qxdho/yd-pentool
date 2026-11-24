import 'dart:convert';
import 'dart:io';

/// Windows 移动热点（ICS）探测与启动。
///
/// 全新词典笔没有任何权限可用，唯一入口是网络层：
/// 让笔连电脑开的移动热点，电脑就是它的网关/DNS，
/// 再把 iotapi.abupdate.com 指到网关 IP，请求就会落到本机服务上。
class HotspotInfo {
  HotspotInfo({required this.adapterName, required this.ipv4, required this.prefixLength});

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
      n.contains('hotspot');
}

/// 探测已开启的移动热点（ICS 固定用 192.168.137.0/24）。
Future<HotspotInfo?> detectHotspot() async {
  try {
    final interfaces = await NetworkInterface.list(
      type: InternetAddressType.IPv4,
      includeLoopback: false,
      includeLinkLocal: false,
    );
    HotspotInfo? best;
    for (final i in interfaces) {
      for (final a in i.addresses) {
        final ip = a.address;
        final isIcs = ip.startsWith('192.168.137.');
        final looksHot = _looksLikeHotspotAdapter(i.name) || _looksLikeHotspotAdapter(i.description ?? '');
        if (!isIcs && !looksHot) continue;
        final info = HotspotInfo(
          adapterName: i.name,
          ipv4: ip,
          prefixLength: a.prefixLength ?? 24,
        );
        // ICS 网段优先级最高
        if (isIcs) return info;
        best ??= info;
      }
    }
    return best;
  } catch (_) {
    return null;
  }
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

/// 通过 WinRT 接口尝试启动移动热点。返回 null 表示成功，否则是错误说明。
///
/// PowerShell 7 对 WinRT 支持差，这里优先用 Windows PowerShell 5.1。
Future<String?> startHotspot() async {
  final script = r'''
$ErrorActionPreference = 'Stop'
try {
  [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
  [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
  $profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
  if ($null -eq $profile) { Write-Output 'NO_INTERNET_PROFILE'; exit 2 }
  $mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
  $result = $mgr.StartTetheringAsync().GetResults()
  Write-Output ("STATUS=" + $result.Status)
  $cfg = $mgr.GetCurrentAccessPointConfiguration()
  Write-Output ("SSID=" + $cfg.Ssid)
  Write-Output ("KEY=" + $cfg.Passphrase)
} catch {
  Write-Output ("ERROR=" + $_.Exception.Message)
  exit 1
}
''';
  final candidates = <String>[
    r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    'powershell.exe',
  ];
  for (final exe in candidates) {
    try {
      final r = await Process.run(exe, ['-NoProfile', '-NonInteractive', '-Command', script]);
      final out = '${r.stdout}${r.stderr}';
      if (out.contains('ERROR=')) {
        return out.split('ERROR=').last.trim();
      }
      if (out.contains('NO_INTERNET_PROFILE')) {
        return '电脑当前没有可用网络连接，热点无法共享（先连上 WiFi/有线）。';
      }
      if (out.contains('STATUS=') && !out.contains('AccessPointCannotStart')) {
        return null;
      }
      return '热点启动结果未知：${out.trim()}';
    } catch (e) {
      continue;
    }
  }
  return '无法调用系统热点接口，请在「设置 → 网络 → 移动热点」手动打开后再点一次。';
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
    final r = await Process.run(
      r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
    );
    final out = latin1.decode(r.stdout as List<int>, allowInvalid: true);
    String? ssid;
    String? key;
    for (final line in const LineSplitter().convert(out)) {
      if (line.startsWith('SSID=')) ssid = line.substring(5).trim();
      if (line.startsWith('KEY=')) key = line.substring(4).trim();
    }
    return (ssid: ssid, key: key);
  } catch (_) {
    return (ssid: null, key: null);
  }
}
