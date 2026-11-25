import 'dart:convert';
import 'dart:io';

/// hosts 文件的行级操作。
///
/// 三条原则：
/// 1. 只用正则精确增删我们自己管理的那些行，其它行（含注释、行尾符）字节不动；
/// 2. 同域名下**别人**写的记录要临时注释掉，否则 Windows 只用第一条匹配；
/// 3. 被临时注释的原行记在状态文件里，还原时逐行恢复。
///
/// 重要：本工具自己会写两条（IPv4 指向热点网关、IPv6 指向 ::1），
/// 它们属于同一组，**不能互相注释**——早期版本分两次写就踩过这个坑：
/// 写完 A 记录后写 ::1 时，把刚写的 A 记录当成"别人的"注释掉了，
/// 结果笔解析到 ::1 连自己，请求永远到不了本机。
const String kDefaultHostsPath = r'C:\Windows\System32\drivers\etc\hosts';
const String kDisabledPrefix = '# [yd-pentool 临时禁用] ';

/// 本工具写 IPv6 时固定用这个地址（笔去连自己，快速失败后回落 IPv4）。
const String kOurIpv6 = '::1';

/// 判断某个 IP 是不是本工具写的（热点网段或 ::1）。
bool isOurEntryIp(String ip) =>
    ip == kOurIpv6 || ip.startsWith('192.168.137.');

/// 纯函数：插入或替换某域名指向。
///
/// 只替换 **IP 也相同** 的那一行；不同 IP 的同域名行由
/// [disableForeignEntries] 负责注释，不能在这里覆盖——
/// 否则本工具的 IPv4 与 IPv6 两条映射会互相顶掉。
String upsertHostEntry(String content, String ip, String domain) {
  final line = '$ip $domain';
  final re = RegExp(
    r'^[ \t]*' + RegExp.escape(ip) + r'[ \t]+' + RegExp.escape(domain) + r'[ \t]*\r?$',
    multiLine: true,
  );
  if (re.hasMatch(content)) return content.replaceAll(re, line);

  final sep = content.isEmpty || content.endsWith('\n') ? '' : '\r\n';
  final tail = content.endsWith('\n') || content.isEmpty ? '' : '\r\n';
  return '$content$sep$line$tail';
}

/// 纯函数：删除指定 IP 的那一行。
String removeHostEntry(String content, String domain, {String? ip}) {
  final ipPart = ip == null ? r'\S+' : RegExp.escape(ip);
  final re = RegExp(
    r'^[ \t]*' + ipPart + r'[ \t]+' + RegExp.escape(domain) + r'[ \t]*\r?\n?',
    multiLine: true,
  );
  return content.replaceAll(re, '');
}

/// 纯函数：把同域名但**不属于本工具**的行注释掉，收进 [disabled]。
///
/// 保留原始行尾（`\r`），还原时逐字节一致。
String disableForeignEntries(
  String content,
  String domain,
  List<String> disabled,
) {
  final lines = content.split('\n');
  final out = <String>[];
  for (final raw in lines) {
    final trimmed = raw.replaceAll('\r', '').trim();
    if (trimmed.isEmpty || trimmed.startsWith('#')) {
      out.add(raw);
      continue;
    }
    final parts = trimmed.split(RegExp(r'\s+'));
    if (parts.length >= 2 && parts.sublist(1).contains(domain)) {
      if (isOurEntryIp(parts.first)) {
        out.add(raw); // 本工具的行，保留
      } else {
        disabled.add(raw);
        out.add(kDisabledPrefix + raw);
      }
    } else {
      out.add(raw);
    }
  }
  return out.join('\n');
}

/// 纯函数：把注释掉的原有行恢复回去。
String restoreDisabledEntries(String content, List<String> disabled) {
  var result = content;
  for (final line in disabled) {
    result = result.replaceFirst('$kDisabledPrefix$line', line);
  }
  return result;
}

/// 纯函数：查某域名当前指向哪（第一个未被注释的匹配）。
String? findHostEntry(String content, String domain) {
  for (final line in content.split(RegExp(r'\r?\n'))) {
    final trimmed = line.trim();
    if (trimmed.isEmpty || trimmed.startsWith('#')) continue;
    final parts = trimmed.split(RegExp(r'\s+'));
    if (parts.length >= 2 && parts.sublist(1).contains(domain)) return parts.first;
  }
  return null;
}

class HostsManager {
  HostsManager({this.path = kDefaultHostsPath, this.statePath});

  final String path;

  /// 记录"被我们临时禁用"的行，放在用户目录下，重启后也能还原。
  final String? statePath;

  String get _state =>
      statePath ?? '${Platform.environment['LOCALAPPDATA'] ?? '.'}\\yd-pentool\\hosts_state.json';

  Future<String> read() => File(path).readAsString();

  Future<String> backupOnce() async {
    final bak = File('$path.ydpentool.bak');
    if (!await bak.exists()) {
      await File(path).copy(bak.path);
    }
    return bak.path;
  }

  Future<List<String>> _loadState() async {
    try {
      final f = File(_state);
      if (!await f.exists()) return [];
      final data = jsonDecode(await f.readAsString());
      if (data is List) return data.cast<String>();
    } catch (_) {}
    return [];
  }

  Future<void> _saveState(List<String> lines) async {
    try {
      final f = File(_state);
      await f.parent.create(recursive: true);
      await f.writeAsString(jsonEncode(lines));
    } catch (_) {}
  }

  /// 接管某域名：写入 IPv4（热点网关）+ IPv6（::1），并把别人的同域名记录临时注释。
  ///
  /// 两条记录算同一组，**一次写完**，避免互相注释。
  /// 返回被临时禁用的行数。
  Future<int> activate(String domain, {required String ipv4}) async {
    await backupOnce();
    final content = await read();
    final disabled = <String>[];
    var updated = disableForeignEntries(content, domain, disabled);
    updated = upsertHostEntry(updated, ipv4, domain);
    updated = upsertHostEntry(updated, kOurIpv6, domain);
    if (disabled.isNotEmpty) await _saveState(disabled);
    if (updated != content) await File(path).writeAsString(updated);
    return disabled.length;
  }

  /// 撤销接管：删掉本工具写的所有行（IPv4 热点网段 + ::1），并恢复被注释的原行。
  ///
  /// 返回 (是否删除了本工具的条目, 恢复的行数)。
  Future<(bool, int)> deactivate(String domain) async {
    final content = await read();
    final disabled = await _loadState();
    var updated = removeHostEntry(content, domain, ip: kOurIpv6);
    final ours = RegExp(
      r'^[ \t]*192\.168\.137\.\d{1,3}[ \t]+' + RegExp.escape(domain) + r'[ \t]*\r?\n?',
      multiLine: true,
    );
    final hadV4 = ours.hasMatch(updated);
    updated = updated.replaceAll(ours, '');
    updated = restoreDisabledEntries(updated, disabled);
    final removed = hadV4 || updated != content;
    if (updated != content) await File(path).writeAsString(updated);
    if (disabled.isNotEmpty) await _saveState(const []);
    return (removed, disabled.length);
  }

  Future<String?> currentEntry(String domain) async =>
      findHostEntry(await read(), domain);

  /// hosts 里与某域名相关的所有条目，用于诊断显示。
  Future<List<String>> relatedEntries(String domain) async {
    final content = await read();
    final out = <String>[];
    for (final line in content.split(RegExp(r'\r?\n'))) {
      final trimmed = line.trim();
      if (trimmed.isEmpty) continue;
      if (trimmed.startsWith(kDisabledPrefix)) {
        out.add('${trimmed.replaceFirst(kDisabledPrefix, '')}  （已被本工具临时禁用）');
        continue;
      }
      if (trimmed.startsWith('#')) continue;
      final parts = trimmed.split(RegExp(r'\s+'));
      if (parts.length >= 2 && parts.sublist(1).contains(domain)) {
        final tag = isOurEntryIp(parts.first) ? '  （本工具）' : '';
        out.add('$trimmed$tag');
      }
    }
    return out;
  }

  Future<bool> flushDns() async {
    try {
      final r = await Process.run('ipconfig', ['/flushdns']);
      return r.exitCode == 0;
    } catch (_) {
      return false;
    }
  }
}
