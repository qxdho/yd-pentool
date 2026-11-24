import 'dart:convert';
import 'dart:io';

/// hosts 文件的行级操作。
///
/// 三条原则：
/// 1. 只用正则精确增删我们自己的那一行，其它行（包括注释、行尾符）字节不动；
/// 2. **如果同一个域名已经指向别的 IP**（别的工具或用户自己配的），
///    必须临时注释掉它，否则 Windows 只会用第一条匹配，我们的劫持等于没生效；
/// 3. 被临时注释的原行记在状态文件里，还原时逐行恢复。
const String kDefaultHostsPath = r'C:\Windows\System32\drivers\etc\hosts';
const String kDisabledPrefix = '# [yd-pentool 临时禁用] ';

/// 纯函数：插入或替换某域名指向。
String upsertHostEntry(String content, String ip, String domain) {
  final line = '$ip $domain';
  final re = RegExp(
    r'^[ \t]*\S+[ \t]+' + RegExp.escape(domain) + r'[ \t]*\r?$',
    multiLine: true,
  );
  if (re.hasMatch(content)) {
    return content.replaceAll(re, line);
  }
  final sep = content.isEmpty || content.endsWith('\n') ? '' : '\r\n';
  final tail = content.endsWith('\n') || content.isEmpty ? '' : '\r\n';
  return '$content$sep$line$tail';
}

/// 纯函数：只删除 IP + 域名都匹配的行。
String removeHostEntry(String content, String domain, {String? ip}) {
  final ipPart = ip == null ? r'\S+' : RegExp.escape(ip);
  final re = RegExp(
    r'^[ \t]*' + ipPart + r'[ \t]+' + RegExp.escape(domain) + r'[ \t]*\r?\n?',
    multiLine: true,
  );
  return content.replaceAll(re, '');
}

/// 纯函数：把同域名但指向其它 IP 的行注释掉，收进 [disabled]。
///
/// 保留原始行尾（`\r`），这样还原回去是逐字节一致的。
String disableForeignEntries(
  String content,
  String domain,
  String keepIp,
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
    if (parts.length >= 2 &&
        parts.sublist(1).contains(domain) &&
        parts.first != keepIp) {
      disabled.add(raw);
      out.add(kDisabledPrefix + raw);
    } else {
      out.add(raw);
    }
  }
  return out.join('\n');
}

/// 纯函数：把之前注释掉的行恢复回去。
String restoreDisabledEntries(String content, List<String> disabled) {
  var result = content;
  for (final line in disabled) {
    result = result.replaceFirst('$kDisabledPrefix$line', line);
  }
  return result;
}

/// 从内容里查某个域名当前指向哪（第一个未被注释的匹配）。
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

  /// 首次修改前备份一次；保留最早的原始版本，绝不覆盖。
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

  /// 写入劫持条目。
  ///
  /// 若发现同域名指向别的 IP，先把那些行注释掉并记下来，
  /// 否则 Windows 只用第一条匹配，劫持不会生效。
  /// 返回被临时禁用的行数。
  Future<int> setEntry(String ip, String domain) async {
    await backupOnce();
    final content = await read();
    final disabled = <String>[];
    var updated = disableForeignEntries(content, domain, ip, disabled);
    updated = upsertHostEntry(updated, ip, domain);
    if (disabled.isNotEmpty) {
      await _saveState(disabled);
    }
    if (updated != content) {
      await File(path).writeAsString(updated);
    }
    return disabled.length;
  }

  /// 精确删除我们写过的那一行（IP 必须匹配），并恢复被临时禁用的行。
  ///
  /// 返回 (是否删除了本工具的条目, 恢复的行数)。
  Future<(bool, int)> removeEntry(String domain, {String? ip}) async {
    final content = await read();
    final disabled = await _loadState();
    var updated = removeHostEntry(content, domain, ip: ip);
    updated = restoreDisabledEntries(updated, disabled);
    final changed = updated != content;
    if (changed) {
      await File(path).writeAsString(updated);
    }
    if (disabled.isNotEmpty) {
      await _saveState(const []);
    }
    return (changed, disabled.length);
  }

  Future<String?> currentEntry(String domain) async =>
      findHostEntry(await read(), domain);

  /// hosts 里与某域名相关的所有条目（含指向别人的），用于诊断显示。
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
      if (trimmed.split(RegExp(r'\s+')).sublist(1).contains(domain)) {
        out.add(trimmed);
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
