import 'dart:io';

/// hosts 文件的行级操作，做成纯函数便于单测。
const String kDefaultHostsPath = r'C:\Windows\System32\drivers\etc\hosts';

String upsertHostEntry(String content, String ip, String domain) {
  final lines = content.split(RegExp(r'\r?\n'));
  final kept = <String>[];
  var replaced = false;
  for (final line in lines) {
    final trimmed = line.trim();
    if (trimmed.isEmpty || trimmed.startsWith('#')) {
      kept.add(line);
      continue;
    }
    final parts = trimmed.split(RegExp(r'\s+'));
    if (parts.length >= 2 && parts.sublist(1).contains(domain)) {
      if (!replaced) {
        kept.add('$ip $domain');
        replaced = true;
      }
      continue;
    }
    kept.add(line);
  }
  if (!replaced) kept.add('$ip $domain');
  return kept.join('\r\n');
}

String removeHostEntry(String content, String domain) {
  final lines = content.split(RegExp(r'\r?\n'));
  final kept = <String>[];
  for (final line in lines) {
    final trimmed = line.trim();
    if (trimmed.isEmpty || trimmed.startsWith('#')) {
      kept.add(line);
      continue;
    }
    final parts = trimmed.split(RegExp(r'\s+'));
    if (parts.length >= 2 && parts.sublist(1).contains(domain)) continue;
    kept.add(line);
  }
  return kept.join('\r\n');
}

/// 从原始 hosts 内容里查某个域名当前指向哪。
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
  HostsManager({this.path = kDefaultHostsPath});

  final String path;

  Future<String> read() => File(path).readAsString();

  bool get canWrite {
    try {
      final f = File(path);
      return f.existsSync() && !f.readAsStringSync().isEmpty;
    } catch (_) {
      return false;
    }
  }

  /// 写入前自动备份一次，避免破坏用户原有 hosts。
  Future<String> _backupOnce() async {
    final bak = File('$path.ydpentool.bak');
    if (!await bak.exists()) {
      await File(path).copy(bak.path);
    }
    return bak.path;
  }

  Future<void> setEntry(String ip, String domain) async {
    final backup = await _backupOnce();
    final current = await read();
    await File(path).writeAsString(upsertHostEntry(current, ip, domain));
    // writeAsString 默认会截断重写，对 hosts 是预期行为
    if (backup.isEmpty) throw StateError('备份路径异常');
  }

  Future<void> removeEntry(String domain) async {
    final current = await read();
    await File(path).writeAsString(removeHostEntry(current, domain));
  }

  Future<String?> currentEntry(String domain) async =>
      findHostEntry(await read(), domain);

  Future<bool> flushDns() async {
    try {
      final r = await Process.run('ipconfig', ['/flushdns']);
      return r.exitCode == 0;
    } catch (_) {
      return false;
    }
  }
}
