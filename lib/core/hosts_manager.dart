import 'dart:io';

/// hosts 文件的行级操作。
///
/// 设计原则：**只用正则精确增删我们自己的那一行**，其它行（包括注释、行尾符）
/// 一个字节都不改动。整文件重写很容易把用户自己的条目弄丢或改掉编码。
const String kDefaultHostsPath = r'C:\Windows\System32\drivers\etc\hosts';

/// 纯函数版本（供单测/预览）：在内容里插入或替换某域名指向。
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

/// 纯函数版本：只删除 IP + 域名都匹配的行。
String removeHostEntry(String content, String domain, {String? ip}) {
  final ipPart = ip == null ? r'\S+' : RegExp.escape(ip);
  final re = RegExp(
    r'^[ \t]*' + ipPart + r'[ \t]+' + RegExp.escape(domain) + r'[ \t]*\r?\n?',
    multiLine: true,
  );
  return content.replaceAll(re, '');
}

/// 从内容里查某个域名当前指向哪（第一个匹配）。
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

  /// 首次修改前备份一次；保留最早的原始版本，绝不覆盖。
  Future<String> backupOnce() async {
    final bak = File('$path.ydpentool.bak');
    if (!await bak.exists()) {
      await File(path).copy(bak.path);
    }
    return bak.path;
  }

  /// 写入劫持条目：只替换/追加这一行，不动其它内容。
  Future<void> setEntry(String ip, String domain) async {
    await backupOnce();
    final content = await read();
    final updated = upsertHostEntry(content, ip, domain);
    if (updated == content) return;
    await File(path).writeAsString(updated);
  }

  /// 精确删除我们写过的那一行（IP 必须匹配），其余内容不变。
  ///
  /// [ip] 为空时退化为按域名删除（只在不知道写入 IP 时才用）。
  Future<bool> removeEntry(String domain, {String? ip}) async {
    final content = await read();
    final updated = removeHostEntry(content, domain, ip: ip);
    if (updated == content) return false;
    await File(path).writeAsString(updated);
    return true;
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
