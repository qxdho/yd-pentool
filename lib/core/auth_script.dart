import 'hash_util.dart';

/// 从固件中解析出的一段鉴权脚本及其改写目标。
class AuthScript {
  AuthScript({
    required this.scriptStart,
    required this.hashOffset,
    required this.storedHash,
    required this.algorithm,
    required this.trailingNewline,
    required this.dashSuffix,
    required this.prompt,
    required this.scriptText,
    required this.hitMarker,
    required this.confidence,
  });

  /// 脚本正文在镜像中的近似起点（仅用于展示定位）。
  final int scriptStart;

  /// 哈希字符串在镜像中的精确字节偏移 = 改写目标。
  final int hashOffset;

  /// 固件中原有的哈希字符串。
  final String storedHash;

  final HashAlgorithm algorithm;

  /// `echo $PASSWD` → true（带换行）；`echo -n $PASSWD` → false。
  final bool trailingNewline;

  /// 比较串是否带 `  -` 后缀（md5sum 输出格式的尾巴）。
  final bool dashSuffix;

  final String prompt;

  /// 脚本正文（供人工复核，UI 要展示出来）。
  final String scriptText;

  /// 触发命中的标记串，例如 `/tmp/.adb_auth_verified`。
  final String hitMarker;

  /// 0~100，解析置信度。
  final int confidence;

  String get offsetHex => '0x${hashOffset.toRadixString(16).toUpperCase()}';

  /// 比较串的完整形态，例如 `302af1...c92  -`。
  String get comparisonLiteral =>
      dashSuffix ? '$storedHash  -' : storedHash;

  Map<String, dynamic> toJson() => {
        'scriptStart': scriptStart,
        'hashOffset': hashOffset,
        'offsetHex': offsetHex,
        'storedHash': storedHash,
        'algorithm': algorithm.name,
        'trailingNewline': trailingNewline,
        'dashSuffix': dashSuffix,
        'prompt': prompt,
        'hitMarker': hitMarker,
        'confidence': confidence,
      };
}

/// 解析脚本窗口里的鉴权逻辑。
///
/// 不再硬编码任何机型/偏移：算法看 `xxxsum` 命令，换行看 `echo -n`，
/// 比较串尾巴看 `-`，一切都是从脚本本身读出来的。
AuthScript? parseAuthScript({
  required String window,
  required int windowBase,
  required String marker,
  required int markerOffset,
}) {
  // 1) 先在窗口里找哈希：优先找紧挨 `-` 的 32/40/64/128 位十六进制串
  final hashRe = RegExp(r'([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})');
  final matches = hashRe.allMatches(window).toList();
  if (matches.isEmpty) return null;

  // 2) 说明脚本里用的是哪个散列命令
  HashAlgorithm? algoFromCmd;
  final cmdRe = RegExp(r'\b(sha512sum|sha256sum|sha1sum|md5sum)\b');
  final cmd = cmdRe.firstMatch(window);
  if (cmd != null) {
    algoFromCmd = switch (cmd.group(1)) {
      'md5sum' => HashAlgorithm.md5,
      'sha1sum' => HashAlgorithm.sha1,
      'sha256sum' => HashAlgorithm.sha256,
      'sha512sum' => HashAlgorithm.sha512,
      _ => null,
    };
  }

  // 3) 挑最像"比较目标"的那一个：邻近有 = 或 == ，且长度与算法一致
  RegExpMatch? best;
  var bestScore = -1;
  for (final m in matches) {
    var score = 0;
    final end = m.end;
    final before = window.substring(end < window.length ? end : window.length);
    final around = window.substring(
      m.start > 24 ? m.start - 24 : 0,
      end + 24 < window.length ? end + 24 : window.length,
    );
    if (around.contains('=')) score += 3;
    if (around.contains('-')) score += 1;
    if (before.startsWith('  -')) score += 3;
    if (algoFromCmd != null && m.group(1)!.length == algoFromCmd.hexLength) {
      score += 4;
    }
    if (window.contains('PASSWD') || window.contains('PASS')) score += 2;
    if (score > bestScore) {
      bestScore = score;
      best = m;
    }
  }
  if (best == null) return null;

  final hash = best.group(1)!;
  final algo = algoFromCmd ?? HashAlgorithmX.fromHexLength(hash.length);
  if (algo == null) return null;

  // 4) 换行语义
  final noNewline = RegExp(r'echo\s+-n\b').hasMatch(window);
  final trailingNewline = !noNewline;

  // 5) 比较串尾巴
  final tail = window.substring(best.end, best.end + 4 <= window.length ? best.end + 4 : window.length);
  final dashSuffix = tail.startsWith('  -');

  // 6) 提示语
  final promptMatch = RegExp(r'read\s+-p\s+"([^"]*)"').firstMatch(window);
  final prompt = promptMatch?.group(1) ?? '';

  // 7) 脚本起点：从命中标记往前找最近的 `#!/bin/sh`
  final markerRel = (markerOffset - windowBase).clamp(0, window.length);
  var scriptStartRel = window.lastIndexOf('#!/bin/sh', markerRel);
  if (scriptStartRel < 0) scriptStartRel = 0;

  var confidence = 40;
  if (algoFromCmd != null) confidence += 25;
  if (dashSuffix) confidence += 15;
  if (prompt.isNotEmpty) confidence += 10;
  if (trailingNewline) confidence += 5;
  if (confidence > 95) confidence = 95;

  return AuthScript(
    scriptStart: windowBase + scriptStartRel,
    hashOffset: windowBase + best.start,
    storedHash: hash,
    algorithm: algo,
    trailingNewline: trailingNewline,
    dashSuffix: dashSuffix,
    prompt: prompt,
    scriptText: window.substring(scriptStartRel).split('\u0000').first,
    hitMarker: marker,
    confidence: confidence,
  );
}
