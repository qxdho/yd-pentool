import 'dart:convert';
import 'dart:io';

class AdbDevice {
  AdbDevice(this.serial, this.state);
  final String serial;
  final String state;
  @override
  String toString() => '$serial($state)';
}

class AdbResult {
  AdbResult(this.exitCode, this.stdout, this.stderr);
  final int exitCode;
  final String stdout;
  final String stderr;
  String get combined => '$stdout$stderr';
  @override
  String toString() => 'exit=$exitCode\n$combined';
}

/// 解析 `adb devices` 输出。
List<AdbDevice> parseDevices(String output) {
  final result = <AdbDevice>[];
  for (final line in output.split(RegExp(r'\r?\n'))) {
    final trimmed = line.trim();
    if (trimmed.isEmpty) continue;
    if (trimmed.startsWith('List of devices')) continue;
    if (trimmed.startsWith('*')) continue;
    final parts = trimmed.split(RegExp(r'\s+'));
    if (parts.length >= 2) result.add(AdbDevice(parts[0], parts[1]));
  }
  return result;
}

/// `adb shell auth` 的输出判定。
bool authSucceeded(String output) => output.contains('success.');

/// `adb shell id` 的 root 判定。
bool isRootOutput(String output) => output.contains('uid=0');

class AdbClient {
  AdbClient(this.adbPath);

  final String adbPath;

  /// 依次找：显式路径 → PATH → 程序同目录 artifacts/adb.exe。
  static Future<String?> locate({String? explicit}) async {
    if (explicit != null && File(explicit).existsSync()) return explicit;
    final exeDir = File(Platform.resolvedExecutable).parent.path;
    final candidates = <String>[
      '$exeDir${Platform.pathSeparator}adb.exe',
      '$exeDir${Platform.pathSeparator}artifacts${Platform.pathSeparator}adb.exe',
    ];
    for (final c in candidates) {
      if (File(c).existsSync()) return c;
    }
    try {
      final r = await Process.run('where', ['adb']);
      if (r.exitCode == 0) {
        final first = r.stdout.toString().split(RegExp(r'\r?\n')).first.trim();
        if (first.isNotEmpty && File(first).existsSync()) return first;
      }
    } catch (_) {}
    return null;
  }

  Future<AdbResult> run(
    List<String> args, {
    String? stdinText,
    Duration timeout = const Duration(seconds: 20),
  }) async {
    final p = await Process.start(adbPath, args);
    if (stdinText != null) {
      p.stdin.write(stdinText);
      await p.stdin.flush();
    }
    await p.stdin.close();
    final out = p.stdout.transform(utf8.decoder).join();
    final err = p.stderr.transform(utf8.decoder).join();
    final code = await p.exitCode.timeout(timeout, onTimeout: () {
      p.kill();
      return -1;
    });
    return AdbResult(code, await out, await err);
  }

  Future<List<AdbDevice>> devices() async {
    final r = await run(['devices']);
    return parseDevices(r.combined);
  }

  Future<AdbResult> shell(String command, {String? serial}) => run([
        if (serial != null) ...['-s', serial],
        'shell',
        command,
      ]);

  /// 执行 `adb shell auth` 并喂入口令。
  ///
  /// 脚本里是 `read -p ... PASSWD`，读的是 shell 的 stdin，
  /// 所以直接把口令写到进程 stdin 即可。
  Future<bool> authenticate(String password, {String? serial}) async {
    final p = await Process.start(adbPath, [
      if (serial != null) ...['-s', serial],
      'shell',
      'auth',
    ]);
    p.stdin.writeln(password);
    await p.stdin.flush();
    await p.stdin.close();
    final out = await p.stdout.transform(utf8.decoder).join();
    final err = await p.stderr.transform(utf8.decoder).join();
    await p.exitCode;
    return authSucceeded('$out$err');
  }

  Future<bool> hasRoot({String? serial}) async {
    final r = await shell('id', serial: serial);
    return isRootOutput(r.combined);
  }
}
