import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'core/adb.dart';
import 'core/artifact_builder.dart';
import 'core/auth_script.dart';
import 'core/checksum.dart';
import 'core/firmware_download.dart';
import 'core/firmware_scanner.dart';
import 'core/firewall.dart';
import 'core/hash_util.dart';
import 'core/hosts_manager.dart';
import 'core/hotspot.dart';
import 'core/image_patcher.dart';
import 'core/ota_capture.dart';
import 'core/ota_proxy.dart';
import 'core/win_window.dart';

void main() => runApp(const YdPenToolApp());

class YdPenToolApp extends StatelessWidget {
  const YdPenToolApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '词典笔 ADB 口令改写器',
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: const Color(0xFF3B82F6),
        scaffoldBackgroundColor: const Color(0xFFF5F6F8),
        fontFamily: 'Microsoft YaHei UI',
        fontFamilyFallback: const ['Microsoft YaHei', 'Segoe UI'],
        cardTheme: CardTheme(
          elevation: 0,
          margin: EdgeInsets.zero,
          color: Colors.white,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(14),
            side: const BorderSide(color: Color(0xFFE6E8EC)),
          ),
        ),
        dividerTheme: const DividerThemeData(color: Color(0xFFE6E8EC), thickness: 1),
        filledButtonTheme: FilledButtonThemeData(
          style: FilledButton.styleFrom(
            minimumSize: const Size(0, 40),
            padding: const EdgeInsets.symmetric(horizontal: 18),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
            textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
          ),
        ),
        outlinedButtonTheme: OutlinedButtonThemeData(
          style: OutlinedButton.styleFrom(
            minimumSize: const Size(0, 40),
            padding: const EdgeInsets.symmetric(horizontal: 16),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
            side: const BorderSide(color: Color(0xFFD7DBE2)),
            textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500),
          ),
        ),
        textButtonTheme: TextButtonThemeData(
          style: TextButton.styleFrom(
            textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          isDense: true,
          filled: true,
          fillColor: const Color(0xFFF9FAFB),
          contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(10),
            borderSide: const BorderSide(color: Color(0xFFE6E8EC)),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(10),
            borderSide: const BorderSide(color: Color(0xFFE6E8EC)),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(10),
            borderSide: const BorderSide(color: Color(0xFF3B82F6), width: 1.5),
          ),
          labelStyle: const TextStyle(fontSize: 12),
        ),
        textTheme: const TextTheme(
          titleMedium: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
          bodyMedium: TextStyle(fontSize: 13, height: 1.5),
          bodySmall: TextStyle(fontSize: 12, height: 1.5, color: Color(0xFF6B7280)),
        ),
      ),
      builder: (context, child) => MediaQuery.withClampedTextScaling(
        minScaleFactor: 0.9,
        maxScaleFactor: 1.2,
        child: child ?? const SizedBox.shrink(),
      ),
      home: const WizardPage(),
    );
  }
}

class WizardPage extends StatefulWidget {
  const WizardPage({super.key});

  @override
  State<WizardPage> createState() => _WizardPageState();
}

class _WizardPageState extends State<WizardPage> {
  final _imagePath = TextEditingController();
  final _password = TextEditingController();
  final _endPositions = TextEditingController();
  final _jsonPath = TextEditingController();
  final _ssidCtrl = TextEditingController();
  final _passCtrl = TextEditingController();
  final _log = StringBuffer();
  OtaCapture? _capture;
  String? _captureRaw;
  BuiltArtifacts? _artifacts;

  ScanResult? _scan;
  AuthScript? _selected;
  ChecksumReport? _checksum;
  OtaProxyServer? _server;
  final HostsManager _hosts = HostsManager();
  AdbClient? _adb;
  String? _lanIp;
  HotspotInfo? _hotspot;
  String? _hostsIp;
  bool _hotspotStartedByUs = false;
  bool _busy = false;
  int _step = 0;

  void _write(String line) {
    setState(() {
      _log.writeln(line);
    });
  }

  Future<void> _scanImage() async {
    final path = _imagePath.text.trim();
    if (path.isEmpty) {
      _write('[!] 先填固件路径');
      return;
    }
    final file = File(path);
    if (!await file.exists()) {
      _write('[!] 文件不存在：$path');
      return;
    }
    setState(() => _busy = true);
    try {
      _write('[*] 扫描中：$path（${await file.length()} 字节）');
      final result = await scanFirmware(file);
      _scan = result;
      _selected = result.candidates.isEmpty ? null : result.candidates.first;
      _step = 2;
      _write('[+] 容器=${result.container}'
          '${result.versionString.isEmpty ? '' : '，版本串=${result.versionString}'}'
          '${result.rkafOffset >= 0 ? '，RKAF=0x${result.rkafOffset.toRadixString(16)}' : ''}');
      for (final note in result.notes) {
        _write('    $note');
      }
      for (final c in result.candidates) {
        _write('    候选：${c.algorithm.label} @ ${c.offsetHex} '
            '| 换行=${c.trailingNewline} | 置信度=${c.confidence}%');
      }
    } catch (e) {
      _write('[!] 扫描失败：$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _applyPatch() async {
    final script = _selected;
    if (script == null) {
      _write('[!] 先扫描并选中一个候选');
      return;
    }
    if (_password.text.isEmpty) {
      _write('[!] 口令不能为空');
      return;
    }
    final preview = hashPassword(
      password: _password.text,
      algorithm: script.algorithm,
      trailingNewline: script.trailingNewline,
    );
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('确认改写镜像'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SelectableText('目标偏移：${script.offsetHex}'),
            SelectableText('原哈希：${script.storedHash}'),
            SelectableText('新哈希：$preview'),
            const SizedBox(height: 8),
            const Text('会先创建 .bak 备份，再等长覆盖哈希字符串；文件大小不允许变化。'),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('取消')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('写入')),
        ],
      ),
    );
    if (confirmed != true) return;

    setState(() => _busy = true);
    try {
      final result = await patchImage(
        image: File(_imagePath.text.trim()),
        script: script,
        newPassword: _password.text,
      );
      _write('[+] 改写完成 @ ${result.offsetHex}');
      _write('    原：${result.oldHash}');
      _write('    新：${result.newHash}');
      _write('    回读校验：${result.verified ? '通过' : '失败'}');
      _write('    文件大小：${result.fileSize}（与原始一致）');
      _write('    输出：${result.outputPath}');
      if (result.backupPath != null) _write('    备份：${result.backupPath}');
      // 后续校验/上传都应该针对改写后的文件
      _imagePath.text = result.outputPath;
      _write('    已把路径切到改写后的文件，可继续第 4 步计算校验。');
      _step = 3;
    } catch (e) {
      _write('[!] 改写失败：$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _computeChecksums() async {
    final path = _imagePath.text.trim();
    if (path.isEmpty) {
      _write('[!] 先填固件路径');
      return;
    }
    List<int> ends = const [];
    try {
      ends = parseEndPositions(_endPositions.text);
    } on FormatException catch (e) {
      _write('[!] ${e.message}');
      return;
    }
    setState(() => _busy = true);
    try {
      _write('[*] 计算校验（${ends.isEmpty ? '不分段' : '${ends.length} 段'}）…');
      final report = await computeChecksums(File(path), endPositions: ends);
      _checksum = report;
      _step = 4;
      _write('    MD5    = ${report.totalMd5}');
      _write('    SHA1   = ${report.totalSha1}');
      _write('    SHA256 = ${report.totalSha256}');
      for (var i = 0; i < report.segmentMd5.length; i++) {
        _write('    段$i = ${report.segmentMd5[i]}');
      }
      _write('    可直接粘进 YDPen.js 的 segmentMd5：');
      _write('    ${report.segmentJson()}');
    } catch (e) {
      _write('[!] 计算失败：$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  String _buildDir() => '${_imagePath.text.trim()}.build';

  /// 确保热点就绪，并把域名指到本机。返回笔可访问的 IP。
  ///
  /// 全新词典笔没有任何权限可用，唯一入口是网络层：笔连上电脑开的移动热点后，
  /// 电脑就是它的网关兼 DNS；把 iotapi.abupdate.com 指到网关 IP，
  /// 更新请求就会落到本机服务上。
  Future<String?> _prepareNetwork() async {
    if (!await isElevated()) {
      _write('[!] 当前不是管理员：改 hosts / 开热点都会失败。');
      _write('    请关掉本程序，右键「以管理员身份运行」再打开。');
      return null;
    }
    var hs = await detectHotspot();
    if (hs == null) {
      _write('[*] 未检测到移动热点，尝试启动…');
      final err = await startHotspot();
      if (err != null) {
        _write('[!] $err');
        _write('    手动方式：设置 → 网络和 Internet → 移动热点 → 打开');
        return null;
      }
      _hotspotStartedByUs = true;
      for (var i = 0; i < 10 && hs == null; i++) {
        await Future.delayed(const Duration(milliseconds: 800));
        hs = await detectHotspot();
      }
    }
    if (hs == null) {
      _write('[!] 热点已开但没有拿到 IP（期待 192.168.137.x）');
      return null;
    }
    _hotspot = hs;
    final creds = await hotspotCredentials();
    if (creds.ssid != null && creds.ssid!.isNotEmpty && _ssidCtrl.text.isEmpty) {
      _ssidCtrl.text = creds.ssid!;
    }
    if (creds.key != null && creds.key!.isNotEmpty && _passCtrl.text.isEmpty) {
      _passCtrl.text = creds.key!;
    }
    _write('[+] 热点网卡：${hs.adapterName}   网关：${hs.ipv4}');
    if (creds.ssid != null && creds.ssid!.isNotEmpty) {
      _write('    SSID：${creds.ssid}    密码：${creds.key ?? '（到系统设置里看）'}');
    }
    _write('    请让词典笔连上这个 WiFi（全新设备：设置 → 网络 → 选上面的 SSID）');
    try {
      await _hosts.setEntry(hs.ipv4, 'iotapi.abupdate.com');
      _hostsIp = hs.ipv4;
      await _hosts.flushDns();
      _write('[+] hosts：${hs.ipv4} iotapi.abupdate.com（已刷新 DNS）');
    } catch (e) {
      _write('[!] 写 hosts 失败：$e');
      return null;
    }
    return hs.ipv4;
  }

  /// 第一步：抓包。转发真服务器，把原始响应存成 captured.json。
  Future<void> _startCapture() async {
    setState(() => _busy = true);
    try {
      final ip = await _prepareNetwork();
      if (ip == null) return;
      await _server?.stop();
      final fw = await ensureInboundPortRule(80);
      _write(fw.ok ? '[+] ${fw.detail}' : '[!] ${fw.detail}');
      if (!fw.ok) {
        _write('    没放行入站的话，笔的请求会被防火墙静默丢弃，日志里会一片空白');
      }
      final server = OtaProxyServer(
        listenPort: 80,
        captureOnly: true,
        onLog: _write,
        onCapture: (body) async {
          _captureRaw = body;
          final dir = Directory(_buildDir());
          if (!await dir.exists()) await dir.create(recursive: true);
          final f = File('${dir.path}/captured.json');
          await f.writeAsString(body, flush: true);
          _capture = OtaCapture.parse(body);
          _write('[+] 已抓包：${f.path}（${body.length} 字符）');
          _write('    版本 ${_capture!.versionName}｜${_capture!.segmentCount} 段｜'
              '${_capture!.fileSize} 字节｜加密=${_capture!.encrypted}');
          _write('    注意：抓包时已把下载地址拦掉，笔上会显示"更新失败"，这是正常的');
          _write('    2 秒后自动还原 hosts 并停掉服务');
          setState(() {});
          // 抓包目的已达成，立刻还原，避免笔后续检查更新被我们挡住
          await Future.delayed(const Duration(seconds: 2));
          await _restoreHosts();
          await _server?.stop();
          _server = null;
          if (_hotspotStartedByUs) {
            final e2 = await stopHotspot();
            if (e2 == null) {
              _hotspotStartedByUs = false;
              _hotspot = null;
              _write('[+] 热点已自动关闭');
            } else {
              _write('[!] 关闭热点失败（可手动关）：$e2');
            }
          }
          _write('[+] 抓包服务已停止。下一步：点「② 下载全量包」');
          setState(() {});
        },
      );
      await server.start();
      _server = server;
      _step = 0;
      _write('[+] 抓包服务已在 :80 就绪');
      _write('    现在到笔上点「检查更新」');
      _write('    如果笔之前检查过更新，DNS 可能缓存了真实 IP：把笔的 WiFi 关掉再连一次');
      _write('    抓到后会自动保存；笔端下载会被拦掉，不会真的下 1 GB');
    } catch (e) {
      _write('[!] 启动抓包失败：$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  /// 第二步：用抓包里的 deltaUrl 下载全量包。
  Future<void> _downloadFirmware() async {
    final cap = _capture;
    if (cap == null) {
      _write('[!] 还没有抓包，先完成第一步');
      return;
    }
    if (cap.deltaUrl.isEmpty) {
      _write('[!] 抓包里没有 deltaUrl');
      return;
    }
    setState(() => _busy = true);
    try {
      final dir = Directory(_buildDir());
      if (!await dir.exists()) await dir.create(recursive: true);
      final name = cap.deltaUrl.split('/').last;
      final saveTo = '${dir.path}/$name';
      _write('[*] 下载 ${cap.deltaUrl}');
      var lastMb = -1;
      final result = await downloadFirmware(
        url: cap.deltaUrl,
        savePath: saveTo,
        onProgress: (got, total) {
          final mb = got ~/ (32 * 1024 * 1024);
          if (mb != lastMb) {
            lastMb = mb;
            final t = total == null ? '?' : (total / 1048576).toStringAsFixed(0);
            _write('    ${(got / 1048576).toStringAsFixed(0)} / $t MB');
          }
        },
      );
      _write('[+] 下载完成：${result.path}（${result.bytes} 字节，${result.elapsed.inSeconds}s）');
      if (cap.fileSize != 0 && result.bytes != cap.fileSize) {
        _write('[!] 大小与抓包不符：${result.bytes} vs ${cap.fileSize}');
      }
      _imagePath.text = result.path;
      setState(() {});
      _write('    路径已填好，可以「扫描并解析」了');
    } catch (e) {
      _write('[!] 下载失败：$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  /// 阶段 2：生成产物（mod.img + ota_response.json + 报告）。
  Future<void> _generateArtifacts() async {
    final path = _imagePath.text.trim();
    if (path.isEmpty) {
      _write('[!] 先填固件路径');
      return;
    }
    final file = File(path);
    if (!await file.exists()) {
      _write('[!] 文件不存在：$path');
      return;
    }
    final script = _selected;
    if (script == null) {
      _write('[!] 先在第 2 步选中鉴权脚本');
      return;
    }
    if (_password.text.isEmpty) {
      _write('[!] 先在第 3 步填新口令');
      return;
    }
    setState(() => _busy = true);
    try {
      _lanIp ??= await detectLanIp();
      final ip = _hotspot?.ipv4 ?? _lanIp ?? '127.0.0.1';
      _write('[*] 生成中：改写镜像 → 算 21 段校验 → 写响应 JSON');
      final built = await buildArtifacts(
        original: file,
        script: script,
        newPassword: _password.text,
        localIp: ip,
        capturedJsonText: _captureRaw,
        port: 80,
      );
      _artifacts = built;
      _write('[+] 生成完成：${built.dir}');
      _write('    mod.img           ${built.imagePath}');
      _write('    ota_response.json ${built.responsePath}');
      _write('    build_report.json ${built.reportPath}');
      if (built.capturePath != null) {
        _write('    captured.json     ${built.capturePath}');
      }
      _write('    哈希偏移 ${built.hashOffsetHex} → ${built.newHash}');
      _write('    MD5=${built.md5}');
      _write('    SHA256=${built.sha256}');
      _write('    分段 ${built.segmentCount} 段'
          '${built.usedCapture ? '（用抓包边界）' : '（无抓包，按 50MB 兜底）'}');
      _step = 5;
    } catch (e) {
      _write('[!] 生成失败：$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  /// 阶段 3：回灌。用生成好的响应 + mod.img 起服务。
  Future<void> _startServe() async {
    final built = _artifacts;
    if (built == null) {
      _write('[!] 先生成产物');
      return;
    }
    final responseFile = File(built.responsePath);
    if (!await responseFile.exists()) {
      _write('[!] 找不到生成的响应文件：${built.responsePath}');
      return;
    }
    setState(() => _busy = true);
    try {
      final ip = await _prepareNetwork();
      if (ip == null) return;
      final preset = await responseFile.readAsString();
      final fw = await ensureInboundPortRule(80);
      if (!fw.ok) _write('[!] ${fw.detail}');
      await _server?.stop();
      final server = OtaProxyServer(
        listenPort: 80,
        imagePath: built.imagePath,
        fixedResponse: preset,
        onLog: _write,
      );
      await server.start();
      _server = server;
      _step = 5;
      _write('[+] 回灌服务已启动：响应来自 ${built.responsePath}');
      _write('    镜像 http://$ip:80/mod.img（${built.fileSize} 字节）');
      _write('    现在到笔上点「检查更新」，会下载并安装你的固件');
    } catch (e) {
      _write('[!] 启动回灌失败：$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _openBuildDir() async {
    final dir = _buildDir();
    try {
      await Process.run('explorer', [dir]);
    } catch (e) {
      _write('[!] 打开目录失败：$e');
    }
  }

  Future<void> _stopServer() async {
    setState(() => _busy = true);
    try {
      await _server?.stop();
      _server = null;
      await _hosts.removeEntry('iotapi.abupdate.com', ip: _hostsIp);
      _hostsIp = null;
      await _hosts.flushDns();
      _write('[+] 服务已停止，hosts 已还原');
    } catch (e) {
      _write('[!] 停止时出错：$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _adbAuth() async {
    setState(() => _busy = true);
    try {
      final located = await AdbClient.locate();
      if (located == null) {
        _write('[!] 没找到 adb.exe：放到程序目录或加进 PATH');
        return;
      }
      _adb = AdbClient(located);
      _write('[*] adb: $located');
      final devices = await _adb!.devices();
      if (devices.isEmpty) {
        _write('[!] 没有已连接的设备，检查数据线和 ADB 开关');
        return;
      }
      for (final d in devices) {
        _write('    设备 ${d.serial} 状态=${d.state}');
      }
      final target = devices.where((d) => d.state == 'device').toList();
      if (target.isEmpty) {
        _write('[!] 设备不在 device 状态');
        return;
      }
      final serial = target.first.serial;
      if (_password.text.isEmpty) {
        _write('[!] 先在第 4 步填口令');
        return;
      }
      final ok = await _adb!.authenticate(_password.text, serial: serial);
      _write(ok ? '[+] 认证成功' : '[!] 认证失败（口令或换行语义不对）');
      if (ok) {
        final root = await _adb!.hasRoot(serial: serial);
        _write(root ? '[+] 已拿到 root shell' : '[!] 认证过了但不是 root');
        _step = 6;
      }
    } catch (e) {
      _write('[!] adb 执行出错：$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _importCapture() async {
    final path = _jsonPath.text.trim();
    if (path.isEmpty) {
      _write('[!] 先填抓包 JSON 路径');
      return;
    }
    try {
      final text = await File(path).readAsString();
      final cap = OtaCapture.parse(text);
      _capture = cap;
      _endPositions.text = cap.endPositions.join(', ');
      _write('[+] 已导入抓包：${cap.segmentCount} 段，首段 ${cap.firstSegmentSize} 字节，'
          '加密=${cap.encrypted}，版本 ${cap.versionName}');
      final local = _imagePath.text.trim();
      if (local.isNotEmpty && await File(local).exists()) {
        final size = await File(local).length();
        if (cap.fileSize != size) {
          _write('[!] 大小不一致：抓包 ${cap.fileSize} vs 本地 $size，可能不是同一版本');
        } else {
          _write('    大小核对一致（$size）');
        }
      }
      setState(() {});
    } catch (e) {
      _write('[!] 解析抓包失败：$e');
    }
  }

  Widget _buildStep4() {
    final running = _server != null;
    final built = _artifacts;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _sectionHeader('步骤 6', '生成并回灌', subtitle: '软件自己产出 mod.img 与 OTA 响应'),
            const SizedBox(height: 8),
            Text('本机地址：${_hotspot?.ipv4 ?? _lanIp ?? '（第 1 步做完后自动探测）'}'),
            const SizedBox(height: 4),
            const Text('抓包在第 1 步完成；这里做 生成 → 回灌。'),
            const SizedBox(height: 12),
            Wrap(
              spacing: 12,
              runSpacing: 8,
              children: [
                FilledButton.icon(
                  onPressed: _busy ? null : _generateArtifacts,
                  icon: const Icon(Icons.build),
                  label: const Text('② 生成 mod.img + 响应'),
                ),
                FilledButton.icon(
                  onPressed: _busy || _artifacts == null ? null : _startServe,
                  icon: const Icon(Icons.upload),
                  label: const Text('③ 回灌（起服务）'),
                ),
                OutlinedButton.icon(
                  onPressed: _busy || !running ? null : _stopServer,
                  icon: const Icon(Icons.stop),
                  label: const Text('停止并还原 hosts'),
                ),
                TextButton.icon(
                  onPressed: _busy ? null : _openBuildDir,
                  icon: const Icon(Icons.folder_open),
                  label: const Text('打开输出目录'),
                ),
              ],
            ),
            if (_captureRaw != null) ...[
              const SizedBox(height: 8),
              const Text('✓ 已抓到原始响应（captured.json）'),
            ],
            if (built != null) ...[
              const SizedBox(height: 8),
              SelectableText(
                '输出目录：${built.dir}\n'
                'mod.img：${built.imagePath}\n'
                '响应：${built.responsePath}\n'
                '报告：${built.reportPath}\n'
                'MD5：${built.md5}\n'
                'SHA256：${built.sha256}\n'
                '分段：${built.segmentCount} 段${built.usedCapture ? '（用抓包边界）' : '（50MB 兜底）'}',
                style: const TextStyle(fontFamily: 'Consolas', fontFamilyFallback: ['Microsoft YaHei', 'Segoe UI', 'SimSun'], fontSize: 12),
              ),
            ],
            if (running) ...[
              const SizedBox(height: 8),
              Text('服务运行中：http://${_lanIp ?? '<ip>'}:80/',
                  style: const TextStyle(fontFamily: 'Consolas', fontFamilyFallback: ['Microsoft YaHei', 'Segoe UI', 'SimSun'], fontSize: 12)),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildStep5() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _sectionHeader('步骤 7', 'ADB 认证与验证'),
            const SizedBox(height: 8),
            const Text('用第 4 步填的口令执行 adb shell auth，随后验证是否为 root。'),
            const SizedBox(height: 12),
            Wrap(
              spacing: 12,
              runSpacing: 8,
              children: [
                FilledButton.icon(
                  onPressed: _busy ? null : _adbAuth,
                  icon: const Icon(Icons.terminal),
                  label: const Text('执行 adb 认证并验证 root'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final scan = _scan;
    return Scaffold(
      appBar: AppBar(
        title: const Text('词典笔 ADB 口令改写器'),
        actions: [
          IconButton(
            tooltip: '窗口适配屏幕',
            onPressed: () {
              if (!WinWindow.fitToScreen()) _write('[!] 调整窗口失败');
            },
            icon: const Icon(Icons.fit_screen),
          ),
          IconButton(
            tooltip: '缩小界面',
            onPressed: () => WinWindow.zoom(1 / 1.12),
            icon: const Icon(Icons.zoom_out),
          ),
          IconButton(
            tooltip: '放大界面',
            onPressed: () => WinWindow.zoom(1.12),
            icon: const Icon(Icons.zoom_in),
          ),
          IconButton(
            tooltip: '复制日志',
            onPressed: () => Clipboard.setData(ClipboardData(text: _log.toString())),
            icon: const Icon(Icons.copy_all),
          ),
        ],
      ),
      body: Row(
        children: [
          if (MediaQuery.sizeOf(context).width >= 1000) ...[
            SizedBox(width: 300, child: _buildStepRail()),
            const VerticalDivider(width: 1),
          ],
          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildCaptureCard(),
                  const SizedBox(height: 16),
                  _buildStep0(),
                  if (scan != null) ...[
                    const SizedBox(height: 16),
                    _reveal(_buildStep1()),
                    const SizedBox(height: 16),
                    _reveal(_buildStep2()),
                    const SizedBox(height: 16),
                    _reveal(_buildStep3()),
                    const SizedBox(height: 16),
                    _reveal(_buildStep4()),
                    const SizedBox(height: 16),
                    _reveal(_buildStep5()),
                  ],
                  const SizedBox(height: 24),
                  _sectionHeader('日志', '运行日志'),
                  const SizedBox(height: 8),
                  Container(
                    width: double.infinity,
                    height: 260,
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0F172A),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: SingleChildScrollView(
                      child: SelectableText(
                        _log.toString(),
                        style: const TextStyle(
                          fontFamily: 'Consolas', fontFamilyFallback: ['Microsoft YaHei', 'Segoe UI', 'SimSun'],
                          fontSize: 12,
                          color: Color(0xFFCBD5E1),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStepRail() {
    const labels = [
      '1 抓包（热点 + hosts）',
      '2 取得全量镜像',
      '3 解析鉴权脚本',
      '4 设口令改写',
      '5 计算校验',
      '6 生成并回灌',
      '7 ADB 认证',
    ];
    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        for (var i = 0; i < labels.length; i++)
          ListTile(
            dense: true,
            leading: CircleAvatar(
              radius: 14,
              backgroundColor: i <= _step ? const Color(0xFF2F6FEB) : Colors.grey.shade300,
              child: Text('${i + 1}',
                  style: const TextStyle(fontSize: 12, color: Colors.white)),
            ),
            title: Text(labels[i],
                style: TextStyle(
                  fontSize: 13,
                  color: i <= _step ? Colors.black87 : Colors.black45,
                )),
          ),
        if (_busy) const Padding(
          padding: EdgeInsets.all(20),
          child: LinearProgressIndicator(),
        ),
      ],
    );
  }

  /// 修改热点的 SSID / 密码（WinRT ConfigureAccessPointAsync）。
  Future<void> _applyHotspot() async {
    setState(() => _busy = true);
    try {
      final err = await configureHotspot(
        ssid: _ssidCtrl.text,
        passphrase: _passCtrl.text,
      );
      if (err != null) {
        _write('[!] 修改热点失败：$err');
        return;
      }
      _write('[+] 热点已更新：SSID ${_ssidCtrl.text.trim()}');
      final creds = await hotspotCredentials();
      if (creds.ssid != null) _ssidCtrl.text = creds.ssid!;
      if (creds.key != null) _passCtrl.text = creds.key!;
      final hs = await detectHotspot();
      if (hs != null) {
        _hotspot = hs;
        _write('    网关 ${hs.ipv4}');
      }
      setState(() {});
    } catch (e) {
      _write('[!] 修改热点失败：$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _checkStaleHosts());
  }

  /// 启动时检查上次抓包是否留下 hosts 劫持。
  /// 只认 192.168.137.x 这种热点网段——那是本工具写的；
  /// 其它 IP 一律不动，避免误删用户自己的条目。
  Future<void> _checkStaleHosts() async {
    try {
      final cur = await _hosts.currentEntry('iotapi.abupdate.com');
      if (cur == null) return;
      if (!cur.startsWith('192.168.137.')) {
        _write('[i] hosts 里有 iotapi.abupdate.com → $cur，不是本工具写入的，保持不动');
        return;
      }
      _write('[!] 检测到 hosts 残留劫持：$cur iotapi.abupdate.com');
      _write('    这会让词典笔一直获取不到更新，正在还原（只删这一行）…');
      _hostsIp = cur;
      await _restoreHosts();
    } catch (e) {
      _write('[!] 检查 hosts 失败：$e');
    }
  }

  /// 还原 hosts：只精确删除我们写的那一行，其它内容一个字节不改。
  Future<void> _restoreHosts() async {
    try {
      final ip = _hostsIp ?? _hotspot?.ipv4;
      final removed = await _hosts.removeEntry('iotapi.abupdate.com', ip: ip);
      if (removed) {
        await _hosts.flushDns();
        _write('[+] hosts 已还原（仅删除本工具写入的那一行，其余内容未动）');
      } else {
        _write('[+] hosts 里没有本工具的条目，无需改动');
      }
      _hostsIp = null;
    } catch (e) {
      _write('[!] 还原 hosts 失败（需管理员身份运行）：$e');
    }
  }

  /// 手动关闭移动热点。
  Future<void> _stopHotspot() async {
    setState(() => _busy = true);
    try {
      final err = await stopHotspot();
      if (err != null) {
        _write('[!] $err');
        return;
      }
      _hotspot = null;
      _hotspotStartedByUs = false;
      _write('[+] 热点已关闭');
      setState(() {});
    } catch (e) {
      _write('[!] 关闭热点失败：$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  /// 卡片出现/消失时的过渡（高度动画 + 淡入），避免内容突然跳出来。
  Widget _reveal(Widget child) => AnimatedSize(
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeOutCubic,
        alignment: Alignment.topCenter,
        child: child,
      );

  /// 统一的卡片标题：左侧小步骤徽标 + 标题 + 可选说明，字重一致。
  Widget _sectionHeader(String step, String title, {String? subtitle}) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: const Color(0xFFEFF6FF),
                borderRadius: BorderRadius.circular(6),
              ),
              child: Text(
                step,
                style: const TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: Color(0xFF2563EB),
                ),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                title,
                style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
              ),
            ),
          ],
        ),
        if (subtitle != null && subtitle.isNotEmpty) ...[
          const SizedBox(height: 6),
          Text(
            subtitle,
            style: const TextStyle(fontSize: 12, height: 1.5, color: Color(0xFF6B7280)),
          ),
        ],
      ],
    );
  }

  Widget _buildCaptureCard() {
    final capture = _capture;
    final running = _server != null;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _sectionHeader('步骤 1', '抓取更新请求', subtitle: '不需要 ADB，全新设备可用'),
            const SizedBox(height: 8),
            const Text(
              '流程：本机开移动热点 → 词典笔连这个热点 → 把 iotapi.abupdate.com 指到本机 → '
              '笔上点「检查更新」→ 请求落到本机，转发真服务器后把响应存下来。',
              style: TextStyle(fontSize: 12),
            ),
            const SizedBox(height: 4),
            const Text(
              '⚠ 抓包期间下载会被故意拦掉，笔上会显示"更新失败"，这是正常的；'
              '抓到后会自动还原 hosts。若中途退出，程序下次启动也会自动清理。',
              style: TextStyle(fontSize: 12, color: Color(0xFFB45309)),
            ),
            const SizedBox(height: 8),
            Text('热点：${_hotspot == null ? '（未探测）' : '${_hotspot!.adapterName}  ${_hotspot!.ipv4}'}'),
            const SizedBox(height: 8),
            Theme(
              data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
              child: ExpansionTile(
                tilePadding: EdgeInsets.zero,
                childrenPadding: const EdgeInsets.only(top: 4, bottom: 8),
                title: const Text('热点设置（SSID / 密码）',
                    style: TextStyle(fontSize: 13, fontWeight: FontWeight.w500)),
                subtitle: const Text('改完点应用，笔需要重新连接新名称',
                    style: TextStyle(fontSize: 11)),
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _ssidCtrl,
                          decoration: const InputDecoration(labelText: '热点名称 SSID'),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: TextField(
                          controller: _passCtrl,
                          decoration: const InputDecoration(labelText: '热点密码（≥8 位）'),
                        ),
                      ),
                      const SizedBox(width: 8),
                      FilledButton.tonal(
                        onPressed: _busy ? null : _applyHotspot,
                        child: const Text('应用'),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            if (capture != null)
              Text('已抓到：版本 ${capture.versionName}｜${capture.segmentCount} 段｜'
                  '${capture.fileSize} 字节｜加密=${capture.encrypted}'),
            const SizedBox(height: 12),
            Row(
              children: [
                FilledButton.icon(
                  onPressed: _busy ? null : _startCapture,
                  icon: const Icon(Icons.wifi_tethering, size: 18),
                  label: const Text('开始抓包'),
                ),
                const SizedBox(width: 8),
                FilledButton.tonalIcon(
                  onPressed: _busy || capture == null ? null : _downloadFirmware,
                  icon: const Icon(Icons.download, size: 18),
                  label: const Text('下载全量包'),
                ),
                const Spacer(),
                PopupMenuButton<String>(
                  tooltip: '更多操作',
                  onSelected: (v) {
                    switch (v) {
                      case 'restore':
                        _restoreHosts();
                      case 'hotspot':
                        _stopHotspot();
                      case 'stop':
                        _stopServer();
                    }
                  },
                  itemBuilder: (_) => const [
                    PopupMenuItem(value: 'restore', child: Text('还原 hosts（恢复真实更新）')),
                    PopupMenuItem(value: 'hotspot', child: Text('关闭移动热点')),
                    PopupMenuItem(value: 'stop', child: Text('停止服务并还原 hosts')),
                  ],
                ),
              ],
            ),
            if (running) ...[
              const SizedBox(height: 8),
              Text('服务运行中，等待笔发起检查更新…（hosts 已指向 ${_hotspot?.ipv4 ?? ''}）',
                  style: const TextStyle(fontSize: 12)),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildStep0() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _sectionHeader('步骤 2', '载入镜像（下载后自动填入，也可手动选择）'),
            const SizedBox(height: 8),
            TextField(
              controller: _imagePath,
              decoration: const InputDecoration(
                labelText: '固件完整路径（.img）',
                hintText: r'E:\path\to\firmware.img',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                FilledButton.icon(
                  onPressed: _busy ? null : _scanImage,
                  icon: const Icon(Icons.search),
                  label: const Text('扫描并解析鉴权脚本'),
                ),
                const SizedBox(width: 12),
                OutlinedButton.icon(
                  onPressed: () => setState(() {
                    _scan = null;
                    _selected = null;
                    _checksum = null;
                    _step = 0;
                  }),
                  icon: const Icon(Icons.restart_alt),
                  label: const Text('重置'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStep1() {
    final scan = _scan!;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _sectionHeader('步骤 3', '核对鉴权脚本'),
            const SizedBox(height: 8),
            Text('容器：${scan.container}    文件大小：${scan.fileSize} 字节'
                '${scan.versionString.isEmpty ? '' : '    版本串：${scan.versionString}'}'),
            const SizedBox(height: 12),
            if (scan.candidates.isEmpty)
              const Text('未解析到鉴权脚本，见日志。')
            else
              DropdownButtonFormField<AuthScript>(
                value: _selected,
                decoration: const InputDecoration(
                  labelText: '选择候选（不同候选对应不同脚本位置）',
                  border: OutlineInputBorder(),
                ),
                items: [
                  for (final c in scan.candidates)
                    DropdownMenuItem(
                      value: c,
                      child: Text('${c.algorithm.label} @ ${c.offsetHex} · 置信度 ${c.confidence}%'),
                    ),
                ],
                onChanged: (v) => setState(() => _selected = v),
              ),
            if (_selected != null) ...[
              const SizedBox(height: 12),
              Wrap(spacing: 16, runSpacing: 8, children: [
                Chip(label: Text('算法 ${_selected!.algorithm.label}')),
                Chip(label: Text(_selected!.trailingNewline ? '带换行符' : '无换行符')),
                Chip(label: Text(_selected!.dashSuffix ? '比较串含 "  -"' : '比较串无尾巴')),
                if (_selected!.prompt.isNotEmpty) Chip(label: Text('提示语 ${_selected!.prompt}')),
              ]),
              const SizedBox(height: 12),
              const Text('脚本原文'),
              const SizedBox(height: 6),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                constraints: const BoxConstraints(maxHeight: 260),
                decoration: BoxDecoration(
                  color: const Color(0xFFF1F5F9),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: SingleChildScrollView(
                  child: SelectableText(
                    _selected!.scriptText.trim(),
                    style: const TextStyle(fontFamily: 'Consolas', fontFamilyFallback: ['Microsoft YaHei', 'Segoe UI', 'SimSun'], fontSize: 12),
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildStep2() {
    final script = _selected;
    String preview = '';
    if (script != null && _password.text.isNotEmpty) {
      preview = hashPassword(
        password: _password.text,
        algorithm: script.algorithm,
        trailingNewline: script.trailingNewline,
      );
    }
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _sectionHeader('步骤 4', '设定新口令并改写'),
            const SizedBox(height: 8),
            TextField(
              controller: _password,
              obscureText: false,
              onChanged: (_) => setState(() {}),
              decoration: const InputDecoration(
                labelText: '新 ADB 口令（明文，会换算成脚本要求的哈希）',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            if (preview.isNotEmpty)
              SelectableText('将写入哈希：$preview',
                  style: const TextStyle(fontFamily: 'Consolas', fontFamilyFallback: ['Microsoft YaHei', 'Segoe UI', 'SimSun'], fontSize: 12)),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: _busy || script == null ? null : _applyPatch,
              icon: const Icon(Icons.edit),
              label: const Text('写入镜像（自动备份 + 回读校验）'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStep3() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _sectionHeader('步骤 5', '计算校验'),
            const SizedBox(height: 8),
            const Text('把抓包响应里 segmentMd5 的每个 endpos 按顺序填进来（逗号或换行分隔）。'
                '留空则只算整包 MD5/SHA1/SHA256。'),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _jsonPath,
                    decoration: const InputDecoration(
                      labelText: '（推荐）抓包得到的 checkVersion 响应 JSON',
                      hintText: r'E:\path\to\ota_full.json',
                      border: OutlineInputBorder(),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                FilledButton.icon(
                  onPressed: _busy ? null : _importCapture,
                  icon: const Icon(Icons.file_open),
                  label: const Text('导入并填充 endpos'),
                ),
              ],
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _endPositions,
              maxLines: 3,
              decoration: const InputDecoration(
                labelText: 'endpos 列表',
                hintText: '104857600, 209715200, 314572800',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: _busy ? null : _computeChecksums,
              icon: const Icon(Icons.functions),
              label: const Text('计算'),
            ),
            if (_checksum != null) ...[
              const SizedBox(height: 12),
              SelectableText('MD5    ${_checksum!.totalMd5}',
                  style: const TextStyle(fontFamily: 'Consolas', fontFamilyFallback: ['Microsoft YaHei', 'Segoe UI', 'SimSun'], fontSize: 12)),
              SelectableText('SHA1   ${_checksum!.totalSha1}',
                  style: const TextStyle(fontFamily: 'Consolas', fontFamilyFallback: ['Microsoft YaHei', 'Segoe UI', 'SimSun'], fontSize: 12)),
              SelectableText('SHA256 ${_checksum!.totalSha256}',
                  style: const TextStyle(fontFamily: 'Consolas', fontFamilyFallback: ['Microsoft YaHei', 'Segoe UI', 'SimSun'], fontSize: 12)),
            ],
          ],
        ),
      ),
    );
  }
}
