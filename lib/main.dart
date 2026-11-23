import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'core/auth_script.dart';
import 'core/checksum.dart';
import 'core/firmware_scanner.dart';
import 'core/hash_util.dart';
import 'core/image_patcher.dart';

void main() => runApp(const YdPenToolApp());

class YdPenToolApp extends StatelessWidget {
  const YdPenToolApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '词典笔 ADB 口令改写器',
      theme: ThemeData(colorSchemeSeed: const Color(0xFF2F6FEB), useMaterial3: true),
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
  final _log = StringBuffer();

  ScanResult? _scan;
  AuthScript? _selected;
  ChecksumReport? _checksum;
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
      _step = 1;
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
      _step = 2;
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
      _step = 3;
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

  @override
  Widget build(BuildContext context) {
    final scan = _scan;
    return Scaffold(
      appBar: AppBar(
        title: const Text('词典笔 ADB 口令改写器'),
        actions: [
          IconButton(
            tooltip: '复制日志',
            onPressed: () => Clipboard.setData(ClipboardData(text: _log.toString())),
            icon: const Icon(Icons.copy_all),
          ),
        ],
      ),
      body: Row(
        children: [
          SizedBox(width: 300, child: _buildStepRail()),
          const VerticalDivider(width: 1),
          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildStep0(),
                  const SizedBox(height: 16),
                  if (scan != null) _buildStep1(),
                  const SizedBox(height: 16),
                  if (scan != null) _buildStep2(),
                  const SizedBox(height: 16),
                  if (scan != null) _buildStep3(),
                  const SizedBox(height: 24),
                  const Text('运行日志', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(height: 8),
                  Container(
                    width: double.infinity,
                    height: 260,
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: const Color(0xFF12161C),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: SingleChildScrollView(
                      child: SelectableText(
                        _log.toString(),
                        style: const TextStyle(
                          fontFamily: 'Consolas',
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
      '1 载入并扫描固件',
      '2 核对鉴权脚本',
      '3 设定口令并改写',
      '4 计算 OTA 校验',
      '5 本地服务器（下一步）',
      '6 认证与持久化（下一步）',
    ];
    return ListView(
      padding: const EdgeInsets.all(16),
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
          padding: EdgeInsets.all(16),
          child: LinearProgressIndicator(),
        ),
      ],
    );
  }

  Widget _buildStep0() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('步骤 1 载入固件', style: TextStyle(fontWeight: FontWeight.bold)),
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
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('步骤 2 核对鉴权脚本', style: TextStyle(fontWeight: FontWeight.bold)),
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
                  borderRadius: BorderRadius.circular(8),
                ),
                child: SingleChildScrollView(
                  child: SelectableText(
                    _selected!.scriptText.trim(),
                    style: const TextStyle(fontFamily: 'Consolas', fontSize: 12),
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
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('步骤 3 设定新口令并改写', style: TextStyle(fontWeight: FontWeight.bold)),
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
                  style: const TextStyle(fontFamily: 'Consolas', fontSize: 12)),
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
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('步骤 4 计算 OTA 校验', style: TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            const Text('把抓包响应里 segmentMd5 的每个 endpos 按顺序填进来（逗号或换行分隔）。'
                '留空则只算整包 MD5/SHA1/SHA256。'),
            const SizedBox(height: 8),
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
                  style: const TextStyle(fontFamily: 'Consolas', fontSize: 12)),
              SelectableText('SHA1   ${_checksum!.totalSha1}',
                  style: const TextStyle(fontFamily: 'Consolas', fontSize: 12)),
              SelectableText('SHA256 ${_checksum!.totalSha256}',
                  style: const TextStyle(fontFamily: 'Consolas', fontSize: 12)),
            ],
          ],
        ),
      ),
    );
  }
}
