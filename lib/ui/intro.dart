import 'package:flutter/material.dart';

import 'theme.dart';
import 'theme_controller.dart';

const String _kIntroSeenKey = 'introSeen';

/// 是否还没有看过首次引导。
Future<bool> shouldShowIntro() async {
  final data = await readUiState();
  return data[_kIntroSeenKey] != true;
}

Future<void> markIntroSeen() => writeUiState({_kIntroSeenKey: true});

/// 首次启动的引导：三句话说明这个工具怎么用，可勾选不再提示。
class IntroDialog extends StatefulWidget {
  const IntroDialog({super.key});

  @override
  State<IntroDialog> createState() => _IntroDialogState();
}

class _IntroDialogState extends State<IntroDialog> {
  bool _dontShowAgain = true;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Dialog(
      insetPadding: const EdgeInsets.symmetric(horizontal: 40, vertical: 32),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 520),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 24, 24, 12),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('三步就能拿到 ADB 权限',
                  style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
              const SizedBox(height: 6),
              Text('不用懂固件结构，按顺序点下去就行。',
                  style: TextStyle(fontSize: 12, color: p.textMuted)),
              const SizedBox(height: 18),
              _step(context, 1, '准备固件',
                  '用抓包导入更新信息，或直接选一个已有的固件镜像。'),
              const SizedBox(height: 12),
              _step(context, 2, '改写并校验',
                  '填入你想用的新口令，程序自动定位脚本、等长替换哈希并重算分段校验。'),
              const SizedBox(height: 12),
              _step(context, 3, '回灌验证',
                  '本机变成更新服务器，让设备自己更新；装完用新口令连 ADB 即可。'),
              const SizedBox(height: 18),
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: p.warning.withOpacity(0.08),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: p.warning.withOpacity(0.3)),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(Icons.warning_amber_rounded, size: 15, color: p.warning),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        '仅供个人学习与设备测试使用。刷机有风险，请自行承担后果。',
                        style: TextStyle(fontSize: 12, height: 1.5, color: p.warning),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Checkbox(
                    value: _dontShowAgain,
                    onChanged: (v) => setState(() => _dontShowAgain = v ?? false),
                    visualDensity: VisualDensity.compact,
                  ),
                  Text('不再提示',
                      style: TextStyle(fontSize: 12, color: p.textMuted)),
                  const Spacer(),
                  TextButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: const Text('跳过'),
                  ),
                  const SizedBox(width: 8),
                  FilledButton(
                    onPressed: () async {
                      if (_dontShowAgain) await markIntroSeen();
                      if (context.mounted) Navigator.of(context).pop();
                    },
                    child: const Text('开始使用'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _step(BuildContext context, int index, String title, String body) {
    final p = context.palette;
    final scheme = Theme.of(context).colorScheme;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        CircleAvatar(
          radius: 13,
          backgroundColor: scheme.primary,
          child: Text('$index',
              style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  color: scheme.onPrimary)),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title,
                  style: const TextStyle(
                      fontSize: 13, fontWeight: FontWeight.w600)),
              const SizedBox(height: 2),
              Text(body,
                  style: TextStyle(fontSize: 12, height: 1.5, color: p.textMuted)),
            ],
          ),
        ),
      ],
    );
  }
}
