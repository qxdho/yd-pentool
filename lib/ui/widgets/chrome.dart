import 'package:flutter/material.dart';

import '../theme.dart';

/// 三阶段进度条，可点击跳转。
class PhaseStepper extends StatelessWidget {
  const PhaseStepper({
    super.key,
    required this.current,
    required this.onSelect,
    this.titles = const ['准备固件', '改写并校验', '回灌验证'],
  });

  final int current;
  final ValueChanged<int> onSelect;
  final List<String> titles;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.fromLTRB(16, 4, 16, 14),
      color: p.surface,
      child: Row(
        children: [
          for (var i = 0; i < titles.length; i++) ...[
            if (i > 0)
              Expanded(
                child: Container(
                  height: 2,
                  margin: const EdgeInsets.symmetric(horizontal: 8),
                  color: i <= current ? scheme.primary : p.border,
                ),
              ),
            InkWell(
              onTap: () => onSelect(i),
              borderRadius: BorderRadius.circular(999),
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    CircleAvatar(
                      radius: 12,
                      backgroundColor:
                          i <= current ? scheme.primary : p.surfaceAlt,
                      child: Text(
                        '${i + 1}',
                        style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                          color: i <= current ? scheme.onPrimary : p.textMuted,
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Text(
                      titles[i],
                      style: TextStyle(
                        fontSize: 13,
                        fontWeight:
                            i == current ? FontWeight.w600 : FontWeight.w400,
                        color: i <= current ? p.textPrimary : p.textMuted,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

/// 顶部状态条：左侧一排状态胶囊，右侧日志入口。
class AppStatusBar extends StatelessWidget {
  const AppStatusBar({
    super.key,
    required this.chips,
    required this.onOpenLog,
  });

  final List<Widget> chips;
  final VoidCallback onOpenLog;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      color: p.surface,
      child: Row(
        children: [
          Expanded(
            child: Wrap(
              spacing: 8,
              runSpacing: 8,
              children: chips,
            ),
          ),
          const SizedBox(width: 12),
          TextButton.icon(
            onPressed: onOpenLog,
            icon: const Icon(Icons.terminal, size: 18),
            label: const Text('日志'),
          ),
        ],
      ),
    );
  }
}

/// 右侧日志抽屉：深色底、等宽字体。
class LogDrawer extends StatelessWidget {
  const LogDrawer({
    super.key,
    required this.text,
    required this.onCopy,
    this.width = 620,
  });

  final String text;
  final VoidCallback onCopy;
  final double width;

  bool get hasError => text.contains('[!]');

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Drawer(
      width: width,
      backgroundColor: p.logBg,
      child: SafeArea(
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 8, 8),
              child: Row(
                children: [
                  Icon(Icons.terminal, size: 18, color: p.logText),
                  const SizedBox(width: 8),
                  Text('运行日志',
                      style: TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                          color: p.logText)),
                  const Spacer(),
                  if (hasError)
                    Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: Text('有错误',
                          style:
                              TextStyle(fontSize: 11, color: p.danger)),
                    ),
                  IconButton(
                    tooltip: '复制全部',
                    onPressed: onCopy,
                    icon: Icon(Icons.copy_all, size: 18, color: p.logText),
                  ),
                  IconButton(
                    tooltip: '关闭',
                    onPressed: () => Navigator.of(context).pop(),
                    icon: Icon(Icons.close, size: 18, color: p.logText),
                  ),
                ],
              ),
            ),
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                child: SelectableText(
                  text,
                  style: TextStyle(
                    fontFamily: 'Consolas',
                    fontFamilyFallback: const [
                      'Microsoft YaHei',
                      'Segoe UI',
                      'SimSun'
                    ],
                    fontSize: 12,
                    height: 1.5,
                    color: p.logText,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// 顶栏的日志按钮，有错误时右上角显示红点。
class LogButton extends StatelessWidget {
  const LogButton({super.key, required this.hasError, required this.onPressed});

  final bool hasError;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    return Stack(
      alignment: Alignment.center,
      children: [
        IconButton(
          tooltip: '运行日志',
          onPressed: onPressed,
          icon: const Icon(Icons.terminal),
        ),
        if (hasError)
          Positioned(
            right: 8,
            top: 8,
            child: Container(
              width: 8,
              height: 8,
              decoration: BoxDecoration(
                color: context.palette.danger,
                shape: BoxShape.circle,
              ),
            ),
          ),
      ],
    );
  }
}

/// 错误横幅：只显示最后一条错误。
class ErrorBanner extends StatelessWidget {
  const ErrorBanner({
    super.key,
    required this.message,
    required this.onOpenLog,
    required this.onDismiss,
  });

  final String message;
  final VoidCallback onOpenLog;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Container(
      width: double.infinity,
      color: p.danger.withOpacity(0.08),
      padding: const EdgeInsets.fromLTRB(16, 6, 8, 6),
      child: Row(
        children: [
          Icon(Icons.error_outline, size: 16, color: p.danger),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              message,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(fontSize: 12, color: p.danger),
            ),
          ),
          TextButton(onPressed: onOpenLog, child: const Text('查看日志')),
          IconButton(
            tooltip: '忽略',
            onPressed: onDismiss,
            icon: const Icon(Icons.close, size: 16),
          ),
        ],
      ),
    );
  }
}
