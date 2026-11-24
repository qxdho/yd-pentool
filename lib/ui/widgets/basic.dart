import 'package:flutter/material.dart';

import '../theme.dart';

/// 统一的卡片标题：左侧小步骤徽标 + 标题 + 可选说明。
class SectionHeader extends StatelessWidget {
  const SectionHeader({
    super.key,
    required this.step,
    required this.title,
    this.subtitle,
  });

  final String step;
  final String title;
  final String? subtitle;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: p.chipBg,
                borderRadius: BorderRadius.circular(6),
              ),
              child: Text(
                step,
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: p.chipText,
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
        if (subtitle != null && subtitle!.isNotEmpty) ...[
          const SizedBox(height: 6),
          Text(
            subtitle!,
            style: TextStyle(fontSize: 12, height: 1.5, color: p.textMuted),
          ),
        ],
      ],
    );
  }
}

/// 空状态 / 提示卡片。
class HintCard extends StatelessWidget {
  const HintCard({super.key, required this.title, required this.body});

  final String title;
  final String body;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Row(
          children: [
            Icon(Icons.info_outline, color: p.textMuted),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title,
                      style: const TextStyle(
                          fontSize: 14, fontWeight: FontWeight.w600)),
                  const SizedBox(height: 4),
                  Text(body,
                      style:
                          TextStyle(fontSize: 12, height: 1.5, color: p.textMuted)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// 底部避嫌说明：始终可见，但只占一行。
class FooterNote extends StatelessWidget {
  const FooterNote({super.key, this.text = '本工具仅供个人学习与设备测试使用 · 请自行承担风险 · 与厂商无关'});

  final String text;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Text(
        text,
        style: TextStyle(fontSize: 11, color: context.palette.textMuted),
      ),
    );
  }
}

/// 顶部就绪状态胶囊：绿=就绪，黄=待处理。
class StatusChip extends StatelessWidget {
  const StatusChip({
    super.key,
    required this.icon,
    required this.label,
    required this.ok,
    this.onTap,
  });

  final IconData icon;
  final String label;
  final bool ok;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final color = ok ? p.success : p.warning;
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(999),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
          color: color.withOpacity(0.10),
          borderRadius: BorderRadius.circular(999),
          border: Border.all(color: color.withOpacity(0.35)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 14, color: color),
            const SizedBox(width: 6),
            Text(label,
                style: TextStyle(
                    fontSize: 12, color: color, fontWeight: FontWeight.w500)),
          ],
        ),
      ),
    );
  }
}
