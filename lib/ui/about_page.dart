import 'package:flutter/material.dart';

import 'theme.dart';

const String kAppName = '词典笔 ADB 口令改写器';
const String kAppVersion = '1.0.0';
const String kDeveloper = '谦虚の海鸥';

/// 已验证机型（与 profiles/models.json 保持同步）。
const List<({String model, String note})> kVerifiedDevices = [
  (model: 'A7 Pro', note: 'RV1106 / Y09 · 本机实测通过'),
  (model: 'S7 Pro', note: '测试者实测通过'),
  (model: 'X7 Pro', note: '待验证（已收集到 MTP 备用方案）'),
];

const List<({String name, String url})> kCredits = [
  (name: '86lbs/ydpen-adb-unlock', url: 'https://github.com/86lbs/ydpen-adb-unlock'),
  (name: 'langningchen/paper', url: 'https://github.com/langningchen/paper'),
  (name: 'xtawa/youdao-dict-crack-mtp', url: 'https://github.com/xtawa/youdao-dict-crack-mtp'),
];

/// 关于 / 免责声明。
///
/// 设计意图：把所有"责任边界"放在一个用户能主动打开的页面里，
/// 主界面不打扰，但启动后可在顶栏一键查看。
class AboutPage extends StatelessWidget {
  const AboutPage({super.key});

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Dialog(
      insetPadding: const EdgeInsets.symmetric(horizontal: 40, vertical: 32),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 560, maxHeight: 660),
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(24, 24, 24, 16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // 标题区：头像 + 名称 + 版本
              Row(
                children: [
                  _avatar(context),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(kAppName,
                            style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
                        const SizedBox(height: 4),
                        Text('版本 $kAppVersion',
                            style: TextStyle(fontSize: 12, color: p.textMuted)),
                        const SizedBox(height: 6),
                        Row(
                          children: [
                            Icon(Icons.person_outline, size: 14, color: p.textMuted),
                            const SizedBox(width: 4),
                            Text('开发者：$kDeveloper',
                                style: TextStyle(fontSize: 12, color: p.textMuted)),
                          ],
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 20),

              // 免责声明（最显眼）
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: p.warning.withOpacity(0.08),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: p.warning.withOpacity(0.35)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.warning_amber_rounded, size: 16, color: p.warning),
                        const SizedBox(width: 6),
                        Text('免责声明',
                            style: TextStyle(
                                fontSize: 13,
                                fontWeight: FontWeight.w600,
                                color: p.warning)),
                      ],
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      '本软件仅供个人学习、研究与设备测试使用，严禁用于任何商业用途、'
                      '批量刷机、二手设备改装或其它违法违规场景。',
                      style: TextStyle(fontSize: 12, height: 1.6),
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      '使用本软件即表示你已充分理解并自行承担全部风险：'
                      '包括但不限于设备变砖、数据丢失、保修失效、以及违反厂商服务条款的后果。'
                      '作者不对任何直接或间接损失负责，也不提供任何形式的担保。',
                      style: TextStyle(fontSize: 12, height: 1.6),
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      '请仅在你本人拥有或已获得明确授权的设备上使用。'
                      '本软件与有道 / 网易及其关联公司没有任何关系，也未获得其授权或认可。',
                      style: TextStyle(fontSize: 12, height: 1.6),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              _sectionTitle(context, '已验证机型'),
              const SizedBox(height: 8),
              ...kVerifiedDevices.map((d) => Padding(
                    padding: const EdgeInsets.only(bottom: 6),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(
                          d.note.contains('待验证')
                              ? Icons.schedule
                              : Icons.check_circle_outline,
                          size: 15,
                          color: d.note.contains('待验证') ? p.textMuted : p.success,
                        ),
                        const SizedBox(width: 8),
                        Text(d.model,
                            style: const TextStyle(
                                fontSize: 13, fontWeight: FontWeight.w500)),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(d.note,
                              style: TextStyle(fontSize: 12, color: p.textMuted)),
                        ),
                      ],
                    ),
                  )),
              const SizedBox(height: 16),

              _sectionTitle(context, '工作原理'),
              const SizedBox(height: 8),
              Text(
                '从固件 rootfs 中读出鉴权脚本，把其中的密码哈希等长替换为新口令的哈希，'
                '再按 OTA 协议重算分段校验，由本机伪造更新服务器让设备自行安装。'
                '原始固件不会被修改，全程只写副本。',
                style: TextStyle(fontSize: 12, height: 1.6, color: p.textMuted),
              ),
              const SizedBox(height: 16),

              _sectionTitle(context, '参考项目'),
              const SizedBox(height: 8),
              ...kCredits.map((c) => Padding(
                    padding: const EdgeInsets.only(bottom: 6),
                    child: Row(
                      children: [
                        Icon(Icons.link, size: 14, color: p.textMuted),
                        const SizedBox(width: 8),
                        Expanded(
                          child: SelectableText(
                            '${c.name}\n${c.url}',
                            style: TextStyle(fontSize: 12, height: 1.5, color: p.textMuted),
                          ),
                        ),
                      ],
                    ),
                  )),
              const SizedBox(height: 12),
              Text(
                '感谢社区公开的文档与工具，本项目在这些工作的基础上做了自动化整合。',
                style: TextStyle(fontSize: 12, color: p.textMuted),
              ),
              const SizedBox(height: 20),

              Align(
                alignment: Alignment.centerRight,
                child: FilledButton.tonal(
                  onPressed: () => Navigator.of(context).pop(),
                  child: const Text('我知道了'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _avatar(BuildContext context) {
    final p = context.palette;
    return Container(
      width: 88,
      height: 88,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        border: Border.all(color: p.border, width: 2),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.08),
            blurRadius: 12,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: ClipOval(
        child: Image.asset(
          'assets/avatar.jpg',
          width: 88,
          height: 88,
          fit: BoxFit.cover,
          errorBuilder: (_, __, ___) => Container(
            color: p.surfaceAlt,
            alignment: Alignment.center,
            child: Icon(Icons.pets, color: p.textMuted),
          ),
        ),
      ),
    );
  }

  Widget _sectionTitle(BuildContext context, String text) => Text(
        text,
        style: TextStyle(
          fontSize: 13,
          fontWeight: FontWeight.w600,
          color: context.palette.textPrimary,
        ),
      );
}

/// 打开关于页。
Future<void> showAbout(BuildContext context) {
  return showDialog<void>(
    context: context,
    barrierDismissible: true,
    builder: (_) => const AboutPage(),
  );
}
