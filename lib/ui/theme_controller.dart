import 'package:flutter/material.dart';

/// 全局主题模式。改成 ValueNotifier 是为了让顶栏按钮和 MaterialApp 都能监听，
/// 不用把状态一路透传。
final ValueNotifier<ThemeMode> themeModeNotifier =
    ValueNotifier<ThemeMode>(ThemeMode.system);

/// 在 亮 → 暗 → 跟随系统 之间循环。
void cycleThemeMode() {
  final cur = themeModeNotifier.value;
  themeModeNotifier.value = switch (cur) {
    ThemeMode.light => ThemeMode.dark,
    ThemeMode.dark => ThemeMode.system,
    ThemeMode.system => ThemeMode.light,
  };
}

String themeModeLabel(ThemeMode mode) => switch (mode) {
      ThemeMode.light => '亮色',
      ThemeMode.dark => '暗色',
      ThemeMode.system => '跟随系统',
    };

IconData themeModeIcon(ThemeMode mode) => switch (mode) {
      ThemeMode.light => Icons.light_mode_outlined,
      ThemeMode.dark => Icons.dark_mode_outlined,
      ThemeMode.system => Icons.brightness_auto_outlined,
    };
