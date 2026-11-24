import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

/// 全局主题模式。改成 ValueNotifier 是为了让顶栏按钮和 MaterialApp 都能监听，
/// 不用把状态一路透传。
final ValueNotifier<ThemeMode> themeModeNotifier =
    ValueNotifier<ThemeMode>(ThemeMode.system);

String get _statePath {
  final base = Platform.environment['LOCALAPPDATA'] ?? '.';
  return '$base\\yd-pentool\\ui.json';
}

/// 启动时读取上次的主题选择（找不到就用"跟随系统"）。
Future<void> loadThemeMode() async {
  try {
    final f = File(_statePath);
    if (!await f.exists()) return;
    final data = jsonDecode(await f.readAsString());
    if (data is Map && data['themeMode'] is String) {
      themeModeNotifier.value = switch (data['themeMode'] as String) {
        'light' => ThemeMode.light,
        'dark' => ThemeMode.dark,
        _ => ThemeMode.system,
      };
    }
  } catch (_) {
    // 读不到就保持默认，不打扰用户
  }
}

Future<void> _saveThemeMode() async {
  try {
    final f = File(_statePath);
    await f.parent.create(recursive: true);
    await f.writeAsString(jsonEncode({'themeMode': themeModeNotifier.value.name}));
  } catch (_) {}
}

/// 在 亮 → 暗 → 跟随系统 之间循环。
void cycleThemeMode() {
  final cur = themeModeNotifier.value;
  themeModeNotifier.value = switch (cur) {
    ThemeMode.light => ThemeMode.dark,
    ThemeMode.dark => ThemeMode.system,
    ThemeMode.system => ThemeMode.light,
  };
  _saveThemeMode();
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
