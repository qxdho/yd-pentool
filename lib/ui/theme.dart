import 'package:flutter/material.dart';

/// 语义色板：UI 里不再直接写颜色，全部从这里取，亮/暗主题共用一套名字。
@immutable
class AppPalette extends ThemeExtension<AppPalette> {
  const AppPalette({
    required this.pageBg,
    required this.surface,
    required this.surfaceAlt,
    required this.border,
    required this.textPrimary,
    required this.textMuted,
    required this.logBg,
    required this.logText,
    required this.chipBg,
    required this.chipText,
    required this.success,
    required this.warning,
    required this.danger,
  });

  final Color pageBg;
  final Color surface;
  final Color surfaceAlt;
  final Color border;
  final Color textPrimary;
  final Color textMuted;
  final Color logBg;
  final Color logText;
  final Color chipBg;
  final Color chipText;
  final Color success;
  final Color warning;
  final Color danger;

  static const light = AppPalette(
    pageBg: Color(0xFFF6F7F9),
    surface: Color(0xFFFFFFFF),
    surfaceAlt: Color(0xFFF9FAFB),
    border: Color(0xFFE6E8EC),
    textPrimary: Color(0xFF111827),
    textMuted: Color(0xFF6B7280),
    logBg: Color(0xFF0F172A),
    logText: Color(0xFFCBD5E1),
    chipBg: Color(0xFFEFF6FF),
    chipText: Color(0xFF2563EB),
    success: Color(0xFF10B981),
    warning: Color(0xFFF59E0B),
    danger: Color(0xFFEF4444),
  );

  static const dark = AppPalette(
    pageBg: Color(0xFF0F1216),
    surface: Color(0xFF161B22),
    surfaceAlt: Color(0xFF1C2230),
    border: Color(0xFF262C36),
    textPrimary: Color(0xFFE6EDF3),
    textMuted: Color(0xFF9BA6B4),
    logBg: Color(0xFF0B0E12),
    logText: Color(0xFFCBD5E1),
    chipBg: Color(0xFF1E3A5F),
    chipText: Color(0xFF93C5FD),
    success: Color(0xFF34D399),
    warning: Color(0xFFFBBF24),
    danger: Color(0xFFF87171),
  );

  @override
  AppPalette copyWith({
    Color? pageBg,
    Color? surface,
    Color? surfaceAlt,
    Color? border,
    Color? textPrimary,
    Color? textMuted,
    Color? logBg,
    Color? logText,
    Color? chipBg,
    Color? chipText,
    Color? success,
    Color? warning,
    Color? danger,
  }) {
    return AppPalette(
      pageBg: pageBg ?? this.pageBg,
      surface: surface ?? this.surface,
      surfaceAlt: surfaceAlt ?? this.surfaceAlt,
      border: border ?? this.border,
      textPrimary: textPrimary ?? this.textPrimary,
      textMuted: textMuted ?? this.textMuted,
      logBg: logBg ?? this.logBg,
      logText: logText ?? this.logText,
      chipBg: chipBg ?? this.chipBg,
      chipText: chipText ?? this.chipText,
      success: success ?? this.success,
      warning: warning ?? this.warning,
      danger: danger ?? this.danger,
    );
  }

  @override
  AppPalette lerp(ThemeExtension<AppPalette>? other, double t) {
    if (other is! AppPalette) return this;
    Color l(Color a, Color b) => Color.lerp(a, b, t) ?? a;
    return AppPalette(
      pageBg: l(pageBg, other.pageBg),
      surface: l(surface, other.surface),
      surfaceAlt: l(surfaceAlt, other.surfaceAlt),
      border: l(border, other.border),
      textPrimary: l(textPrimary, other.textPrimary),
      textMuted: l(textMuted, other.textMuted),
      logBg: l(logBg, other.logBg),
      logText: l(logText, other.logText),
      chipBg: l(chipBg, other.chipBg),
      chipText: l(chipText, other.chipText),
      success: l(success, other.success),
      warning: l(warning, other.warning),
      danger: l(danger, other.danger),
    );
  }
}

/// 便捷取色：`context.palette.textMuted`
extension AppPaletteX on BuildContext {
  AppPalette get palette =>
      Theme.of(this).extension<AppPalette>() ?? AppPalette.light;
}

const double kCardRadius = 14;
const double kControlRadius = 10;
const double kButtonHeight = 40;

ThemeData buildLightTheme() => _build(Brightness.light, AppPalette.light);
ThemeData buildDarkTheme() => _build(Brightness.dark, AppPalette.dark);

ThemeData _build(Brightness brightness, AppPalette p) {
  final scheme = ColorScheme.fromSeed(
    seedColor: const Color(0xFF3B82F6),
    brightness: brightness,
  );
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    brightness: brightness,
    scaffoldBackgroundColor: p.pageBg,
    fontFamily: 'Microsoft YaHei UI',
    fontFamilyFallback: const ['Microsoft YaHei', 'Segoe UI'],
    extensions: [p],
    cardTheme: CardTheme(
      elevation: 0,
      margin: EdgeInsets.zero,
      color: p.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(kCardRadius),
        side: BorderSide(color: p.border),
      ),
    ),
    dividerTheme: DividerThemeData(color: p.border, thickness: 1),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        minimumSize: const Size(0, kButtonHeight),
        padding: const EdgeInsets.symmetric(horizontal: 18),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(kControlRadius),
        ),
        textStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        minimumSize: const Size(0, kButtonHeight),
        padding: const EdgeInsets.symmetric(horizontal: 16),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(kControlRadius),
        ),
        side: BorderSide(color: p.border),
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
      fillColor: p.surfaceAlt,
      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(kControlRadius),
        borderSide: BorderSide(color: p.border),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(kControlRadius),
        borderSide: BorderSide(color: p.border),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(kControlRadius),
        borderSide: BorderSide(color: scheme.primary, width: 1.5),
      ),
      labelStyle: const TextStyle(fontSize: 12),
    ),
    textTheme: TextTheme(
      titleMedium: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
      bodyMedium: const TextStyle(fontSize: 13, height: 1.5),
      bodySmall: TextStyle(fontSize: 12, height: 1.5, color: p.textMuted),
    ),
    popupMenuTheme: PopupMenuThemeData(
      color: p.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(kControlRadius),
        side: BorderSide(color: p.border),
      ),
    ),
    expansionTileTheme: ExpansionTileThemeData(
      iconColor: p.textMuted,
      collapsedIconColor: p.textMuted,
    ),
    tooltipTheme: TooltipThemeData(
      decoration: BoxDecoration(
        color: brightness == Brightness.dark
            ? const Color(0xFF2A3140)
            : const Color(0xFF374151),
        borderRadius: BorderRadius.circular(6),
      ),
      textStyle: const TextStyle(fontSize: 12, color: Colors.white),
    ),
  );
}
