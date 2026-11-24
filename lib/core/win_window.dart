import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// 直接操作当前顶层窗口的位置与尺寸。
///
/// 不依赖任何插件（避免引入 plugin 让 CI 变复杂），只用 user32 的三个 API：
/// GetForegroundWindow / GetWindowRect / SetWindowPos + SystemParametersInfo。
class WinWindow {
  WinWindow._();

  static DynamicLibrary? _user32;
  static DynamicLibrary get _lib => _user32 ??= DynamicLibrary.open('user32.dll');

  static int _getForegroundWindow() {
    final f = _lib.lookupFunction<IntPtr Function(), int Function()>(
      'GetForegroundWindow',
    );
    return f();
  }

  static ({int left, int top, int right, int bottom}) _getWindowRect(int hwnd) {
    final f = _lib.lookupFunction<
        Int32 Function(IntPtr, Pointer<Rect>),
        int Function(int, Pointer<Rect>)>('GetWindowRect');
    final ptr = calloc<Rect>();
    try {
      final ok = f(hwnd, ptr);
      if (ok == 0) return (left: 0, top: 0, right: 0, bottom: 0);
      final r = ptr.ref;
      return (left: r.left, top: r.top, right: r.right, bottom: r.bottom);
    } finally {
      calloc.free(ptr);
    }
  }

  static void _setWindowPos(int hwnd, int x, int y, int w, int h) {
    final f = _lib.lookupFunction<
        Int32 Function(IntPtr, IntPtr, Int32, Int32, Int32, Int32, Uint32),
        int Function(int, int, int, int, int, int, int)>('SetWindowPos');
    const swpNoZOrder = 0x0004;
    const swpNoActivate = 0x0010;
    f(hwnd, 0, x, y, w, h, swpNoZOrder | swpNoActivate);
  }

  /// 工作区（排除任务栏），物理像素。
  static ({int left, int top, int right, int bottom}) _workArea() {
    final f = _lib.lookupFunction<
        Int32 Function(Uint32, Uint32, Pointer<Rect>, Uint32),
        int Function(int, int, Pointer<Rect>, int)>('SystemParametersInfoW');
    const spiGetWorkArea = 0x0030;
    final ptr = calloc<Rect>();
    try {
      f(spiGetWorkArea, 0, ptr, 0);
      final r = ptr.ref;
      return (left: r.left, top: r.top, right: r.right, bottom: r.bottom);
    } finally {
      calloc.free(ptr);
    }
  }

  /// 让窗口铺到工作区的 92%（居中）。返回是否成功。
  static bool fitToScreen({double ratio = 0.92}) {
    if (!Platform.isWindows) return false;
    try {
      final hwnd = _getForegroundWindow();
      if (hwnd == 0) return false;
      final wa = _workArea();
      final availW = wa.right - wa.left;
      final availH = wa.bottom - wa.top;
      if (availW <= 0 || availH <= 0) return false;
      final w = (availW * ratio).round();
      final h = (availH * ratio).round();
      final x = wa.left + ((availW - w) ~/ 2);
      final y = wa.top + ((availH - h) ~/ 2);
      _setWindowPos(hwnd, x, y, w, h);
      return true;
    } catch (_) {
      return false;
    }
  }

  /// 按比例放大/缩小当前窗口（保持中心不动）。
  static bool zoom(double factor) {
    if (!Platform.isWindows) return false;
    try {
      final hwnd = _getForegroundWindow();
      if (hwnd == 0) return false;
      final r = _getWindowRect(hwnd);
      final w = r.right - r.left;
      final h = r.bottom - r.top;
      if (w <= 0 || h <= 0) return false;
      final nw = (w * factor).round().clamp(640, 10000);
      final nh = (h * factor).round().clamp(480, 10000);
      final nx = r.left + ((w - nw) ~/ 2);
      final ny = r.top + ((h - nh) ~/ 2);
      _setWindowPos(hwnd, nx, ny, nw, nh);
      return true;
    } catch (_) {
      return false;
    }
  }
}

final class Rect extends Struct {
  @Int32()
  external int left;

  @Int32()
  external int top;

  @Int32()
  external int right;

  @Int32()
  external int bottom;
}
