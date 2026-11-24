import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// 以管理员身份重新启动自己（UAC 提权）。
///
/// 用 shell32 的 ShellExecuteW + "runas" 动词，等价于右键"以管理员身份运行"。
/// 返回 true 表示已成功发起提权（调用方应立即退出，让新进程接管）。
Future<bool> relaunchAsAdmin({List<String> arguments = const []}) async {
  if (!Platform.isWindows) return false;
  try {
    final shell32 = DynamicLibrary.open('shell32.dll');
    final shellExecute = shell32.lookupFunction<
        IntPtr Function(IntPtr, Pointer<Utf16>, Pointer<Utf16>, Pointer<Utf16>,
            Pointer<Utf16>, Int32),
        int Function(int, Pointer<Utf16>, Pointer<Utf16>, Pointer<Utf16>,
            Pointer<Utf16>, int)>('ShellExecuteW');

    final verb = 'runas'.toNativeUtf16();
    final file = Platform.resolvedExecutable.toNativeUtf16();
    Pointer<Utf16> params = nullptr;
    if (arguments.isNotEmpty) {
      params = arguments.map((a) => '"$a"').join(' ').toNativeUtf16();
    }
    try {
      // SW_SHOWNORMAL = 1
      final r = shellExecute(0, verb, file, params, nullptr, 1);
      // 返回值 > 32 表示成功
      return r > 32;
    } finally {
      calloc.free(verb);
      calloc.free(file);
      if (params != nullptr) calloc.free(params);
    }
  } catch (_) {
    return false;
  }
}
