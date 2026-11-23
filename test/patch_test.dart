import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:yd_pentool/core/firmware_scanner.dart';
import 'package:yd_pentool/core/hash_util.dart';
import 'package:yd_pentool/core/image_patcher.dart';

/// 造一个合成镜像：RKFW 头 + 一段真实的鉴权脚本。
/// 不依赖任何真实固件，所以 CI 上能跑。
Future<File> buildFixture(String password) async {
  final hash = hashPassword(
    password: password,
    algorithm: HashAlgorithm.md5,
    trailingNewline: true,
  );
  final script = '''
#!/bin/sh
VERIFIED=/tmp/.adb_auth_verified

if [ -f "\$VERIFIED" ]; then
    echo "success."
    exit
fi

for i in \$(seq 1 3); do
    read -p "\$(hostname -s)'s password: " PASSWD
    if [ "\$(echo \$PASSWD | md5sum)" = "$hash  -" ]; then
        echo "success."
        touch \$VERIFIED
        exit
    fi
    echo "password incorrect!"
done

false
''';

  final tmp = Directory.systemTemp.createTempSync('yd_pentool_test');
  final file = File('${tmp.path}/fixture.img');
  final prefix = List<int>.filled(4096, 0)
    ..setRange(0, 4, ascii.encode('RKFW'));
  await file.writeAsBytes([
    ...prefix,
    ...latin1.encode(script),
    ...List<int>.filled(4096, 0),
  ], flush: true);
  return file;
}

void main() {
  late String oldHash;
  late File image;

  setUpAll(() async {
    oldHash = hashPassword(
      password: 'oldpass',
      algorithm: HashAlgorithm.md5,
      trailingNewline: true,
    );
    image = await buildFixture('oldpass');
  });

  test('扫描能定位脚本并判定 MD5 + 带换行 + 比较串带尾巴', () async {
    final result = await scanFirmware(image);
    expect(result.container, 'RKFW');
    expect(result.candidates, isNotEmpty);

    final best = result.candidates.first;
    expect(best.algorithm, HashAlgorithm.md5);
    expect(best.storedHash, oldHash);
    expect(best.trailingNewline, isTrue);
    expect(best.dashSuffix, isTrue);
    expect(best.confidence, greaterThanOrEqualTo(60));
  });

  test('改写生成新文件：大小不变、原文件不动、回读命中新哈希', () async {
    final scan = await scanFirmware(image);
    final script = scan.candidates.first;
    final sizeBefore = await image.length();

    final result = await patchImage(
      image: image,
      script: script,
      newPassword: 'newpass',
    );

    final expected = hashPassword(
      password: 'newpass',
      algorithm: HashAlgorithm.md5,
      trailingNewline: true,
    );
    expect(result.newHash, expected);
    expect(result.verified, isTrue);
    expect(result.outputPath, '${image.path}.patched');

    final outFile = File(result.outputPath);
    expect(await outFile.exists(), isTrue);
    expect(await outFile.length(), sizeBefore);

    // 输出文件里应该是新哈希
    final rescan = await scanFirmware(outFile);
    expect(rescan.candidates.first.storedHash, expected);

    // 原文件必须保持原样
    final originalScan = await scanFirmware(image);
    expect(originalScan.candidates.first.storedHash, oldHash);
  });

  test('空口令必须被拒绝', () async {
    final scan = await scanFirmware(image);
    await expectLater(
      patchImage(
        image: image,
        script: scan.candidates.first,
        newPassword: '',
      ),
      throwsA(isA<PatchException>()),
    );
  });

  test('换行符语义：md5 与 md5+\\n 必须不同', () {
    final withNewline = hashPassword(
      password: 'abc',
      algorithm: HashAlgorithm.md5,
      trailingNewline: true,
    );
    final without = hashPassword(
      password: 'abc',
      algorithm: HashAlgorithm.md5,
      trailingNewline: false,
    );
    expect(withNewline, isNot(without));
  });
}
