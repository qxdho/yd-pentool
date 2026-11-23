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
  late String expectedHash;
  late File image;

  setUpAll(() async {
    expectedHash = hashPassword(
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
    expect(best.storedHash, expectedHash);
    expect(best.trailingNewline, isTrue);
    expect(best.dashSuffix, isTrue);
    expect(best.confidence, greaterThanOrEqualTo(60));
  });

  test('改写后哈希正确、文件大小不变、回读通过', () async {
    final scan = await scanFirmware(image);
    final script = scan.candidates.first;
    final sizeBefore = await image.length();

    final result = await patchImage(
      image: image,
      script: script,
      newPassword: 'newpass',
      makeBackup: false,
    );

    final expectHash = hashPassword(
      password: 'newpass',
      algorithm: HashAlgorithm.md5,
      trailingNewline: true,
    );
    expect(result.newHash, expectHash);
    expect(result.verified, isTrue);
    expect(await image.length(), sizeBefore);

    // 重新扫描应该读到新哈希
    final rescan = await scanFirmware(image);
    expect(rescan.candidates.first.storedHash, expectHash);
  });

  test('空口令必须被拒绝', () async {
    final scan = await scanFirmware(image);
    await expectLater(
      patchImage(
        image: image,
        script: scan.candidates.first,
        newPassword: '',
        makeBackup: false,
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
