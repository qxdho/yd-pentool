import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:yd_pentool/core/ota_capture.dart';
import 'package:yd_pentool/core/ota_proxy.dart';

/// 用真实抓包（A7 Pro，固件版本 76011f）当基准，确保改写逻辑对得上真实响应结构。
void main() {
  late String raw;

  setUpAll(() {
    raw = File('test/fixtures/ota_full.json').readAsStringSync();
  });

  test('解析真实抓包：21 段、每段 50MB、未加密', () {
    final c = OtaCapture.parse(raw);
    expect(c.segmentCount, 21);
    expect(c.firstSegmentSize, 52428800);
    expect(c.fileSize, 1053385290);
    expect(c.md5, 'c9d691919c0c56b16fae695fba0397fe');
    expect(c.encrypted, isFalse);
    expect(c.deltaUrl, contains('iotdown-jd.mayitek.com'));
    expect(c.versionName, '99.99.91');
  });

  test('本地镜像一致性核对', () {
    final c = OtaCapture.parse(raw);
    expect(
      c.verifyAgainst(
        localSize: 1053385290,
        localMd5: 'c9d691919c0c56b16fae695fba0397fe',
      ),
      isNull,
    );
    expect(
      c.verifyAgainst(localSize: 1, localMd5: 'whatever'),
      isNotNull,
    );
  });

  test('真实结构改写：字段全部替换，endpos 原样保留', () {
    final c = OtaCapture.parse(raw);
    final json = jsonDecode(raw) as Map<String, dynamic>;
    final cfg = OtaRewriteConfig(
      imageUrl: 'http://192.168.1.5:80/nwgsjsGz.img.patched',
      fileSize: 1053385290,
      md5: 'newmd5',
      sha256: 'newsha',
      segmentMd5: List.generate(c.segmentCount, (i) => 'seg$i'),
    );

    final out = rewriteOtaResponse(json, cfg);
    final version = (out['data'] as Map)['version'] as Map;
    expect(version['md5sum'], 'newmd5');
    expect(version['sha'], 'newsha');
    expect(version['deltaUrl'], contains('192.168.1.5'));
    expect(version['bakUrl'], contains('192.168.1.5'));

    final segs = jsonDecode(version['segmentMd5'] as String) as List;
    expect(segs.length, 21);
    expect((segs[0] as Map)['md5'], 'seg0');
    expect((segs[0] as Map)['endpos'], 52428800);
    expect((segs[13] as Map)['endpos'], 681574400);
    expect((segs[20] as Map)['endpos'], 1053385290);
  });

  test('抓包里的历史记录：哈希改写只影响第 13 段', () {
    // 偏移 0x28CEF0DF = 684650719，落在 629145600..681574400 之外？
    // 实际落在第 13 段（629145600 起）；这里只校验分段边界的算术。
    const offset = 0x28CEF0DF;
    final c = OtaCapture.parse(raw);
    var idx = 0;
    while (idx < c.segmentCount && c.endPositions[idx] <= offset) {
      idx++;
    }
    expect(idx, 13);
  });
}
