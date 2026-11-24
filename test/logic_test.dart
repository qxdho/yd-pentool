import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:yd_pentool/core/adb.dart';
import 'package:yd_pentool/core/checksum.dart';
import 'package:yd_pentool/core/hosts_manager.dart';
import 'package:yd_pentool/core/ota_proxy.dart';

void main() {
  group('hosts 行级操作', () {
    const domain = 'iotapi.abupdate.com';

    test('在空文件上追加条目', () {
      final out = upsertHostEntry('', '192.168.1.5', domain);
      expect(out, contains('192.168.1.5 $domain'));
    });

    test('重复写入会替换而不是叠加', () {
      var content = upsertHostEntry('', '1.1.1.1', domain);
      content = upsertHostEntry(content, '2.2.2.2', domain);
      expect('2.2.2.2 $domain'.allMatches(content).length, 1);
      expect(content.contains('1.1.1.1'), isFalse);
    });

    test('保留注释与其它行', () {
      const original = '# 注释\r\n127.0.0.1 localhost\r\n';
      final out = upsertHostEntry(original, '192.168.1.5', domain);
      expect(out, contains('# 注释'));
      expect(out, contains('127.0.0.1 localhost'));
      expect(findHostEntry(out, domain), '192.168.1.5');
    });

    test('删除后不再命中', () {
      final content = upsertHostEntry('', '192.168.1.5', domain);
      final out = removeHostEntry(content, domain);
      expect(findHostEntry(out, domain), isNull);
    });

    test('往返后用户自己的条目与注释逐字节保留', () {
      const original = '# my comment\r\n10.0.0.1 myhost\r\n';
      final withOurs = upsertHostEntry(original, '192.168.137.1', domain);
      expect(findHostEntry(withOurs, domain), '192.168.137.1');
      final cleaned =
          removeHostEntry(withOurs, domain, ip: '192.168.137.1');
      expect(cleaned, original);
    });

    test('同域名冲突：先注释别人的，我们的才生效，且能逐字节还原', () {
      const original = '# 我的注释\r\n192.168.1.19 iotapi.abupdate.com\r\n';
      final disabled = <String>[];
      var content = disableForeignEntries(
          original, 'iotapi.abupdate.com', '192.168.137.1', disabled);
      content = upsertHostEntry(content, '192.168.137.1', 'iotapi.abupdate.com');
      expect(findHostEntry(content, 'iotapi.abupdate.com'), '192.168.137.1');
      expect(disabled, hasLength(1));
      var restored =
          removeHostEntry(content, 'iotapi.abupdate.com', ip: '192.168.137.1');
      restored = restoreDisabledEntries(restored, disabled);
      expect(restored, original);
    });

    test('只删指定 IP：不碰同一域名的其它条目', () {
      const content = '10.1.1.1 $domain\n192.168.137.1 $domain\n';
      final cleaned = removeHostEntry(content, domain, ip: '192.168.137.1');
      expect(cleaned, '10.1.1.1 $domain\n');
    });
  });

  group('OTA 响应改写', () {
    Map<String, dynamic> sampleResponse() => {
          'status': 1000,
          'msg': 'success',
          'data': {
            'releaseNotes': {'version': '99.99.91'},
            'safe': {'encKey': null, 'isEncrypt': 0},
            'version': {
              'deltaUrl': 'http://real.example/x.img',
              'bakUrl': 'http://real.example/x.img',
              'md5sum': 'old',
              'sha': 'oldsha',
              'fileSize': 100,
              'segmentMd5': jsonEncode([
                {'num': 0, 'startpos': 0, 'md5': 'aaa', 'endpos': 50},
                {'num': 1, 'startpos': 50, 'md5': 'bbb', 'endpos': 100},
              ]),
            },
          },
        };

    OtaRewriteConfig cfg() => OtaRewriteConfig(
          imageUrl: 'http://192.168.1.5:80/x.img.patched',
          fileSize: 1000,
          md5: 'newmd5',
          sha256: 'newsha',
          segmentMd5: const ['seg0', 'seg1'],
        );

    test('替换地址、整包校验与分段 md5，保留 endpos', () {
      final out = rewriteOtaResponse(sampleResponse(), cfg());
      final version = (out['data'] as Map)['version'] as Map;
      expect(version['deltaUrl'], contains('192.168.1.5'));
      expect(version['md5sum'], 'newmd5');
      expect(version['fileSize'], 1000);
      final segs = jsonDecode(version['segmentMd5'] as String) as List;
      expect((segs[0] as Map)['md5'], 'seg0');
      expect((segs[0] as Map)['endpos'], 50);
      expect((segs[1] as Map)['md5'], 'seg1');
    });

    test('分段数量不一致时报错', () {
      final bad = OtaRewriteConfig(
        imageUrl: 'u',
        fileSize: 1,
        md5: 'm',
        sha256: 's',
        segmentMd5: const ['only-one'],
      );
      expect(() => rewriteOtaResponse(sampleResponse(), bad),
          throwsA(isA<OtaRewriteException>()));
    });

    test('响应加密时拒绝改写', () {
      // 手工构造的嵌套 Map 会被推断成 Map<String, int?>，赋 String 会抛类型错误；
      // 走一次 JSON 往返，拿到与真实响应一致的 Map<String, dynamic>。
      final resp =
          jsonDecode(jsonEncode(sampleResponse())) as Map<String, dynamic>;
      ((resp['data'] as Map)['safe'] as Map)['encKey'] = 'abc';
      expect(() => rewriteOtaResponse(resp, cfg()),
          throwsA(isA<OtaRewriteException>()));
    });

    test('没有 data/version 时报错', () {
      expect(() => rewriteOtaResponse({'status': 1}, cfg()),
          throwsA(isA<OtaRewriteException>()));
    });
  });

  group('adb 输出解析', () {
    test('devices 解析跳过表头与提示', () {
      const out = 'List of devices attached\n'
          'ME62200008900890\tdevice\n'
          'emulator-5554\toffline\n'
          '* daemon started successfully\n';
      final list = parseDevices(out);
      expect(list.length, 2);
      expect(list[0].serial, 'ME62200008900890');
      expect(list[0].state, 'device');
      expect(list[1].state, 'offline');
    });

    test('认证与 root 判定', () {
      expect(authSucceeded("pen's password: success."), isTrue);
      expect(authSucceeded('password incorrect!'), isFalse);
      expect(isRootOutput('uid=0(root) gid=0(root)'), isTrue);
      expect(isRootOutput('uid=2000(shell)'), isFalse);
    });
  });

  group('分段校验', () {
    test('按 endpos 切段计算 md5', () async {
      final dir = Directory.systemTemp.createTempSync('yd_ck');
      final f = File('${dir.path}/data.bin');
      final bytes = List<int>.generate(1000, (i) => i % 251);
      await f.writeAsBytes(bytes);

      final report = await computeChecksums(f, endPositions: [300, 700, 1000]);
      expect(report.segmentMd5.length, 3);
      expect(report.segmentMd5[0], md5.convert(bytes.sublist(0, 300)).toString());
      expect(report.segmentMd5[1], md5.convert(bytes.sublist(300, 700)).toString());
      expect(report.segmentMd5[2], md5.convert(bytes.sublist(700, 1000)).toString());
      expect(report.totalMd5, md5.convert(bytes).toString());
      expect(report.fileSize, 1000);
    });

    test('endpos 解析容错', () {
      expect(parseEndPositions('100, 200;300\n400'), [100, 200, 300, 400]);
      expect(() => parseEndPositions('abc'), throwsA(isA<FormatException>()));
    });
  });
}
