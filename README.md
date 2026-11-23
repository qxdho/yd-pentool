# 词典笔 ADB 口令改写器（adbtool）

Windows 桌面工具：把固件里那段 `adbd_auth.sh` 的 MD5/SHA 哈希换成自己的口令，
再算出 OTA 需要的分段校验，配合本地更新服务器刷回设备。

**通用性来自"读脚本"而不是"记偏移"**：算法、换行语义、比较串尾巴全部从固件里的脚本原文解析，
所以同一型号不同固件版本也能用。

## 现在能做什么

| 步骤 | 状态 | 位置 |
|---|---|---|
| 1 载入固件、识别容器（RKFW/RAW）、版本串、RKAF 偏移 | ✅ | `lib/core/firmware_scanner.dart` |
| 2 按标记定位鉴权脚本，自动判定算法/换行/尾巴/提示语 | ✅ | `lib/core/auth_script.dart` |
| 3 等长改写哈希（自动备份 + 回读校验 + 大小不变断言） | ✅ | `lib/core/image_patcher.dart` |
| 4 整包 MD5/SHA1/SHA256 + 按 `endpos` 分段 MD5 | ✅ | `lib/core/checksum.dart` |
| 5 本地 OTA 服务器（伪造响应 + 提供镜像） | ⏳ 待实现 | `lib/core/ota_server.dart` |
| 6 `adb shell auth` 自动化 + 持久化 | ⏳ 待实现 | `lib/core/adb.dart` |
| 7 抓包（Npcap） | ⏳ 待实现 | — |

## 构建（GitHub Actions）

仓库不存 `windows/` 平台目录，CI 里用 `flutter create` 现场生成，避免平台模板堆积。

```yaml
# .github/workflows/build.yml 已包含
jobs:
  test           # ubuntu + flutter test
  build-windows  # windows-latest + flutter build windows --release
```

推上 GitHub 后：

1. Actions → `build` → 跑完
2. 下载 artifact `adbtool-windows-<sha>`
3. 解压运行 `adbtool.exe`

本地想跑的话：装 Flutter 3.24+，`flutter create --platforms=windows . && flutter run -d windows`。

## 为什么是"通用"

- **不硬编码任何偏移**：只按字符串标记定位（`/tmp/.adb_auth_verified`、`adbd_auth.sh` 等），再在窗口内解析
- **算法自适应**：`md5sum`/`sha1sum`/`sha256sum`/`sha512sum`，命令缺失时按哈希长度反推
- **换行语义自适应**：认 `echo -n`
- **机型差异数据化**：`profiles/models.json`，加机型=加一条 JSON，不需要改代码
- **失败可解释**：解析不出脚本时明确提示（HTTPS 已修复 / 脚本压缩 / 机制不同）

## 安全边界

- 只对自己持有的设备使用
- 改写前强制备份 `.bak`，写后回读校验，文件大小不一致立刻中止
- 明文校验的老固件要求新口令与原口令**等长**，代码里会直接拒绝

## 目录

```
lib/
  main.dart               向导 UI（步骤条 + 日志）
  core/firmware_scanner.dart  容器识别 + 标记扫描
  core/auth_script.dart       脚本解析（算法/换行/尾巴）
  core/image_patcher.dart     等长改写 + 校验
  core/checksum.dart          整包/分段校验
  core/hash_util.dart         带换行语义的哈希 + 流式摘要
  core/model_profile.dart     机型档案
profiles/models.json          机型数据（A7 Pro / X7 Pro / CoCo）
docs/FLOW.md                  通用流程（对齐社区文档 + 实测）
test/patch_test.dart          合成镜像端到端测试
```
