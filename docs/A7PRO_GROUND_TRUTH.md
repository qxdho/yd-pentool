# A7 Pro 破解数据核对（实测基准）

> 数据来源：`E:\qxdho\有道词典笔A7pro破解\`
> 核对时间：2026-11-24
> 结论：**工具算出的偏移、算法、校验值与用户真实破解结果逐字节一致。**

## 1. 用到的原始数据

| 文件 | 说明 |
|---|---|
| `nwgsjsGz.img` | 原始全量固件，1,053,385,290 字节 |
| `mod.img` | 用户已破解（已改口令）的固件，大小相同 |
| `ota_response\full.json` | 抓包得到的 `checkVersion` 原始响应 |
| `算密码.bat` | 用户当时算口令哈希的脚本 |
| `DNA\DNA_youdaoA7pro\rootfs\usr\bin\adbd_auth.sh` | 从固件解出的鉴权脚本 |

## 2. 镜像差异：只有 32 字节

对 `nwgsjsGz.img` 与 `mod.img` 做全文件逐字节比较：

```
差异区间数: 1
  0x28CEF0DF  32 字节
    原: 24f192481770c0978c713cf2d41394e6
    新: c3237a5b010281b0499f5923ff20d8b1
```

这与工具从固件里解析出的 `hashOffset` **完全一致**（`adbd_auth.sh` @ `0x28CEF006`，
哈希 @ `0x28CEF0DF`）。

## 3. 校验值与 OTA 声明吻合

| 项 | 实测 | OTA JSON 声明 |
|---|---|---|
| 原镜像 MD5 | `c9d691919c0c56b16fae695fba0397fe` | `c9d691919c0c56b16fae695fba0397fe` ✅ |
| 原镜像 SHA256 | `643ffac6d6fd24014412c818ed3be856aa841743b938d9a59c5741131db072fa` | 同左 ✅ |

`mod.img` 的摘要（也就是伪造响应里应当填写的值）：

```
MD5    = 1b85a57c77417a875ae3188914822541
SHA256 = 4fb4d7daef4bf4ec9ca729293cfc08e8b819718e8ee582ca42bedca829f8d967
```

## 4. 端到端复现

按工具的算法（原镜像 + 在 `0x28CEF0DF` 写入 `c3237a5b…`）做模拟改写：

```
MD5    = 1b85a57c77417a875ae3188914822541   ✅ 与 mod.img 一致
SHA256 = 4fb4d7daef4bf4ec9ca729293cfc08e8b819718e8ee582ca42bedca829f8d967   ✅ 一致
分段   = 21 段，边界与抓包一致
```

即：**扫描 → 定位 → 等长替换 → 整包/分段校验** 这条链路在真实数据上成立。

## 5. 鉴权脚本：与固件内提取的逐字节相同

```sh
#!/bin/sh
VERIFIED=/tmp/.adb_auth_verified
...
    if [ "$(echo $PASSWD | md5sum)" = "24f192481770c0978c713cf2d41394e6  -" ]; then
        echo "success."
        touch $VERIFIED
```

## 6. 口令哈希语义：用户脚本侧面印证

`算密码.bat` 的核心一行：

```powershell
$pass = '口令' + [char]10;  MD5(UTF8($pass))
```

即 **MD5(口令 + `\n`)** —— 与工具里 `trailingNewline = true` 的实现一致。
官方文档反复强调的"换行符陷阱"，用户当时也是这么处理的。

## 7. OTA 响应关键参数（A7 Pro / 76011f）

| 字段 | 值 |
|---|---|
| 版本 | `99.99.91` |
| fileSize | `1053385290` |
| 分段 | **50 MB × 21 段**（不是 S6 的 100 MB） |
| 下载域名 | `iotdown-jd.mayitek.com` |
| 加密 | `safe.isEncrypt = 0`、`encKey = null` → 明文 HTTP，可劫持 |
| `data.sha256` | `932bbc64bc37c7d7c7c62e44ecac4baeea638c3e2038e4e2899a6d8d4feb7143` |

> ⚠️ `data.sha256` 与 `version.sha` **不是同一个值**，含义未知。
> 工具目前只改 `version` 下的字段；如果实际刷机时校验失败，需要回来检查这里。

## 8. 哈希偏移落在第几段

`0x28CEF0DF` = 684,650,719，落在第 13 段（629,145,600 ～ 681,574,400 之后那一段的末尾区间），
所以改写后**只有第 13 段 MD5 会变**，其余 20 段与原始响应完全相同。
这一点可以用来快速自检：算完之后对比一下，只有一段不同才正常。
