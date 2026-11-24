# 通用流程（依据社区文档整理 + A7 Pro 实测校准）

> 本文把 [86lbs/ydpen-adb-unlock](https://github.com/86lbs/ydpen-adb-unlock) 的官方 9 步、
> [langningchen/paper](https://github.com/langningchen/paper) 的自动化思路，
> 以及本工作区对 A7 Pro 固件的实测结论，合并成一条**不依赖具体机型**的流水线。
>
> 重要前提：该手法利用的是厂商 OTA **无签名校验**。2026 年上半年有道开始在部分机型改 HTTPS，
> 遇到加密的更新响应说明该设备已修复，工具应直接报错退出，不做无意义的尝试。
>
> **如果目标设备的 HTTP 更新请求已被封堵**，改走 USB 方案：
> 见 [MTP_UNLOCK.md](MTP_UNLOCK.md) —— MTP 路径穿越写 `/tmp/.adb_auth_verified`，
> 一次性的 root ADB，不需要下载固件（本机已实测成立）。

## 0. 全流程视角

```
[抓包] → [取全量包] → [定位鉴权脚本] → [换哈希] → [重算校验]
                                                    ↓
                                              [本地 OTA 服务器]
                                                    ↓
                                            [笔端检查更新/安装]
                                                    ↓
                                          [adb shell auth] → root
```

## 1. 抓包：拿到 OTA 请求与响应

- 电脑开热点，笔连热点，Wireshark 抓热点网卡
- 笔上触发「检查更新」，抓 `POST http(s)://iotapi.abupdate.com/product/<id>/ota/checkVersion`
- 记录请求体：`timestamp`、`sign`、`mid`、`productId`
- **抓不到包**：笔的"检查更新"可能根本没发请求 → 恢复出厂 → 联网激活 → 重试
- **包体加密**：该机型已修复漏洞，终止

## 2. 取全量包

回放同一请求（`version` 填 `99.99.90` 触发最新包），从响应拿：

| 字段 | 用途 |
|---|---|
| `data.version.deltaUrl` / `bakUrl` | 全量包下载地址 |
| `data.version.fileSize` | 期望大小（改写后必须一致） |
| `data.version.md5sum` | 整包 MD5（改写后要替换） |
| `data.version.sha` | 整包 SHA1/SHA256（改写后要替换） |
| `data.version.segmentMd5[].endpos` | **分段边界**，逐段校验，必须逐字照抄 |

## 3. 定位鉴权脚本（本工具核心）

**不硬编码偏移**，而是按标记搜索 + 从脚本内容反推语义：

| 搜索标记 | 覆盖的代次 |
|---|---|
| `/tmp/.adb_auth_verified` | 现役 Linux 词典笔 OS（最可靠） |
| `/usr/bin/adbd_auth.sh`、`adbd_auth.sh` | A7 Pro / Y09（RV1106） |
| `/usr/bin/adb_auth.sh`、`adb_auth.sh` | CoCo / CV1826 等老平台 |
| `CherryYoudao` | 极老固件的明文口令 |

找到标记后，在 ±几 KB 的窗口里解析：

1. **算法**：看 `md5sum` / `sha256sum` / `sha1sum`；命令缺失时按哈希长度反推（32/40/64/128）
2. **换行语义**：`echo $PASSWD` → 带 `\n`；`echo -n $PASSWD` → 不带
3. **比较串尾巴**：`"<hash>  -"` 里的两个空格 + `-` 属于比对内容
4. **提示语**：`read -p "..."` → 用于确认确实是对的那段脚本

> 官方文档反复强调：**以脚本实际内容为准，不要套用别人的结论**。
> 同一型号不同固件版本的算法和换行都可能不同。

## 4. 换哈希（等长就地改写）

- 只覆盖哈希字符串本身，**字符数必须完全一致**
- 明文口令的极老固件，新口令必须与原口令等长
- 写完：文件大小必须不变 + 回读校验 + 只允许目标区间变化

## 5. 重算校验

- 按 `segmentMd5[].endpos` 切段算每段 MD5（**边界填错 = 下载进度条卡死**）
- 分段大小**不是固定 100 MB**：A7 Pro 实测是 **50 MB × 21 段**，S6 是 100 MB，一律以抓包为准
- 整包 MD5、整包 SHA
- 全部回填到伪造的 OTA 响应里

> 工具已支持直接导入抓包 `full.json`，自动填充 `endpos` 并与本地镜像核对大小/MD5。

## 6. 本地 OTA 服务器

- `YDPen.js`：监听 80，按抓到的 URL 路径返回伪造 JSON
- `httpserver.py`：监听 14514，提供改写后的 img
- `hosts`：`<本机局域网IP> iotapi.abupdate.com`，然后 `ipconfig /flushdns`
- 笔与电脑必须在同一局域网

> A7 Pro 固件里自带 `hostapd + dnsmasq + udhcpc`（`0x393ed986` 区域），
> 说明设备本身具备热点能力，可用它减少网络变量。

## 7. 安装与认证

- 笔上「检查更新」→ 下载 → 安装 → 自动重启
- 重启后到「法律监管」连击开 ADB
- `adb shell auth` → 输入**明文**新口令 → `success.` → `adb shell` 得 root

## 8. 持久化（可选）

- `/tmp` 重启即清空，`/tmp/.adb_auth_verified` 不会保留
- 老平台可参考 `/tmp/.adbON` + `/userdisk/skip_re/skip_login.sh` 的做法

## 机型差异速查

| 平台 | 容器 | rootfs | 脚本 | 算法 | 备注 |
|---|---|---|---|---|---|
| A7 Pro（RV1106 / Y09） | RKFW | EROFS（未压缩） | `/usr/bin/adbd_auth.sh` | MD5 + 换行 | 脚本 @0x28CEF006，哈希 @0x28CEF0DF |
| X7 Pro（RK3562） | RKFW | EROFS | `/usr/bin/adbd_auth.sh` | MD5 或 SHA256（**看脚本**） | 社区样本 `302af1d8…` |
| S6 / CoCo（CV1826） | 裸 img | squashfs | `/usr/bin/adb_auth.sh` | SHA256 | 另有 `/data/adb_persist/adbd_auth.sh` 可绕过 |
| 极老固件 | — | — | — | 明文 | 默认口令 `CherryYoudao` |

## 工具与手工的对应关系

| 官方步骤 | 工具里的位置 |
|---|---|
| 1–2 抓包/取包 | `lib/core/ota_proxy.dart`（**代理模式**：笔把请求发到本机，程序转发真服务器并抓下响应，不再需要 Npcap）+ `firmware_download.dart` 下载 |
| 3 定位脚本 | `lib/core/firmware_scanner.dart` + `auth_script.dart` |
| 4 换哈希 | `lib/core/image_patcher.dart` |
| 5 重算校验 | `lib/core/checksum.dart` |
| 6 本地服务器 | `ota_proxy.dart`（响应改写 + 80 端口发镜像）+ `hosts_manager.dart`（hosts 改写/还原/刷 DNS） |
| 7 认证 | `lib/core/adb.dart`（`shell auth` + root 验证） |

> 代理模式的关键：**不需要提前知道 `productId`**。程序把笔的 `checkVersion` 原样转发给真服务器，
> 拿到真实响应（含 `segmentMd5.endpos`）后再改地址与校验值返回。抓包只在笔不走系统 DNS 时才需要。
