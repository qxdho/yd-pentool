# MTP 路径穿越开 ADB（临时解锁方案）

> 状态：**方案已在本机实测成立**（2026-11-24），尚未集成进 GUI。
> 外部参考：[xtawa/youdao-dict-crack-mtp](https://github.com/xtawa/youdao-dict-crack-mtp)（2026-10-16 验证）
> 本仓库的实测记录见文末「本机验证结果」。

## 一、这个方法解决什么问题

改固件哈希那套（`docs/FLOW.md` 的 8 步）需要：抓包 → 下载 1 GB 全量包 → 改镜像 → 回灌。
对于**已经封堵 HTTP Post 请求**的新版系统，第一步就断了。

MTP 方案完全绕开网络：

```
不改固件、不下载、不改密码
只用 USB 往设备里写一个 0 字节文件 /tmp/.adb_auth_verified
adbd 看到这个文件就认为"已经认证过"，直接给 root shell
```

代价是**一次性的**：`/tmp` 是 tmpfs，重启即失效，每次重启后要重新写。

## 二、原理

设备的 MTP 服务（`/usr/bin/mtp-server`）以 **root** 运行，把 `/userdisk` 当存储根目录。
它在接收发送对象（SendObject）时，用的是 MTP 协议里的 **`ORIGINAL_NAME`** 字段来拼真实路径，
并且没有做 `..` 过滤 → 路径穿越 → 以 root 身份写任意文件。

关键点：

| 字段 | 值 | 作用 |
|---|---|---|
| `WPD_OBJECT_PARENT_ID` | `Music` 文件夹的 object id | 让父目录看起来正常 |
| `WPD_OBJECT_NAME` | `.adb_auth_verified` | MTP 客户端里显示的名字，干净 |
| `WPD_OBJECT_ORIGINAL_NAME` | `../../../../tmp/.adb_auth_verified` | **真正被用来拼路径的字段** |
| `WPD_OBJECT_SIZE` | `0` | 空文件即可，脚本只判断存在性 |

写入后的实际路径：

```
/userdisk/Music/../../../../tmp/.adb_auth_verified
  → /tmp/.adb_auth_verified
```

（多写几层 `../` 无害，到 `/` 之后再 `..` 还是 `/`。）

## 三、操作步骤

1. **笔上开启 ADB 开关**
   设置 → 关于 → 法律监管 → 连点 7 次 → 出现"已打开 adb"提示。
   > 没有这一步 adbd 不接受连接，后面全做不了。

2. **USB 连接电脑**，笔上选"文件传输 / MTP"模式。

3. **运行解锁工具**（目前是外部脚本）

   ```powershell
   python unlock_mtp.py --unlock     # 或仓库里的 unlock.cmd
   ```

   成功输出：

   ```json
   {"status":"unlocked","identity":"uid=0(root) gid=0(root) groups=0(root)",
    "proof":"-rw-rw-r-- 1 root root 0 ... /tmp/.adb_auth_verified",
    "scope":"temporary marker only; firmware and password unchanged"}
   ```

4. **进入设备**

   ```bash
   adb -d shell        # 直接就是 uid=0(root)
   ```

## 四、本机验证结果（A7 Pro / RV1106 / YODPA7-2）

为了不改变鉴权状态，验证时**没有**写 `.adb_auth_verified`，而是写了一个无害的探测文件：

```
CreateObjectWithPropertiesAndData hr = 0x0
commit ok
/tmp/mtp_probe_1795526701:  -rw-rw-r-- 1 root root 0 Nov 24 21:25 /tmp/mtp_probe_1795526701
/userdisk/Music/mtp_probe_…:  MISSING
/userdisk/mtp_probe_…:        MISSING
```

结论：

- ✅ 文件确实逃出了 MTP 存储根 `/userdisk`，落在 `/tmp`
- ✅ 属主是 `root`（MTP 服务以 root 运行）
- ✅ 探测文件已清理，`/tmp/.adb_auth_verified` 与 root 状态未受影响
- ⏳ 未验证：重启后是否确实失效（`/tmp` 为 tmpfs，理论上必然失效）

设备侧事实（`adb shell` 实测）：

```
uid=0(root)
tmpfs on /tmp type tmpfs (rw,relatime,size=46196k)
/dev/mmcblk0p12 on /userdisk type ext4 (rw)
/usr/bin/mtp-server  pid=2205  root
strings /usr/bin/mtp-server → /userdisk、/media/、basename（无 .. 过滤迹象）
```

## 五、和固件改写方案的关系

| | MTP 路径穿越 | 固件改写（8 步） |
|---|---|---|
| 需要下载 1 GB 包 | 否 | 是 |
| 需要网络 / 抓包 | 否 | 是 |
| 改动设备 | 只写 `/tmp` 一个空文件 | 改 rootfs 里的密码哈希 |
| 效果 | 临时 root ADB，重启失效 | 永久（密码已变） |
| 失败风险 | 极低 | 刷坏系统需要回灌原包 |
| 适用 | 新版系统（HTTP 被堵） | 能抓包的版本 |

两者可以叠加：**先用 MTP 拿到 root ADB，再做持久化**。持久化的候选路径：

- 用 root 直接 `dd` 把改好的 rootfs 写回分区（`/` 是 erofs 只读挂载，但块设备可写）
- 找到开机自启且可写的目录（如 `/userdata` 下的服务配置）挂一个 `touch /tmp/.adb_auth_verified` 的钩子
- 仍然走 OTA 回灌（最稳妥，有原包可回滚）

## 六、集成方案（待实现）

外部脚本依赖 Python + comtypes，不适合直接塞进 Flutter。三个候选：

| 方案 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| **A（推荐）** | CI 里用 C# 写 `mtp_unlock.exe`（WPD COM 互操作），Flutter 调用 | 用户零依赖 | CI 多一步编译，多一个产物文件 |
| B | 打包 Python 脚本 + comtypes wheel，调用本机 Python | 改动最小 | 用户没装 Python 就用不了 |
| C | Dart FFI 直接调 WPD 的 COM vtable | 单文件 | 工作量大且易崩（手工声明接口曾导致进程访问违例 `0xC0000005`） |

方案 A 的落地清单：

```
lib/core/mtp_unlock.dart        ← 定位 exe、执行、解析 JSON 输出
tools/mtp_unlock/MtpUnlock.cs   ← 照抄已验证的 WPD 调用序列
.github/workflows/build.yml     ← 增加 csc 编译步骤，产物一起打包
lib/main.dart                   ← 新增按钮「MTP 一键开 ADB（临时）」+ 7 次点击说明
```

界面位置：放在第 1 步之前，作为「前置：没有 ADB 时的临时入口」。

## 七、注意事项

- 这是**一次性**的：重启后要重新执行，不要指望它长期有效
- 写入目标务必只有 `/tmp/.adb_auth_verified`，不要用这个洞去写系统分区（写错一个字节就可能起不来）
- 设备需要先有那 7 次点击的 ADB 开关；没有这个开关的机型，此方案不适用
- 仅对自己的设备使用
