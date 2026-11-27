# 防格机卫士 (antiwipe)

作者：风花雪月

KernelSU / ReSukiSU 模块：在格机（wipe / 强重启 / 删数据）脚本真正执行前把它掐死。

纯用户态实现，**不写任何分区**，不替换系统文件，只做监测与终止。

## 特性

| 能力 | 说明 |
|---|---|
| 执行即杀（静态预检） | `sh` 脚本一 exec 就先读内容，命中危险命令行立刻终止，第一条命令都跑不到 |
| 命令级拦截 | 内核 proc connector（exec 事件）+ 250ms `/proc` 轮询双通道，命令一出现就匹配 |
| 脚本树终止 | 命中后连同子进程、包装 shell 一起杀，防止换 shell 继续跑 |
| 块设备句柄监控 | 非系统进程持有 `/dev/block*` 可写句柄时直接杀（抓原生二进制擦除） |
| 零落盘断电层（v1.1） | 独立线程每 100ms 扫一次块设备句柄，`open()` 后 **50–90ms** 内 SIGSTOP 冻结（实测 49/63/66/75/88ms），刷盘后强制关机，把「首次写入已落盘」的窗口压到几乎为零；默认关闭，`POWEROFF=1` 才启用 |
| 用户存储保护 | `/sdcard`、`/storage/emulated/*`、`/data/user/*` 下的删除一律拦，只放行 `cache`/`code_cache`/`.thumbnails`/`tmp` |
| 运行时随机路径 | 守卫从 `/data/adb/antiwipe/run/.g<随机>` 运行，按模块目录匹配的杀进程脚本抓不到 |
| 三进程互拉 | main / keeper / watchdog 互相看护，单杀、双杀 2–4 秒内自愈；忽略 TERM/INT/HUP/QUIT/TSTP |
| web 控制台看护 | 内置网页控制台（仅 127.0.0.1 + 令牌鉴权），进程掉了守卫自动拉起 |
| sysrq 加固 | 定时把 `/proc/sys/kernel/sysrq` 写回 0，挡住 `echo b > sysrq-trigger` 强重启 |
| 设备管理器监控 | 新增设备管理器自动移除（白名单可配） |

## 安装

1. 下载 `防格机卫士-v3.0.zip`
2. 用 KernelSU / ReSukiSU 管理器「从本地安装」→ 重启
3. 首次启动会安装弹窗组件 `com.dsh.antiwipe.alerts`（不需要可自行卸载，守卫仍会拦，只是没弹窗）

卸载：管理器里移除模块并重启；运行数据在 `/data/adb/antiwipe`，卸载脚本会清掉运行目录。

## 使用

**管理器内**：模块卡片 →「操作」按钮，显示三进程状态 + 最近 8 条事件，并请求重启守卫。

**网页控制台**：模块卡片 →「WebUI」（管理器内置 WebView 打开，不跳浏览器）。
地址形如 `http://127.0.0.1:8099/?tk=<令牌>`，令牌在 `/data/adb/antiwipe/web.token`。

## 配置

`/data/adb/modules/antiwipe/config.conf`，改完点「操作」或重启模块生效；网页 `/config` 页可直接编辑。

| 键 | 默认 | 说明 |
|---|---|---|
| `POLL_MS` | 250 | `/proc` 轮询间隔（50–2000 ms） |
| `KILL` | 1 | 1=击杀命中进程，0=只记录 |
| `POPUP` | 1 | 命中后是否弹窗 |
| `AUTO_REMOVE_ADMIN` | 1 | 是否自动移除新增设备管理器 |
| `ADMIN_WHITELIST` | `com.android.*,...` | 设备管理器白名单，支持 `*` |
| `PROTECT_SD` | 1 | 用户存储删除保护 |
| `SCAN_SCRIPTS` | 1 | 脚本静态预检；设 0 则退回纯命令级拦截 |
| `BLOCK_FD` | 1 | 块设备可写句柄监控 |
| `BLOCK_FD_MS` | 100 | 块设备句柄扫描间隔（20–1000 ms），独立线程 |
| `POWEROFF` | 0 | 零落盘断电层：命中可写块设备句柄后冻结→刷盘→强制关机 |
| `POWEROFF_HOLD` | 0 | 1=只冻结不断电（调试用） |
| `POWEROFF_DRYRUN` | 0 | 1=走完整流程但跳过真正的关机命令，用来验证链路；确认无误再改成 0 上真机 |
| `SAFE_UPTIME` | 180 | 开机安全期（秒），这段时间内只杀进程不断电 |
| `WEB_PORT` | 8099 | 网页端口，0=关闭 |

## 检测规则

`SYS_REQ`（sysrq/内核请求）、`PANIC`、`WIPE_BCAST`、`REBOOT`、`RM_RF`（递归删危险目录）、`RM_CWD`、`FIND_DEL`、`MV_DATA`、`PM_CLEAR`、`BLOCK_WRITE`（dd/cp/cat 写块设备）、`MKFS`、`IPT_POLICY`、`SHRED`、`UMOUNT`、`BLOCK_FD`（持有可写块设备句柄）。

危险目标：系统/数据/启动关键目录、块设备、sysrq、恢复出厂相关命令；用户存储按前缀判定。

## 验证

`test/` 里是自测工具，全部使用假路径/假程序，不会真破坏：

```sh
su -c 'sh /data/local/tmp/伪格机.sh'        # 13 步演示：一 exec 就被终止
su -c 'sh /data/local/tmp/伪格机-对照.sh'   # 对照：应完整跑完（证明不误杀）
su -c 'sh /data/local/tmp/全杀模块.sh'      # 连杀 3 轮，看守卫能不能自己回来
```

预期：

- 伪格机 → 终端会话直接被终止，`/data/adb/antiwipe/events.log` 出现 `[拦截] ... 脚本预检: ...`
- 对照 → 全部打印完，日志无新拦截
- 全杀 → 守卫跑在随机路径，按模块目录杀不到；web 被杀后 5 秒内被拉回

## 已知限制（请务必阅读）

1. **用户态实现，不是内核 LSM**。能挡住绝大多数脚本化格机，挡不住内核级/驱动级破坏。
2. **三个角色被同时 `kill -9` 就失效**，直到重启或手动 `sh service.sh`。脚本化的“连杀”能绕过互拉。
3. 静态预检只读脚本文件（上限 1 MB），超大脚本/二进制脚本不预检。
4. 原生二进制直接 `open()` 块设备写：只有在**打开后仍持有写句柄**时才会被抓。v1.1 把扫描改到独立线程（默认 100ms），实测 `open()` 到 SIGSTOP 冻结为 50–90ms；`POWEROFF=1` 时冻结后立刻强制关机，把落盘窗口压到最小。但 `open→write→close` 在 50ms 内完成的极端情况仍然抓不到，这是用户态方案的天花板（要彻底解决只能上内核 KPM/LSM）。
5. **断电层是用「可能丢一点未刷盘数据」换「不出事」**：强制关机前会 `sync` 并等脏页回落（最多约 2 秒），但内核/厂商驱动的缓存不保证全刷干净。开启前请确认能接受这个取舍，建议先用 `POWEROFF_DRYRUN=1` 验证。
6. 不做数据恢复：已删除/已清空的内容无法找回。
7. 部分 ROM 的 proc connector 不可用时会自动退回纯轮询（延迟约 250 ms）。
8. 弹窗依赖 `alerts.apk`，卸载后仍有拦截与日志，只是没有弹窗。

## 构建

```sh
# Termux：pkg install clang
sh build.sh
```

产出 `module/bin/guard`、`module/bin/web`（aarch64, Android 24+）。

## 目录结构

```
module/         打包进 zip 的模块内容（module.prop / *.sh / bin / webroot / alerts.apk）
src/            源码（guard.c / web.c）
test/           自测脚本（伪格机、对照、全杀）
dist/           发布 zip
```

## 零落盘断电层怎么验证（v1.1）

```sh
# 1) 先演练：冻结+刷盘，但不真关机
#    把 POWEROFF=1、POWEROFF_DRYRUN=1 写进 config.conf，重启守卫
#    然后跑一个持有可写块设备句柄的进程（test/fdprobe.c 是样例）
#    预期日志：[发现] BLOCK_FD → [冻结] SIGSTOP → [断电演练] → [拦截]

# 2) 确认演练正常后，POWEROFF_DRYRUN=0 再测一次真实断电（手机直接关机，别慌）
```

实测（本机，Android 15 / 6.6.127 内核）：

- 可写句柄 `open()` → SIGSTOP 冻结：49 / 63 / 66 / 75 / 88 ms
- 只读句柄：不误杀，进程正常跑完 4 秒
- 冻结 → 刷盘 → 断电指令：约 450ms（刷盘占大头，期间进程是 STOP 状态写不了）

## 版本

1.1（versionCode 2）：新增零落盘断电层（独立 100ms 扫描线程 + 冻结 + 刷盘 + 强制关机），断电层默认关闭
1.0（versionCode 1）：首发

## 许可

MIT

## 免责

本模块会主动终止它判定为危险进程的进程，包括你自己执行的脚本。请在理解规则后再安装；因误杀或绕过造成的任何后果由使用者自负。
