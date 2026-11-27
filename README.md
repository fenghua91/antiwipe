# 防格机卫士 (antiwipe)

作者：风花雪月

KernelSU / ReSukiSU 模块：在格机（wipe / 强重启 / 删数据）脚本真正执行前把它掐死。

纯用户态实现，**不写任何分区**，不替换系统文件，只做监测与终止。

## 下载

- 最新 v1.2.2：<https://github.com/fenghua91/antiwipe/releases/download/v1.2.2/antiwipe-v1.2.2.zip>
- v1.2.1（stdin/管道预检 + MV 子路径）：<https://github.com/fenghua91/antiwipe/releases/download/v1.2.1/antiwipe-v1.2.1.zip>
- v1.2：<https://github.com/fenghua91/antiwipe/releases/download/v1.2/antiwipe-v1.2.zip>
- v1.1：<https://github.com/fenghua91/antiwipe/releases/download/v1.1/antiwipe-v1.1.zip>（md5 `7f087e1a29011bc812152cefd58118ec`）
- 初版 v1.0（无断电层）：<https://github.com/fenghua91/antiwipe/releases/download/v1.0/antiwipe-v1.0.zip>（md5 `c1da22051035c29ea0f50a462ca96505`）
- 全部版本：<https://github.com/fenghua91/antiwipe/releases>

## 特性

| 能力 | 说明 |
|---|---|
| 执行即杀（静态预检） | `sh` 脚本一 exec 就先读内容，命中危险命令行立刻终止，第一条命令都跑不到 |
| stdin / 管道预检（v1.2） | `sh < 脚本`、`cat 脚本 | sh` 这类 argv 里没有路径的执行方式：读 stdin 指向的文件、或顺管道写端/父进程命令行找回源文件再扫；base64 编码的载荷会先解码再匹配 |
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

## 架构

一句话：**没有内核钩子，全部在用户态做「采集 → 判定 → 处置」**，用多通道采集把检测窗口压到几十毫秒，再用「断电兜底」把最后那点落盘窗口抹掉。

```
                  采集层                                  判定层                 处置层
  ┌────────────────────────────────────────┐
  │ 1. proc connector（NETLINK_CONNECTOR）  │──┐
  │    内核 exec 事件，命令一 exec 就推送    │  │
  │ 2. /proc 轮询（POLL_MS=250）            │  │      match_cmd()
  │    兜住 connector 漏掉/被屏蔽的进程      │──┼──►  14 条规则匹配  ──┬──► 杀进程树（父+子+包装 shell）
  │ 3. 脚本预检（SCAN_SCRIPTS=1）           │  │      SYS_REQ/PANIC/   │     + 弹窗 + events.log
  │    sh/bash <path> 先读脚本文本再放行     │  │      RM_RF/BLOCK_FD…  │
  │ 4. 块设备句柄扫描（fd_loop，100ms）      │──┘                      └──► 可写 /dev/block 句柄？
  │    扫 /proc/*/fd + fdinfo 写标志         │                             → SIGSTOP → sync → 断电
  └────────────────────────────────────────┘
```

### 三层职责

| 层 | 做什么 | 关键实现 |
|---|---|---|
| 采集层 | 拿「谁在 exec、谁开着块设备」 | proc connector 主通道 + 250ms `/proc` 轮询兜底 + 脚本预检提前读内容 + 独立线程 100ms 扫 fd |
| 判定层 | 把命令行/路径/句柄归一成可控字符串再匹配 | `match_cmd()` 按规则表逐条匹配，路径先做 `..`／引号／空白归一；`exe_trusted()` 白名单放行系统与模块自身 |
| 处置层 | 终止与兜底 | 命中 exec 类规则 → 杀整棵进程树并弹窗；命中 `BLOCK_FD` → SIGSTOP 冻结后按 `POWEROFF` 配置刷盘断电 |

### 进程模型

```
/data/adb/antiwipe/run/.g<随机串>        ← 主机（main），监听 + 轮询 + 规则匹配
        ├── keeper                        ← 看护主机，主机死则拉起
        └── watchdog                      ← 看护 keeper，双杀 2–4 秒自愈
```

- 三者互相 `waitpid` + 心跳，忽略 `TERM/INT/HUP/QUIT/TSTP`，只认 `SIGKILL`
- 二进制跑在随机文件名下（`.g<19 位随机>`），按模块目录名写死的杀进程脚本抓不到
- 配置、日志、令牌都在 `/data/adb/antiwipe/`，与模块目录分离，升级模块不丢配置

### 为什么是用户态，而不是 KPM / 内核钩子

参考实现（失序 awblock）走 KPatch-Next，在 `blkdev_write_iter`、`blkdev_common_ioctl` 上直接拒绝写入——**零窗口**，理论上更硬。代价是依赖 KPatch-Next 内核补丁（`kpatch hello` 需返回 `hello2026`），测试机内核 `6.6.127-android15-8-g24b70dd1cb81` 没有该模块，装了也不生效。

本模块的选择是：**不碰分区、不碰内核**，用「多通道采集 + 快速冻结 + 断电兜底」逼近同样的效果：

| 方案 | 拦截点 | 落盘窗口 | 依赖 |
|---|---|---|---|
| 失序 awblock（KPM） | 块设备写入口 | 0 | KPatch-Next 内核补丁 |
| 本模块（用户态） | exec 前 / fd 持有期 | 50–90ms（实测 49–88ms），断电层再兜底 | 只要 root + KernelSU |

窗口期的取舍写在「已知限制」里：`POWEROFF=1` 时窗口内的首次写入可能已经落盘，因此强制断电会丢未刷盘的 `/data` 数据——这是明确告知的代价，默认关闭。

## 安装

1. 下载 `antiwipe-v1.1.zip`（见上方「下载」）
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
| `SCAN_STDIN` | 1 | stdin 预检开关：`sh < 文件` 等不把路径放 argv 的写法也检查 |
| `STRICT_PIPE` | 0 | 管道来源查不回来（curl 管道、编码载荷已跑完）时直接拦；默认 0 只放行 |
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

### 一键自检（推荐先跑这个）

```sh
su -c "sh /storage/emulated/0/Download/antiwipe/test/自检.sh"
```

脚本把每个用例放在**孤儿进程**里执行（父进程立刻退出、被 init 收养），所以守卫「连坐脚本树」时不会把自检脚本一起杀掉。所有破坏性动作只指向它自建的探针（`/data/adb/aw_selftest_*`、`/dev/block/antiwipe_selftest0`），跑完自动清理，不碰真实数据。

覆盖 9 项：服务存活 / 直接执行 / `sh < 文件` / `cat 文件 | sh`（竞态项会标 WARN）/ 写块设备 / 递归删 /data/adb/aw_selftest_子目录 / 搬走子目录 / `find -delete` / 正常脚本零误报。全部通过输出 `PASS=8 FAIL=0 WARN=1`。

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


> **管道喂入的小脚本仍有竞态（v1.2 起）**：`cat tiny.sh | sh`、`base64 -w0 x | base64 -d | sh` 这类内容在管道里、argv 里没有路径，守卫只能顺管道写端去找源文件；写端几百字节就干完、几十毫秒内退场时大概率找不到，脚本正文因此漏检。**正文漏检不等于放行**：脚本里真正执行的写块设备命令、递归删数据命令、重启命令在 exec 那一刻仍会被命令级规则当场掐掉（已实测：base64 编码管道喂入的写块设备命令仍被判 BLOCK_WRITE 击杀）。想更严可把 `STRICT_PIPE=1`，代价是 `curl | sh` 这类来源不可读的安装脚本也会被拦。

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

实测（Android 15 / 6.6.127 内核）：

- 可写句柄 `open()` → SIGSTOP 冻结：49 / 63 / 66 / 75 / 88 ms
- 只读句柄：不误杀，进程正常跑完 4 秒
- 冻结 → 刷盘 → 断电指令：约 450ms（刷盘占大头，期间进程是 STOP 状态写不了）

## 版本
- **v1.2.2**：`guard.pid` 被安装器/清理脚本删掉后自动重建（否则外部看门狗和自检会误判"没在跑"）；`service.sh`/`post-fs-data.sh` 改用 `setsid` 启动，脚本退出不再带走主进程；自检脚本修 `printf` 以 `-` 开头格式串的崩溃、并在 pid 文件缺失时按 cmdline 找主进程
- **v1.2.1**：`MV_DATA` 从「只认三个精确路径」改成「受保护目录的任意子路径」——把受保护目录里的内容 `mv ` 走现在会被拦（往 /data/adb 里搬仍放行，不影响装模块）
- **v1.2**：新增 stdin / 管道预检（`sh < 文件`、`cat 文件 | sh`、base64 解码链、父进程命令行回溯），新增 `SCAN_STDIN` / `STRICT_PIPE` 配置；命令级规则与块设备监控不变

1.1（versionCode 2）：新增零落盘断电层（独立 100ms 扫描线程 + 冻结 + 刷盘 + 强制关机），断电层默认关闭
1.0（versionCode 1）：首发

## 许可

MIT

## 免责

本模块会主动终止它判定为危险进程的进程，包括你自己执行的脚本。请在理解规则后再安装；因误杀或绕过造成的任何后果由使用者自负。
