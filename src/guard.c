// 防格机卫士 guard v1.1
// 主进程：扫描 /proc 拦截毁机命令；keeper 进程(-k)：主进程被杀后自动拉起，反之亦然。
// 命中后：SIGKILL 进程（可连带父 shell）+ 弹窗 + 日志。
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/reboot.h>

// 运行目录可用 AW_HOME 覆盖（用于测试，避免和正式实例抢锁）
// 运行目录；AW_HOME 可覆盖（测试用，避免和正式实例抢锁）
static char g_moddir_buf[256] = "/data/adb/antiwipe";
static char g_conf_buf[300] = "/data/adb/antiwipe/config.conf";
static char g_logf_buf[300] = "/data/adb/antiwipe/events.log";
static char g_pidf_buf[300] = "/data/adb/antiwipe/guard.pid";
static char g_lockf_buf[300] = "/data/adb/antiwipe/keeper.lock";
static char g_lockw_buf[300] = "/data/adb/antiwipe/watchdog.lock";
static char g_lockm_buf[300] = "/data/adb/antiwipe/guard.lock";
static const char *g_moddir = g_moddir_buf;
static const char *g_conf = g_conf_buf;
static const char *g_logf = g_logf_buf;
static const char *g_pidf = g_pidf_buf;
static const char *g_lockf = g_lockf_buf;
static const char *g_lockw = g_lockw_buf;
static const char *g_lockm = g_lockm_buf;
#define MODDIR ((char *)g_moddir)
#define CONF g_conf
#define CONF2 "/data/adb/modules/antiwipe/config.conf"
#define LOGF g_logf
#define PIDF g_pidf
#define LOCKF g_lockf
#define LOCKW g_lockw
#define LOCKM g_lockm
#define ALERTPKG "com.dsh.antiwipe.alerts/.AlertActivity"
#define LOGMAX (512 * 1024)
#define PIDBITS (1 << 20)

static int poll_ms = 250;
static int kill_enabled = 1;
static int auto_rm_admin = 1;
static int popup_enabled = 1;
static int protect_sd = 1;
static int scan_scripts = 1;
static int scan_stdin = 1;   // sh < file / cat file | sh 也做预检
static int strict_pipe = 0;  // 管道源不可读时直接拦（默认只放行不拦）
static char whitelist[1024] = "com.android.*,com.google.*,com.vivo.*,com.qualcomm.*,com.mediatek.*";
static char selfpath[512];
static time_t last_popup = 0;
static int is_keeper = 0;
static int is_watch = 0;
static int block_fd = 1;
static int block_fd_ms = 100;
static int web_port = 8099;
static int poweroff_react = 0;   // POWEROFF=1 时才真的关断
static int safe_uptime = 180;    // 开机这么久之后才认定“这是格机”
static int poweroff_hold = 0;    // 只冻结不断电（调试）
static int poweroff_dryrun = 0;  // 断电演练：走完整流程但不真的关机
static unsigned long fdpass = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void logline(const char *fmt, ...) {
    pthread_mutex_lock(&lock);
    FILE *f = fopen(LOGF, "a");
    if (!f) return;
    time_t t = time(NULL);
    struct tm tmv; localtime_r(&t, &tmv);
    struct timespec tsp; clock_gettime(CLOCK_REALTIME, &tsp);
    char ts[40]; strftime(ts, sizeof(ts), "%m-%d %H:%M:%S", &tmv);
    fprintf(f, "%s.%03d ", ts, (int)(tsp.tv_nsec / 1000000));
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fprintf(f, "\n"); fclose(f);
    struct stat st;
    if (stat(LOGF, &st) == 0 && st.st_size > LOGMAX) {
        char bak[360];
        snprintf(bak, sizeof(bak), "%s.1", LOGF);
        rename(LOGF, bak);
        f = fopen(LOGF, "w"); if (f) fclose(f);
    }
    pthread_mutex_unlock(&lock);
}

static void load_config(void) {
    FILE *f = fopen(CONF, "r");
    if (!f) f = fopen(CONF2, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, '='); if (!p) continue;
        *p = 0;
        char *k = line, *v = p + 1;
        while (*k == ' ' || *k == '\t') k++;
        while (*v == ' ' || *v == '\t') v++;
        char *e = v + strlen(v);
        while (e > v && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ')) *--e = 0;
        if (!strcmp(k, "POLL_MS")) poll_ms = atoi(v);
        else if (!strcmp(k, "KILL")) kill_enabled = atoi(v);
        else if (!strcmp(k, "AUTO_REMOVE_ADMIN")) auto_rm_admin = atoi(v);
        else if (!strcmp(k, "POPUP")) popup_enabled = atoi(v);
        else if (!strcmp(k, "PROTECT_SD")) protect_sd = atoi(v);
        else if (!strcmp(k, "SCAN_SCRIPTS")) scan_scripts = atoi(v);
        else if (!strcmp(k, "SCAN_STDIN")) scan_stdin = atoi(v);
        else if (!strcmp(k, "STRICT_PIPE")) strict_pipe = atoi(v);
        else if (!strcmp(k, "BLOCK_FD")) block_fd = atoi(v);
        else if (!strcmp(k, "BLOCK_FD_MS")) block_fd_ms = atoi(v);
        else if (!strcmp(k, "WEB_PORT")) web_port = atoi(v);
        else if (!strcmp(k, "POWEROFF")) poweroff_react = atoi(v);
        else if (!strcmp(k, "POWEROFF_HOLD")) poweroff_hold = atoi(v);
        else if (!strcmp(k, "POWEROFF_DRYRUN")) poweroff_dryrun = atoi(v);
        else if (!strcmp(k, "SAFE_UPTIME")) safe_uptime = atoi(v);
        else if (!strcmp(k, "ADMIN_WHITELIST")) { strncpy(whitelist, v, sizeof(whitelist)-1); whitelist[sizeof(whitelist)-1] = 0; }
    }
    fclose(f);
    if (block_fd_ms < 20) block_fd_ms = 20;
    if (block_fd_ms > 1000) block_fd_ms = 1000;
    if (poll_ms < 50) poll_ms = 50;
    if (poll_ms > 2000) poll_ms = 2000;
}

static int wl_match(const char *pkg) {
    char buf[1024]; strncpy(buf, whitelist, sizeof(buf)-1); buf[sizeof(buf)-1] = 0;
    char *save = NULL;
    for (char *t = strtok_r(buf, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        size_t n = strlen(t);
        if (n > 1 && t[n-1] == '*') { if (!strncmp(pkg, t, n-1)) return 1; }
        else if (!strcmp(pkg, t)) return 1;
    }
    return 0;
}

static const char *base(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static int sd_subpath_danger(const char *t) {
    static const char *sp[] = {"/sdcard/", "/storage/emulated/0/", "/storage/emulated/",
                               "/storage/self/primary/", "/mnt/sdcard/", "/mnt/media_rw/",
                               "/data/media/", "/data/user/", NULL};
    for (int i = 0; sp[i]; i++) {
        size_t n = strlen(sp[i]);
        if (strncmp(t, sp[i], n)) continue;
        if (!t[n]) return 0;
        size_t L = strlen(t);
        while (L > 1 && t[L-1] == '/') L--;
        const char *ls = t + L;
        while (ls > t && ls[-1] != '/') ls--;
        size_t ln = (size_t)(t + L - ls);
        if ((ln == 5 && !strncmp(ls, "cache", 5)) ||
            (ln == 10 && !strncmp(ls, "code_cache", 10)) ||
            (ln == 11 && !strncmp(ls, ".thumbnails", 11)) ||
            (ln == 3 && !strncmp(ls, "tmp", 3))) return 0;
        return 1;
    }
    return 0;
}

static int blk_target(const char *p) {
    if (p[0] != '/') return 0;
    return !strncmp(p, "/dev/block", 10) || !strncmp(p, "/dev/disk", 9) ||
           !strncmp(p, "/dev/mmcblk", 11) || !strncmp(p, "/dev/sd", 7) ||
           !strncmp(p, "/dev/ufs", 8) || !strncmp(p, "/dev/nvme", 9);
}

static int danger_target(const char *t) {
    if (!strncmp(t, "/data/local/tmp", 15) && (t[15] == 0 || t[15] == '/')) return 0;
    if (protect_sd && sd_subpath_danger(t)) return 1;
    static const char *exact[] = {
        "/", "/system", "/vendor", "/product", "/odm", "/persist", "/boot",
        "/recovery", "/frp", "/nvdata", "/nvram", "/cache", "/metadata",
        "/data", "/data/app", "/data/system", "/data/misc", "/data/adb",
        "/data/data", "/data/local", "/sdcard", "/storage", "/storage/emulated",
        "/storage/emulated/0", "/mnt", "/dev", "/dev/input", "/dev/block",
        "/boot.img", "/recovery.img", "/param", "/dalvik-cache", "/data/log", NULL
    };
    for (int i = 0; exact[i]; i++) if (!strcmp(t, exact[i])) return 1;
    if (!strcmp(t, "*") || !strcmp(t, "/*") || !strcmp(t, "/data/*") ||
        !strcmp(t, "/sdcard/*") || !strcmp(t, "/storage/*") ||
        !strcmp(t, "/storage/emulated/0/*") || !strcmp(t, "/storage/emulated/*")) return 1;
    if (!strncmp(t, "/system/", 8) || !strncmp(t, "/vendor/", 8) ||
        !strncmp(t, "/product/", 9)) return 1;
    if (!strncmp(t, "/dev/", 5)) return 1;
    if (!strncmp(t, "/mnt/", 5)) return 1;
    if (!strncmp(t, "/.", 2)) return 1;
    if (!strncmp(t, "/data/adb/", 10) || !strncmp(t, "/data/system/", 13) ||
        !strncmp(t, "/data/app/", 10) || !strncmp(t, "/data/misc/", 11)) return 1;
    return 0;
}

static int is_sep(const char *t) {
    return !strcmp(t, "&&") || !strcmp(t, "||") || !strcmp(t, ";") ||
           !strcmp(t, "|") || !strcmp(t, "&") || !strcmp(t, "then") ||
           !strcmp(t, "do") || !strcmp(t, "done") || !strcmp(t, "else") ||
           !strcmp(t, "fi") || !strcmp(t, "esac");
}

static int is_rm(const char *t) { return !strcmp(t, "rm") || !strcmp(t, "/rm"); }
static int at_cmdpos(char **tok, int i) {
    if (i == 0) return 1;
    const char *p = tok[i-1];
    if (is_sep(p)) return 1;
    if (!strcmp(p, "exec") || !strcmp(p, "env") || !strcmp(p, "busybox") ||
        !strcmp(p, "nohup") || !strcmp(p, "-c") || !strcmp(p, "xargs") ||
        !strcmp(p, "timeout") || !strcmp(p, "watch") || !strcmp(p, "nice") ||
        !strcmp(p, "ionice") || !strcmp(p, "chrt") || !strcmp(p, "stdbuf") ||
        !strcmp(p, "command") || !strcmp(p, "eval")) return 1;
    return 0;
}

static int is_tool(const char *t, const char *name) { return !strcmp(base(t), name); }

static int cwd_danger(pid_t pid) {
    char p[64], buf[512];
    snprintf(p, sizeof(p), "/proc/%d/cwd", pid);
    ssize_t n = readlink(p, buf, sizeof(buf)-1);
    if (n <= 0) return 0;
    buf[n] = 0;
    size_t L = strlen(buf);
    while (L > 1 && buf[L-1] == '/') buf[--L] = 0;
    if (!strncmp(buf, "/data/local/tmp", 15)) return 0;
    static const char *ex[] = {"/", "/data", "/sdcard", "/storage",
        "/storage/emulated/0", "/system", "/vendor", "/mnt", "/data/adb",
        "/data/system", NULL};
    for (int i = 0; ex[i]; i++) if (!strcmp(buf, ex[i])) return 1;
    return 0;
}

// ---- 断电反应层：块设备被写/丢块时，冻结进程 + 关页面缓存 + 强制断电 ----
static time_t boot_time = 0;

static unsigned long long proc_uptime(void) {
    FILE *f = fopen("/proc/uptime", "r");
    if (!f) return 0;
    double up = 0;
    if (fscanf(f, "%lf", &up) != 1) up = 0;
    fclose(f);
    return (unsigned long long)up;
}

// 关断前尽量把脏页刷下去，减少“断电导致丢数据”的代价
static void sync_before_off(void) {
    sync();
    for (int i = 0; i < 200; i++) {
        FILE *f = fopen("/proc/meminfo", "r");
        if (!f) break;
        char line[128]; long dirty = 0, wb = 0;
        while (fgets(line, sizeof(line), f)) {
            if (!strncmp(line, "Dirty:", 6)) sscanf(line + 6, "%ld", &dirty);
            else if (!strncmp(line, "Writeback:", 10)) sscanf(line + 10, "%ld", &wb);
        }
        fclose(f);
        if (dirty <= 64 && wb <= 64) break;
        usleep(10000);
    }
}

static void do_poweroff(const char *why) {
    if (poweroff_dryrun) {
        logline("[断电演练] 命中 %s，真实场景会在此刷盘并强制关机（演练不执行）", why);
        sync_before_off();
        logline("[断电演练] 刷盘完成，退出演练");
        return;
    }
    logline("[断电] 触发强制关机: %s", why);
    sync_before_off();
    unsigned long long up = proc_uptime();
    // sysrq 在开机 60s 后才可用，且需要 /proc/sysrq-trigger 可写；不行就走 init 的 normal shutdown
    const char *cmdline = (up > 60 && access("/proc/sysrq-trigger", W_OK) == 0)
        ? "echo o > /proc/sysrq-trigger"
        : "reboot -p";
    pid_t c = fork();
    if (c == 0) {
        setsid();
        execl("/system/bin/sh", "sh", "-c", cmdline, (char *)NULL);
        _exit(1);
    }
    struct timespec ts = { 0, 600 * 1000 * 1000 };
    nanosleep(&ts, NULL);   // 给 init 600ms 反应时间
    // 兜底一：直接调 reboot(RB_POWER_OFF)，绕过 init 自己的策略
    c = fork();
    if (c == 0) {
        setsid();
        reboot(0x4321fedc);
        _exit(1);
    }
    ts.tv_sec = 2; ts.tv_nsec = 0;
    nanosleep(&ts, NULL);
    // 兜底二：走 Android 的电源服务
    c = fork();
    if (c == 0) {
        setsid();
        execl("/system/bin/svc", "svc", "power", "shutdown", (char *)NULL);
        _exit(1);
    }
    ts.tv_sec = 3; ts.tv_nsec = 0;
    nanosleep(&ts, NULL);
    logline("[断电] 关机命令未生效，继续拦截");
}


static void popup(const char *rule, const char *desc, pid_t pid);

// 危险块写入的处理：先冻住，再决定关不关机
static void react_block_write(pid_t pid, const char *desc, const char *cmd) {
    (void)cmd;
    if (pid > 1) kill(pid, SIGSTOP);
    logline("[冻结] 已 SIGSTOP pid=%d (%s)", pid, desc);
    unsigned long long up = boot_time ? (unsigned long long)(time(NULL) - boot_time) : proc_uptime();
    if (poweroff_react) {
        if (up < (unsigned long long)safe_uptime) {
            logline("[跳过断电] 开机 %llus < %ds，判定为开机期正常操作，只杀进程", up, safe_uptime);
        } else if (poweroff_hold) {
            logline("[跳过断电] POWEROFF_HOLD=1，只冻结不断电");
        } else {
            popup("POWEROFF", desc, pid);
            do_poweroff(desc);
        }
    }
    if (kill_enabled) kill(pid, SIGKILL);
    popup("BLOCK_FD", desc, pid);
}

static void popup(const char *rule, const char *desc, pid_t pid) {
    if (!popup_enabled) return;
    time_t now = time(NULL);
    pthread_mutex_lock(&lock);
    if (now - last_popup < 1) { pthread_mutex_unlock(&lock); return; }
    last_popup = now;
    pthread_mutex_unlock(&lock);
    char msg[256];
    snprintf(msg, sizeof(msg), "[%s] 已拦截 pid=%d %s", rule, pid, desc);
    for (char *p = msg; *p; p++)
        if (*p == '\'' || *p == '"' || *p == '\\' || *p == '\n' || *p == '\r') *p = ' ';
    logline("[弹窗] %s", msg);
    pid_t c = fork();
    if (c == 0) {
        setsid();
        execl("/system/bin/am", "am", "start", "-n", ALERTPKG, "--es", "msg", msg, (char *)NULL);
        logline("[弹窗] exec失败 errno=%d", errno);
        _exit(1);
    }
}

static const char *match_cmd(pid_t pid, const char *cmd, char *dbuf, size_t dn) {
    if (strstr(cmd, "sysrq-trigger")) { snprintf(dbuf, dn, "触发内核 sysrq"); return "SYS_REQ"; }
    if (strstr(cmd, "/proc/sys/kernel/panic")) { snprintf(dbuf, dn, "改 panic 参数"); return "PANIC"; }
    if (strstr(cmd, "MASTER_CLEAR") || strstr(cmd, "master_clear") || strstr(cmd, "wipe_data")) {
        snprintf(dbuf, dn, "擦除广播/恢复指令"); return "WIPE_BCAST";
    }
    {
        char t2[512];
        strncpy(t2, cmd, sizeof(t2)-1); t2[sizeof(t2)-1] = 0;
        char *sv = NULL;
        char *t2v[64]; int n2 = 0;
        for (char *t = strtok_r(t2, " \t", &sv); t && n2 < 64; t = strtok_r(NULL, " \t", &sv)) t2v[n2++] = t;
        for (int i2 = 0; i2 < n2; i2++) {
            if ((is_tool(t2v[i2], "reboot") || is_tool(t2v[i2], "poweroff") || is_tool(t2v[i2], "halt")) &&
                at_cmdpos(t2v, i2)) {
                snprintf(dbuf, dn, "强制重启/关机 (%s)", base(t2v[i2]));
                return "REBOOT";
            }
        }
    }
    char tmp[1024];
    size_t tl = 0;
    for (const char *q = cmd; *q && tl + 4 < sizeof(tmp); q++) {
        char c = *q;
        if (c == '\n' || c == '\r' || c == ';' || c == '&' || c == '|' ||
            c == '(' || c == ')' || c == '`') {
            tmp[tl++] = ' '; tmp[tl++] = ';'; tmp[tl++] = ' ';
        } else {
            tmp[tl++] = c;
        }
    }
    tmp[tl] = 0;
    char *tok[64]; int nt = 0; char *save = NULL;
    for (char *t = strtok_r(tmp, " \t", &save); t && nt < 64; t = strtok_r(NULL, " \t", &save)) tok[nt++] = t;
    if (nt == 0) return NULL;

    for (int i = 0; i < nt; i++) {
        const char *t = tok[i];
        if ((is_rm(t) || (i > 0 && is_tool(tok[i-1], "busybox") && is_tool(t, "rm"))) && at_cmdpos(tok, i)) {
            int rec = 0, target_at = -1, wildcard = 0, hasarg = 0;
            for (int j = i + 1; j < nt && j <= i + 32; j++) {
                const char *a = tok[j];
                if (is_sep(a)) break;
                if (a[0] == '-' && a[1] != '-') { if (strchr(a, 'r')) rec = 1; }
                else if (!strcmp(a, "--recursive")) rec = 1;
                else {
                    hasarg = 1;
                    if (!strcmp(a, "*") || !strcmp(a, "./*") || !strcmp(a, "/data/*")) wildcard = 1;
                    if (danger_target(a)) { target_at = j; break; }
                }
            }
            if (rec && target_at >= 0) { snprintf(dbuf, dn, "递归删除 %s", tok[target_at]); return "RM_RF"; }
            if (rec && (wildcard || !hasarg) && cwd_danger(pid)) {
                snprintf(dbuf, dn, "危险目录内 rm -rf 通配"); return "RM_CWD";
            }
        }
        if (is_tool(t, "find")) {
            int del = 0; const char *tgt = NULL;
            for (int j = i + 1; j < nt; j++) {
                if (is_sep(tok[j])) break;
                if (!strcmp(tok[j], "-delete")) del = 1;
                if (danger_target(tok[j])) tgt = tok[j];
            }
            if (del && tgt) { snprintf(dbuf, dn, "find -delete %s", tgt); return "FIND_DEL"; }
        }
        if (is_tool(t, "mv")) {
            // 只看源：把受保护目录（含所有子路径）里的东西搬走才是破坏，往 /data/adb 里搬是正常装模块
            for (int j = i + 1; j < nt; j++) {
                if (is_sep(tok[j])) break;
                if (tok[j][0] == '-') continue;
                if (danger_target(tok[j])) { snprintf(dbuf, dn, "移动 %s", tok[j]); return "MV_DATA"; }
                break;
            }
        }
        if (is_tool(t, "pm") && i + 2 < nt && !strcmp(tok[i+1], "clear")) {
            const char *pkg = tok[i+2];
            if (!wl_match(pkg)) { snprintf(dbuf, dn, "pm clear %s", pkg); return "PM_CLEAR"; }
        }
        if (is_tool(t, "dd")) {
            for (int j = i + 1; j < nt && j <= i + 32; j++) {
                if (is_sep(tok[j])) break;
                if (!strncmp(tok[j], "of=", 3) && blk_target(tok[j] + 3)) {
                    snprintf(dbuf, dn, "写块设备 %s", tok[j]); return "BLOCK_WRITE";
                }
            }
        }
        if (is_tool(t, "cp")) {
            const char *dst = NULL;
            for (int j = i + 1; j < nt && j <= i + 32; j++) {
                if (is_sep(tok[j])) break;
                if (tok[j][0] == '-') continue;
                dst = tok[j];
            }
            if (dst && blk_target(dst)) { snprintf(dbuf, dn, "拷贝到块设备 %s", dst); return "BLOCK_WRITE"; }
        }
        if (is_tool(t, "cat")) {
            for (int j = i + 1; j < nt && j <= i + 32; j++) {
                if (is_sep(tok[j])) break;
                const char *red = NULL;
                if (tok[j][0] == '>') red = tok[j] + 1;
                else if (!strcmp(tok[j], ">") && j + 1 < nt) red = tok[j+1];
                if (red && *red && blk_target(red)) { snprintf(dbuf, dn, "重定向写块设备 %s", red); return "BLOCK_WRITE"; }
            }
        }
        if ((!strncmp(base(t), "mkfs", 4) || is_tool(t, "mke2fs") || is_tool(t, "wipefs")) && at_cmdpos(tok, i)) {
            snprintf(dbuf, dn, "格式化 %s", base(t)); return "MKFS";
        }
        if (is_tool(t, "iptables") || is_tool(t, "ip6tables")) {
            for (int j = i + 1; j + 1 < nt; j++) {
                if (is_sep(tok[j])) break;
                if (!strcmp(tok[j], "-P") && (!strcmp(tok[j+1], "DROP") || (j + 2 < nt && !strcmp(tok[j+2], "DROP")))) {
                    snprintf(dbuf, dn, "防火墙默认丢弃策略"); return "IPT_POLICY";
                }
            }
        }
        if (is_tool(t, "shred")) {
            for (int j = i + 1; j < nt; j++) {
                if (is_sep(tok[j])) break;
                if (danger_target(tok[j])) { snprintf(dbuf, dn, "shred %s", tok[j]); return "SHRED"; }
            }
        }
        if (is_tool(t, "umount")) {
            for (int j = i + 1; j < nt; j++) {
                if (is_sep(tok[j])) break;
                if (!strcmp(tok[j], "/data") || !strcmp(tok[j], "/system") || !strcmp(tok[j], "/vendor") ||
                    !strcmp(tok[j], "/sdcard") || !strcmp(tok[j], "/storage") || !strcmp(tok[j], "/mnt") ||
                    !strncmp(tok[j], "/mnt/", 5) || !strncmp(tok[j], "/system/", 8) ||
                    !strncmp(tok[j], "/vendor/", 8)) {
                    snprintf(dbuf, dn, "卸载 %s", tok[j]); return "UMOUNT";
                }
            }
        }
    }
    return NULL;
}

static unsigned char seen[PIDBITS / 8];
static int pass = 0;

static pid_t get_ppid(pid_t pid) {
    char p[64], buf[512];
    snprintf(p, sizeof(p), "/proc/%d/stat", pid);
    FILE *f = fopen(p, "r"); if (!f) return 0;
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);
    char *q = strrchr(buf, ')'); if (!q) return 0;
    int ppid = 0;
    sscanf(q + 1, " %*c %d", &ppid);
    return (pid_t)ppid;
}

static void read_cmdline(pid_t pid, char *out, size_t n) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/cmdline", pid);
    out[0] = 0;
    FILE *f = fopen(p, "r"); if (!f) return;
    size_t r = fread(out, 1, n - 1, f);
    fclose(f);
    out[r] = 0;
    for (size_t i = 0; i < r; i++) if (out[i] == 0 || out[i] == '\n' || out[i] == '\r') out[i] = ' ';
}

// 命中后：杀进程；若父进程是 shell，一并杀掉（干掉循环驱动脚本）
static int shell_kind(pid_t p, char *out, size_t on) {
    char cmd[512];
    read_cmdline(p, cmd, sizeof(cmd));
    if (!cmd[0]) return 0;
    char tmp[512];
    strncpy(tmp, cmd, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = 0;
    char *tok[16]; int nt = 0; char *sv = NULL;
    for (char *t = strtok_r(tmp, " \t", &sv); t && nt < 16; t = strtok_r(NULL, " \t", &sv)) tok[nt++] = t;
    if (!nt) return 0;
    const char *b = base(tok[0]);
    if (strcmp(b, "sh") && strcmp(b, "bash") && strcmp(b, "mksh") && strcmp(b, "dash")) return 0;
    int isc = 0, script = 0;
    for (int i = 1; i < nt; i++) {
        if (!strcmp(tok[i], "-c")) { isc = 1; break; }
        if (tok[i][0] == '-') continue;
        script = 1; break;
    }
    if (out) snprintf(out, on, "%s", cmd);
    return isc ? 3 : (script ? 2 : 1);
}

static void kill_kids(pid_t p, int depth) {
    if (depth > 8) return;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/children", p, p);
    FILE *f = fopen(path, "r");
    if (!f) return;
    pid_t kids[256]; int n = 0, v;
    while (fscanf(f, "%d", &v) == 1 && n < 256) kids[n++] = (pid_t)v;
    fclose(f);
    for (int i = 0; i < n; i++) {
        kill(kids[i], SIGKILL);
        kill_kids(kids[i], depth + 1);
    }
}

// ---- 脚本静态预检：sh 脚本一 exec 就先读文件，发现危险命令行立刻终止（不等它跑第一条）----
static const char *precheck_script(pid_t pid, const char *cmd, char *dbuf, size_t dn) {
    if (!scan_scripts) return NULL;
    char tmp[1024]; strncpy(tmp, cmd, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = 0;
    char *tok[16]; int nt = 0; char *save = NULL;
    for (char *t = strtok_r(tmp, " \t", &save); t && nt < 16; t = strtok_r(NULL, " \t", &save)) tok[nt++] = t;
    if (nt < 2) return NULL;
    const char *b = base(tok[0]);
    if (strcmp(b, "sh") && strcmp(b, "bash") && strcmp(b, "mksh") &&
        strcmp(b, "dash") && strcmp(b, "ash")) return NULL;
    const char *sp = NULL;
    for (int i = 1; i < nt; i++) { if (tok[i][0] == '-') continue; sp = tok[i]; break; }
    if (!sp || sp[0] != '/') return NULL;
    if (!strncmp(sp, "/data/adb/modules/antiwipe", 26) || !strncmp(sp, "/data/adb/antiwipe", 19)) return NULL;
    struct stat st;
    if (stat(sp, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) return NULL;
    size_t cap = st.st_size > (1 << 20) ? (1 << 20) : (size_t)st.st_size;
    FILE *f = fopen(sp, "r");
    if (!f) return NULL;
    char *buf = malloc(cap + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, cap, f);
    fclose(f);
    const char *hit = NULL;
    char line[1024];
    size_t pos = 0;
    while (pos < got) {
        size_t e = pos;
        while (e < got && buf[e] != '\n') e++;
        size_t L = e - pos;
        if (L >= sizeof(line)) L = sizeof(line) - 1;
        memcpy(line, buf + pos, L); line[L] = 0;
        while (L && (line[L-1] == '\r' || line[L-1] == ' ' || line[L-1] == '\t')) line[--L] = 0;
        if (L > 0) {
            char d2[120] = "";
            const char *r = match_cmd(pid, line, d2, sizeof(d2));
            if (r) { snprintf(dbuf, dn, "脚本预检: %s", d2[0] ? d2 : line); hit = r; break; }
        }
        pos = e + 1;
    }
    free(buf);
    return hit;
}

static void kill_hit(pid_t pid, const char *rule, const char *desc, const char *cmd) {
    pid_t pp = get_ppid(pid);
    if (kill_enabled) kill(pid, SIGKILL);
    logline("[拦截] %s | pid=%d %s | %s", rule, pid, desc, cmd);
    if (kill_enabled && pp > 1) {
        char pcmd[512];
        int k = shell_kind(pp, pcmd, sizeof(pcmd));
        if (k == 2) {
            kill_kids(pp, 0);
            kill(pp, SIGKILL);
            logline("[拦截] 脚本树终止 | pid=%d | %s", pp, pcmd);
        } else if (k == 3) {
            kill(pp, SIGKILL);
            logline("[拦截] 包装shell | pid=%d | %s", pp, pcmd);
            pid_t gp = get_ppid(pp);
            if (gp > 1) {
                char gcmd[512];
                if (shell_kind(gp, gcmd, sizeof(gcmd)) == 2) {
                    kill_kids(gp, 0);
                    kill(gp, SIGKILL);
                    logline("[拦截] 脚本树终止 | pid=%d | %s", gp, gcmd);
                }
            }
        } else if (k == 1) {
            kill(pp, SIGKILL);
            logline("[拦截] shell | pid=%d | %s", pp, pcmd);
        }
    }
    popup(rule, desc, pid);
}


// ---- stdin 预检：`sh < 脚本`、`cat 脚本 | sh`、`base64 -d | sh` 这类不把路径放在 argv 里的执行方式 ----
static const char *scan_buf(pid_t pid, const char *buf, size_t got, char *dbuf, size_t dn) {
    char line[1024];
    size_t pos = 0;
    while (pos < got) {
        size_t e = pos;
        while (e < got && buf[e] != '\n') e++;
        size_t L = e - pos;
        if (L >= sizeof(line)) L = sizeof(line) - 1;
        memcpy(line, buf + pos, L); line[L] = 0;
        while (L && (line[L-1] == '\r' || line[L-1] == ' ' || line[L-1] == '\t')) line[--L] = 0;
        if (L > 0) {
            char d2[120] = "";
            const char *r = match_cmd(pid, line, d2, sizeof(d2));
            if (r) { snprintf(dbuf, dn, "%s", d2[0] ? d2 : line); return r; }
        }
        pos = e + 1;
    }
    return NULL;
}

// 简易 base64 解码：对付 base64 -d | sh 这类把脚本文本变形的执行方式
static int b64_decode(const char *in, size_t n, char *out, size_t cap, size_t *on) {
    static const char tb[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned v = 0; int bits = 0; size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c == '=') break;
        const char *q = strchr(tb, c);
        if (!q) continue;
        v = (v << 6) | (unsigned)(q - tb);
        bits += 6;
        if (bits >= 8) { bits -= 8; if (k < cap) out[k++] = (char)((v >> bits) & 0xFF); }
    }
    *on = k;
    return 0;
}

static int file_looks_b64(const char *buf, size_t got) {
    size_t n = got > 4096 ? 4096 : got;
    if (n < 16) return 0;
    size_t okc = 0;
    for (size_t i = 0; i < n; i++) {
        char c = buf[i];
        if (c == '\n' || c == '\r') continue;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '+' || c == '/' || c == '=') { okc++; continue; }
        return 0;
    }
    return okc > n / 2;
}

static const char *scan_path(pid_t pid, const char *path, char *dbuf, size_t dn, const char *why, int dec) {
    struct stat st;
    if (!path || path[0] != '/') return NULL;
    if (!strncmp(path, "/data/adb/modules/antiwipe", 26) || !strncmp(path, "/data/adb/antiwipe", 19)) return NULL;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) return NULL;
    if (st.st_size > (1 << 20)) return NULL;
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);
    buf[got] = 0;
    char inner[120] = "";
    const char *r = scan_buf(pid, buf, got, inner, sizeof(inner));
    if (!r && (dec || file_looks_b64(buf, got))) {
        char *dec2 = malloc(got + 8);
        if (dec2) {
            size_t dn2 = 0;
            b64_decode(buf, got, dec2, got, &dn2);
            if (dn2 > 0) {
                char inner2[120] = "";
                const char *r2 = scan_buf(pid, dec2, dn2, inner2, sizeof(inner2));
                if (r2) { snprintf(inner, sizeof(inner), "base64 解码: %s", inner2); r = r2; }
            }
            free(dec2);
        }
    }
    free(buf);
    if (r) snprintf(dbuf, dn, "%s: %s", why, inner);
    return r;
}

static int proc_is_shell(pid_t pid, const char *cmd) {
    static const char *names[] = {"sh", "bash", "mksh", "dash", "ash", NULL};
    char p[64], exe[256] = "";
    snprintf(p, sizeof(p), "/proc/%d/exe", pid);
    ssize_t n = readlink(p, exe, sizeof(exe) - 1);
    if (n > 0) { exe[n] = 0;
        for (int i = 0; names[i]; i++) if (!strcmp(base(exe), names[i])) return 1; }
    char tmp[128]; strncpy(tmp, cmd, sizeof(tmp) - 1); tmp[sizeof(tmp) - 1] = 0;
    char *sp = strchr(tmp, ' '); if (sp) *sp = 0;
    for (int i = 0; names[i]; i++) if (!strcmp(base(tmp), names[i])) return 1;
    return 0;
}

static int proc_has_decoder(pid_t w) {
    char cmd[512] = "";
    read_cmdline(w, cmd, sizeof(cmd));
    if (strstr(cmd, "base64") && (strstr(cmd, "-d") || strstr(cmd, "--decode"))) return 1;
    if (strstr(cmd, "uudecode")) return 1;
    if (strstr(cmd, "openssl") && strstr(cmd, "base64")) return 1;
    return 0;
}

static pid_t pipe_writer(const char *tgt) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    pid_t found = -1;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        pid_t w = (pid_t)atoi(de->d_name);
        if (w <= 1) continue;
        char p[64], t[512];
        snprintf(p, sizeof(p), "/proc/%d/fd/1", w);
        ssize_t n = readlink(p, t, sizeof(t) - 1);
        if (n <= 0) continue;
        t[n] = 0;
        if (!strcmp(t, tgt)) { found = w; break; }
    }
    closedir(d);
    return found;
}

// 沿管道链往上走：写端进程的参数 / 打开的 fd 里若指向普通文件，就读出来预检
static const char *chain_scan(pid_t w, const char *pipe_tgt, int depth, char *dbuf, size_t dn, int dec) {
    if (getenv("AW_DEBUG")) logline("[调试] chain pid=%d depth=%d dec=%d", w, depth, dec);
    if (depth <= 0 || w <= 1 || w == getpid()) return NULL;
    if (proc_has_decoder(w)) dec = 1;
    char cmd[512] = "";
    read_cmdline(w, cmd, sizeof(cmd));
    char tmp[512]; strncpy(tmp, cmd, sizeof(tmp) - 1); tmp[sizeof(tmp) - 1] = 0;
    char *save = NULL;
    for (char *t = strtok_r(tmp, " \t", &save); t; t = strtok_r(NULL, " \t", &save)) {
        if (t[0] != '/') continue;
        const char *r = scan_path(w, t, dbuf, dn, "管道源预检", dec);
        if (r) return r;
    }
    char fdp[64], tgt[512];
    int again = 0;
    for (int fd = 0; fd < 24; fd++) {
        if (fd == 1) continue;
        snprintf(fdp, sizeof(fdp), "/proc/%d/fd/%d", w, fd);
        ssize_t m = readlink(fdp, tgt, sizeof(tgt) - 1);
        if (m <= 0) continue;
        tgt[m] = 0;
        if (!strncmp(tgt, "pipe:[", 6)) {
            if (fd == 0) again = 1;
            continue;
        }
        if (tgt[0] != '/') continue;
        const char *r = scan_path(w, tgt, dbuf, dn, "管道源预检", dec);
        if (r) return r;
    }
    if (again) {
        pid_t up = pipe_writer(tgt[0] ? tgt : "");
        (void)up;
        char p0[64], t0[512];
        snprintf(p0, sizeof(p0), "/proc/%d/fd/0", w);
        ssize_t k = readlink(p0, t0, sizeof(t0) - 1);
        if (k > 0) {
            t0[k] = 0;
            if (!strncmp(t0, "pipe:[", 6)) {
                pid_t up2 = pipe_writer(t0);
                if (up2 > 1) return chain_scan(up2, t0, depth - 1, dbuf, dn, dec);
            }
        }
    }
    (void)pipe_tgt;
    return NULL;
}

// 写端是否已经 exec 完（cmdline 不再是外面的包装 shell）
static int pipe_writer_ready(pid_t w) {
    char exe[256] = "";
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/exe", w);
    ssize_t n = readlink(p, exe, sizeof(exe) - 1);
    if (n <= 0) return 0;
    exe[n] = 0;
    const char *b = base(exe);
    return strcmp(b, "bash") && strcmp(b, "sh") && strcmp(b, "mksh");
}

// 管道写端可能一瞬就跑完：顺着父进程命令行找被喂进去的文件（cat f | sh 这类调用在父 shell 的 argv 里）
static const char *ancestor_scan(pid_t pid, char *dbuf, size_t dn) {
    pid_t cur = pid;
    for (int depth = 0; depth < 4; depth++) {
        pid_t pp = get_ppid(cur);
        if (pp <= 1) break;
        char cmd[1024] = "";
        read_cmdline(pp, cmd, sizeof(cmd));
        if (!cmd[0]) break;
        int dec = strstr(cmd, "base64") != NULL;
        char tmp[1024];
        strncpy(tmp, cmd, sizeof(tmp) - 1); tmp[sizeof(tmp) - 1] = 0;
        char *save = NULL;
        for (char *t = strtok_r(tmp, " \t", &save); t; t = strtok_r(NULL, " \t", &save)) {
            if (t[0] != '/') continue;
            const char *r = scan_path(pp, t, dbuf, dn, "父进程命令行预检", dec);
            if (r) return r;
        }
        cur = pp;
    }
    return NULL;
}

static const char *precheck_stdin(pid_t pid, char *dbuf, size_t dn) {
    if (!scan_stdin) return NULL;
    char p[64], tgt[512];
    snprintf(p, sizeof(p), "/proc/%d/fd/0", pid);
    ssize_t n = readlink(p, tgt, sizeof(tgt) - 1);
    if (n <= 0) return NULL;
    tgt[n] = 0;
    if (getenv("AW_DEBUG")) logline("[调试] stdin pid=%d fd0=%s", pid, tgt);
    if (tgt[0] == '/') return scan_path(pid, tgt, dbuf, dn, "stdin 文件预检", 0);
    if (strncmp(tgt, "pipe:[", 6)) return NULL;
    pid_t w = pipe_writer(tgt);
    if (getenv("AW_DEBUG")) logline("[调试] 管道写端 pid=%d -> %d", pid, w);
    if (w > 1) {
        const char *hit = chain_scan(w, tgt, 4, dbuf, dn, 0);
        if (hit) return hit;
        hit = ancestor_scan(pid, dbuf, dn);
        if (hit) return hit;
        if (strict_pipe) {
            char wcmd[220] = "";
            read_cmdline(w, wcmd, sizeof(wcmd));
            snprintf(dbuf, dn, "管道输入不可预检: %s", wcmd);
            return "STDIN_PIPE";
        }
    } else {
        const char *hit = ancestor_scan(pid, dbuf, dn);
        if (hit) return hit;
        if (strict_pipe) {
            snprintf(dbuf, dn, "管道来源已退出，无法预检");
            return "STDIN_PIPE";
        }
    }
    return NULL;
}

// 管道场景写端可能还在 exec / 还没就位，放到独立线程里重试，别堵住 exec 事件通道
static void *stdin_thread(void *arg) {
    pid_t pid = *(pid_t *)arg;
    free(arg);
    char dbuf[160] = "";
    for (int a = 0; a < 8; a++) {
        const char *r = precheck_stdin(pid, dbuf, sizeof(dbuf));
        if (r) {
            char cmd[512] = "";
            read_cmdline(pid, cmd, sizeof(cmd));
            kill_hit(pid, r, dbuf, cmd);
            return NULL;
        }
        usleep(8000);
    }
    return NULL;
}

static const char *stdin_is_pipe(pid_t pid) {
    char p[64], tgt[512];
    snprintf(p, sizeof(p), "/proc/%d/fd/0", pid);
    ssize_t n = readlink(p, tgt, sizeof(tgt) - 1);
    if (n <= 0) return NULL;
    tgt[n] = 0;
    if (strncmp(tgt, "pipe:[", 6)) return NULL;
    return "pipe";
}

static const char *check_proc(pid_t pid, const char *cmd, char *dbuf, size_t dn) {
    const char *rule = match_cmd(pid, cmd, dbuf, dn);
    if (rule) return rule;
    rule = precheck_script(pid, cmd, dbuf, dn);
    if (rule) return rule;
    if (!proc_is_shell(pid, cmd)) return NULL;
    if (stdin_is_pipe(pid)) {
        pid_t *pp = malloc(sizeof(pid_t));
        if (pp) {
            *pp = pid;
            pthread_t t;
            if (pthread_create(&t, NULL, stdin_thread, pp) == 0) pthread_detach(t);
            else free(pp);
        }
        return NULL;
    }
    return precheck_stdin(pid, dbuf, dn);
}

// ---- 内核 exec 事件通道：进程一 exec 就检查，毫秒级 ----
#define NETLINK_CONNECTOR 11
#define CN_IDX_PROC 1
#define CN_VAL_PROC 1
#define PROC_CN_MCAST_LISTEN 1
#define PROC_EVENT_EXEC 2

struct cnm { uint32_t idx, val, seq, ack; uint16_t len, flags; uint8_t data[]; };
struct pev {
    uint32_t what, cpu, timestamp_ns_lo, timestamp_ns_hi, tgid;
    union { struct { uint32_t pid, tgid; } exec; uint8_t raw[48]; } d;
};

static void handle_exec(pid_t pid) {
    if (pid <= 1 || pid == getpid()) return;
    char cmd[1024];
    read_cmdline(pid, cmd, sizeof(cmd));
    if (!cmd[0]) return;
    if (strstr(cmd, "/antiwipe/bin/guard")) return;
    char dbuf[160] = "";
    const char *rule = check_proc(pid, cmd, dbuf, sizeof(dbuf));
    if (!rule) return;
    kill_hit(pid, rule, dbuf, cmd);
}

static void *nl_loop(void *arg) {
    (void)arg;
    for (;;) {
        int s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
        if (s < 0) { sleep(5); continue; }
        struct sockaddr_nl sa;
        memset(&sa, 0, sizeof(sa));
        sa.nl_family = AF_NETLINK;
        sa.nl_groups = CN_IDX_PROC;
        sa.nl_pid = (uint32_t)getpid();
        if (bind(s, (void *)&sa, sizeof(sa)) < 0) { close(s); sleep(5); continue; }
        struct { struct nlmsghdr nl; struct cnm cn; uint32_t op; } msg;
        memset(&msg, 0, sizeof(msg));
        msg.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct cnm) + sizeof(uint32_t));
        msg.nl.nlmsg_type = NLMSG_DONE;
        msg.nl.nlmsg_pid = (uint32_t)getpid();
        msg.cn.idx = CN_IDX_PROC;
        msg.cn.val = CN_VAL_PROC;
        msg.cn.len = sizeof(uint32_t);
        msg.op = PROC_CN_MCAST_LISTEN;
        if (send(s, &msg, msg.nl.nlmsg_len, 0) < 0) { close(s); sleep(5); continue; }
        logline("[启动] exec 事件通道已连接");
        for (;;) {
            char buf[8192];
            ssize_t n = recv(s, buf, sizeof(buf), 0);
            if (n <= 0) break;
            struct nlmsghdr *h = (void *)buf;
            for (; NLMSG_OK(h, (unsigned int)n); h = NLMSG_NEXT(h, n)) {
                if (h->nlmsg_type != NLMSG_DONE) continue;
                struct cnm *cn = NLMSG_DATA(h);
                if (cn->idx != CN_IDX_PROC) continue;
                struct pev *e = (void *)cn->data;
                if (e->what & PROC_EVENT_EXEC) handle_exec((pid_t)e->d.exec.pid);
            }
        }
        close(s);
        sleep(1);
    }
    return NULL;
}

static void check_sysrq(void) {
    int fd = open("/proc/sys/kernel/sysrq", O_RDWR);
    if (fd < 0) return;
    char b[8];
    ssize_t r = read(fd, b, sizeof(b) - 1);
    if (r > 0 && b[0] != '0') {
        if (lseek(fd, 0, SEEK_SET) == 0 && write(fd, "0", 1) == 1)
            logline("[加固] sysrq 已重新禁用 (防止 echo b > sysrq-trigger 强重启)");
    }
    close(fd);
}

// 扫描 /proc 找同类进程：role=0 主进程，role=1 keeper
static int count_role(int role) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    char p[64], buf[640];
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        pid_t pid = atoi(e->d_name);
        if (pid <= 1 || pid == getpid()) continue;
        snprintf(p, sizeof(p), "/proc/%d/exe", pid);
        ssize_t m = readlink(p, buf, sizeof(buf)-1);
        if (m <= 0) continue;
        buf[m] = 0;
        if (strcmp(buf, selfpath)) continue;
        char cl[256];
        read_cmdline(pid, cl, sizeof(cl));
        int k = (strstr(cl, " -k") != NULL);
        int w = (strstr(cl, " -w") != NULL);
        int r = k ? 1 : (w ? 2 : 0);
        if (r == role) n++;
    }
    closedir(d);
    return n;
}

static void spawn_self(const char *arg) {
    pid_t c = fork();
    if (c != 0) return;
    setsid();
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) { dup2(fd, 0); dup2(fd, 1); dup2(fd, 2); if (fd > 2) close(fd); }
    if (arg) execl(selfpath, selfpath, arg, (char *)NULL);
    else execl(selfpath, selfpath, (char *)NULL);
    _exit(1);
}

static void scan_proc(void) {
    DIR *d = opendir("/proc");
    if (!d) return;
    pid_t self = getpid();
    pass++;
    int full = (pass % 64) == 0;
    if (full) memset(seen, 0, sizeof(seen));
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        pid_t pid = atoi(e->d_name);
        if (pid <= 1 || pid == self) continue;
        if (!full && pid < PIDBITS && (seen[pid >> 3] & (1 << (pid & 7)))) continue;
        char path[64], cmd[1024];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        size_t n = fread(cmd, 1, sizeof(cmd)-1, f);
        fclose(f);
        if (pid < PIDBITS) seen[pid >> 3] |= (unsigned char)(1 << (pid & 7));
        if (n == 0) continue;
        cmd[n] = 0;
        for (size_t i = 0; i < n; i++) if (cmd[i] == 0 || cmd[i] == '\n' || cmd[i] == '\r') cmd[i] = ' ';
        if (strstr(cmd, "/antiwipe/bin/guard")) continue;
        char dbuf[160] = "";
        const char *rule = check_proc(pid, cmd, dbuf, sizeof(dbuf));
        if (!rule) continue;
        kill_hit(pid, rule, dbuf, cmd);
    }
    closedir(d);
}

// ---- 块设备句柄监控：抓“二进制直接 open("/dev/block/...") 写”的路径 ----
static int exe_trusted(const char *exe) {
    static const char *ok[] = {"/system", "/vendor", "/apex", "/product", "/odm",
        "/data/adb/modules/antiwipe", "/data/adb/magisk", "/data/adb/ksu",
        "/data/adb/ap", "/data/adb/modules_update", NULL};
    for (int i = 0; ok[i]; i++) if (!strncmp(exe, ok[i], strlen(ok[i]))) return 1;
    return 0;
}
static int fdinfo_writable(const char *p) {
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    char line[160]; int flags = -1;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "flags:", 6)) { flags = (int)strtol(line + 6, NULL, 8); break; }
    }
    fclose(f);
    if (flags < 0) return -1;
    return (flags & 3) != 0;
}
// 立即处理刚发现的危险句柄：SIGSTOP 在毫秒级生效，比整轮扫描完再杀要早得多
static void hit_block_fd(pid_t pid, const char *tgt, const char *fdn, const char *exe) {
    char cmd[512] = "";
    read_cmdline(pid, cmd, sizeof(cmd));
    char desc[240];
    snprintf(desc, sizeof(desc), "持有可写块设备句柄 %s (fd %s)", tgt, fdn);
    logline("[发现] BLOCK_FD pid=%d exe=%s %s", pid, exe, desc);
    react_block_write(pid, desc, cmd);
    logline("[拦截] BLOCK_FD 进程已处理: %s | exe=%s", desc, exe);
}

static void scan_block_fds(void) {
    if (!block_fd) return;
    int dbg = getenv("AW_DEBUG") != NULL;
    int npid = 0, nfd = 0, nblk = 0, allpid = 0;
    DIR *d = opendir("/proc");
    if (!d) { if (dbg) logline("[调试] opendir /proc 失败"); return; }
    struct dirent *e;
    char p[128], exe[512], tgt[512], fdp[160], fin[160];
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        allpid++;
        pid_t pid = atoi(e->d_name);
        if (pid <= 1 || pid == getpid()) continue;
        snprintf(p, sizeof(p), "/proc/%d/exe", pid);
        ssize_t m = readlink(p, exe, sizeof(exe)-1);
        if (m <= 0) continue;
        exe[m] = 0;
        if (strstr(exe, "/antiwipe/bin/guard")) continue;
        if (exe_trusted(exe)) continue;
        npid++;
        if (dbg && npid <= 40) logline("[调试] 候选 exe=%s", exe);
        snprintf(p, sizeof(p), "/proc/%d/fd", pid);
        DIR *fd = opendir(p);
        if (!fd) continue;
        struct dirent *fe; int hit = 0;
        while ((fe = readdir(fd))) {
            if (fe->d_name[0] < '0' || fe->d_name[0] > '9') continue;
            snprintf(fdp, sizeof(fdp), "/proc/%d/fd/%s", pid, fe->d_name);
            ssize_t k = readlink(fdp, tgt, sizeof(tgt)-1);
            if (k <= 0) continue;
            tgt[k] = 0;
            nfd++;
            if (!blk_target(tgt)) continue;
            nblk++;
            snprintf(fin, sizeof(fin), "/proc/%d/fdinfo/%s", pid, fe->d_name);
            if (fdinfo_writable(fin) != 1) continue;
            hit_block_fd(pid, tgt, fe->d_name, exe);
            hit = 1; break;
        }
        closedir(fd);
        if (hit) break;
    }
    closedir(d);
    if (dbg) logline("[调试] 块句柄扫描: /proc可见pid=%d 候选=%d fd=%d 块设备fd=%d", allpid, npid, nfd, nblk);
}

// 独立的块设备句柄扫描线程：默认 100ms 一轮，比主循环快得多
static void *fd_loop(void *arg) {
    (void)arg;
    for (;;) {
        if (block_fd) scan_block_fds();
        usleep(block_fd_ms * 1000);
    }
    return NULL;
}

// ---- web 控制台看护：掉了就拉起来 ----
#define WEBP "/data/adb/modules/antiwipe/bin/web"
static int count_web(void) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int n = 0; char p[64], b[512];
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        pid_t pid = atoi(e->d_name);
        if (pid <= 1 || pid == getpid()) continue;
        snprintf(p, sizeof(p), "/proc/%d/exe", pid);
        ssize_t m = readlink(p, b, sizeof(b)-1);
        if (m <= 0) continue;
        b[m] = 0;
        if (strstr(b, "/antiwipe/") && !strcmp(base(b), "web")) n++;
    }
    closedir(d);
    return n;
}
static void ensure_web(void) {
    if (web_port <= 0) return;
    if (count_web() > 0) return;
    struct stat st;
    if (stat(WEBP, &st) != 0) return;
    pid_t c = fork();
    if (c != 0) { if (c > 0) logline("[启动] web 已拉起 pid=%d", c); return; }
    setsid();
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) { dup2(fd, 0); dup2(fd, 1); dup2(fd, 2); if (fd > 2) close(fd); }
    execl(WEBP, WEBP, (char *)NULL);
    _exit(1);
}

static void check_paths(void) {
    const char *paths[] = {"/data/adb", "/data/system", "/data/app", "/data/misc", "/data/adb/modules", NULL};
    for (int i = 0; paths[i]; i++) {
        struct stat st;
        if (stat(paths[i], &st) != 0) logline("[告警] 关键目录丢失: %s", paths[i]);
    }
}

static void check_admins(void) {
    FILE *p = fopen("/data/system/device_policies.xml", "r");
    if (!p) return;
    char line[1024];
    while (fgets(line, sizeof(line), p)) {
        char *a = strstr(line, "<admin name=\"");
        if (!a) continue;
        a += 13;
        char *b = strchr(a, '"'); if (!b) continue;
        *b = 0;
        char *slash = strchr(a, '/'); if (!slash) continue;
        *slash = 0;
        const char *pkg = a;
        if (wl_match(pkg)) continue;
        static char seen_wl[2048];
        if (strstr(seen_wl, pkg)) continue;
        strncat(seen_wl, pkg, sizeof(seen_wl) - strlen(seen_wl) - 2);
        strcat(seen_wl, ",");
        logline("[告警] 新增设备管理器: %s", pkg);
        if (auto_rm_admin) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "dpm remove-active-admin %s 2>/dev/null", pkg);
            if (system(cmd) == 0) logline("[已移除] 设备管理器 %s", pkg);
        }
    }
    fclose(p);
}

static void lock_role(const char *path) {
    int dbg = getenv("AW_DEBUG") != NULL;
    int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (dbg) logline("[调试] open 锁 %s fd=%d errno=%d", path, fd, fd < 0 ? errno : 0);
    if (fd < 0) return;
    int rc = flock(fd, LOCK_EX | LOCK_NB);
    if (dbg) logline("[调试] flock rc=%d errno=%d", rc, rc ? errno : 0);
    if (rc != 0) _exit(0);   // 已有同角色在跑
}

static void keeper_loop(void) {
    lock_role(LOCKF);
    logline("[启动] keeper pid=%d", getpid());
    for (;;) {
        if (count_role(0) <= 0) spawn_self(NULL);
        if (count_role(2) <= 0) spawn_self("-w");
        sleep(2);
    }
}

static void watch_loop(void) {
    lock_role(LOCKW);
    logline("[启动] watchdog pid=%d", getpid());
    for (;;) {
        if (count_role(0) <= 0) spawn_self(NULL);
        if (count_role(1) <= 0) spawn_self("-k");
        sleep(2);
    }
}

int main(int argc, char **argv) {
    const char *home = getenv("AW_HOME");
    if (home && home[0] == '/') {
        snprintf(g_moddir_buf, sizeof(g_moddir_buf), "%s", home);
        mkdir(g_moddir_buf, 0755);
        snprintf(g_conf_buf, sizeof(g_conf_buf), "%s/config.conf", home);
        snprintf(g_logf_buf, sizeof(g_logf_buf), "%s/events.log", home);
        snprintf(g_pidf_buf, sizeof(g_pidf_buf), "%s/guard.pid", home);
        snprintf(g_lockf_buf, sizeof(g_lockf_buf), "%s/keeper.lock", home);
        snprintf(g_lockw_buf, sizeof(g_lockw_buf), "%s/watchdog.lock", home);
        snprintf(g_lockm_buf, sizeof(g_lockm_buf), "%s/guard.lock", home);
    }
    snprintf(selfpath, sizeof(selfpath), "/proc/%d/exe", getpid());
    ssize_t n = readlink(selfpath, selfpath, sizeof(selfpath)-1);
    if (n > 0) selfpath[n] = 0;
    else snprintf(selfpath, sizeof(selfpath), "/data/adb/modules/antiwipe/bin/guard");
    if (argc > 1 && !strcmp(argv[1], "-t")) {
        char line[1024];
        while (fgets(line, sizeof(line), stdin)) {
            size_t L = strlen(line);
            while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
            if (!L) continue;
            char dbuf[160] = "";
            const char *rule = match_cmd(getpid(), line, dbuf, sizeof(dbuf));
            printf("%s\t%s\t%s\n", rule ? rule : "MISS", dbuf, line);
        }
        return 0;
    }
    is_keeper = (argc > 1 && !strcmp(argv[1], "-k"));
    is_watch  = (argc > 1 && !strcmp(argv[1], "-w"));
    signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN); signal(SIGHUP, SIG_IGN);
    signal(SIGQUIT, SIG_IGN); signal(SIGPIPE, SIG_IGN);
    signal(SIGTSTP, SIG_IGN); signal(SIGTTIN, SIG_IGN); signal(SIGTTOU, SIG_IGN);
    mkdir(MODDIR, 0755);
    char logdir[320];
    snprintf(logdir, sizeof(logdir), "%s/log", MODDIR);
    mkdir(logdir, 0755);
    load_config();
    if (is_keeper) keeper_loop();
    if (is_watch) watch_loop();
    if (getenv("AW_DEBUG")) logline("[调试] main 进入前台循环");
    if (getenv("AW_DEBUG")) logline("[调试] 角色=main pid=%d", getpid());
    if (getenv("AW_DEBUG")) logline("[调试] 准备拿主锁");
    lock_role(LOCKM);
    if (getenv("AW_DEBUG")) logline("[调试] 拿到主锁 pid=%d", getpid());
    pthread_t nt;
    pthread_create(&nt, NULL, nl_loop, NULL);
    pthread_t bt;
    pthread_create(&bt, NULL, fd_loop, NULL);
    FILE *pf = fopen(PIDF, "w");
    if (pf) { fprintf(pf, "%d", getpid()); fclose(pf); }
    boot_time = time(NULL) - (long)proc_uptime();
    logline("[启动] 防格机卫士 pid=%d poll=%dms kill=%d popup=%d protect_sd=%d block_fd=%d poweroff=%d",
            getpid(), poll_ms, kill_enabled, popup_enabled, protect_sd, block_fd, poweroff_react);
    spawn_self("-k");   // 重复的会因 flock 自动退出
    spawn_self("-w");
    time_t last_path = 0, last_admin = 0, last_keep = 0;
    for (;;) {
        scan_proc();
        time_t now = time(NULL);
        if (now - last_path >= 3) { check_paths(); last_path = now; }
        if (now - last_admin >= 60) { check_admins(); last_admin = now; }
        if (now - last_keep >= 5) {
            if (count_role(1) <= 0) spawn_self("-k");
            if (count_role(2) <= 0) spawn_self("-w");
            ensure_web();
            check_sysrq(); last_keep = now;
        }
        usleep(poll_ms * 1000);
    }
}
