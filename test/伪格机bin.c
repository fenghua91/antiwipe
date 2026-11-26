
// 二进制伪格机：所有动作都是无害的（假路径/非法系统调用/只读打开），
// 用于验证“预检”和“命令行匹配”能不能发现非 shell 的擦除行为。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <linux/reboot.h>
#include <stdarg.h>

static void say(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("[伪bin] ", stdout); vprintf(fmt, ap); putchar('\n'); va_end(ap);
    fflush(stdout);
}
static void try_open(const char *p, int flags) {
    int fd = open(p, flags);
    if (fd < 0) say("open %s -> 失败(%s)，不会写任何东西", p, strerror(errno));
    else { say("open %s -> fd=%d（未写入，立即关闭）", p, fd); close(fd); }
}
static int rm_tree(const char *p) {
    DIR *d = opendir(p); if (!d) return -1;
    struct dirent *e; char b[512];
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        snprintf(b, sizeof b, "%s/%s", p, e->d_name);
        struct stat st; if (lstat(b,&st)==0 && S_ISDIR(st.st_mode)) rm_tree(b); else unlink(b);
    }
    closedir(d); return rmdir(p);
}
int main(int argc, char **argv) {
    say("开始，pid=%d（这是二进制，不是脚本）", getpid());
    if (getenv("ANTIWIpe_FDTEST")) {
        say("[0] FDTEST 模式：真开 /dev/block/antiwipe_fdtest O_WRONLY 并写 8 字节");
        int fd = open("/dev/block/antiwipe_fdtest", O_WRONLY);
        if (fd < 0) { say("    open 失败: %s", strerror(errno)); }
        else { write(fd, "wipe-demo", 9); say("    fd=%d 写入完成，睡 3 秒（等 BLOCK_FD 抓）", fd); sleep(3); close(fd); }
    }
    say("[1] 打开假块设备（O_WRONLY）"); try_open("/dev/block/antiwipe_fake0", O_WRONLY);
    say("[2] 递归删除假目录");
    system("mkdir -p /data/local/tmp/antiwipe_bin_fake/a/b && echo x > /data/local/tmp/antiwipe_bin_fake/a/b/f");
    int r = rm_tree("/data/local/tmp/antiwipe_bin_fake");
    say("    rm_tree -> %d（假目录，删了也无所谓）", r);
    say("[3] 非法 reboot 系统调用（magic 错误，返回 EINVAL，不会重启）");
    long rr = syscall(SYS_reboot, 0xdeadbeef, 0, 0, NULL);
    say("    reboot -> %ld errno=%s", rr, rr ? strerror(errno) : "?");
    say("[4] mount 假挂载点");
    int m = mount("none", "/mnt/antiwipe_fake", "tmpfs", 0, "");
    say("    mount -> %d errno=%s", m, strerror(errno));
    say("[5] 打开 sysrq-trigger 只读（不写，不会触发）");
    try_open("/proc/sysrq-trigger", O_RDONLY);
    say("[6] 打开真块设备只读看 fd（不写）");
    try_open("/dev/block/by-name/abl", O_RDONLY);
    say("结束：如果卫士没杀我，说明二进制路径确实绕过了命令行匹配");
    return 0;
}
