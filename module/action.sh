#!/system/bin/sh
# KernelSU 管理器「操作」按钮：显示状态 + 重启守卫
MODDIR=${0%/*}
RUNDIR=/data/adb/antiwipe
echo "== 防格机卫士 状态 =="
n=0
for p in /proc/[0-9]*; do
  e=$(readlink "$p/exe" 2>/dev/null)
  case "$e" in
    "$RUNDIR"/run/*|"$MODDIR"/bin/*) echo "  运行中: ${p#/proc/} $e"; n=$((n+1));;
  esac
done
[ "$n" = "0" ] && echo "  未运行，正在启动..."
[ -f "$RUNDIR/events.log" ] && { echo "== 最近事件 =="; tail -n 8 "$RUNDIR/events.log"; }
setsid sh "$MODDIR/service.sh" </dev/null >/dev/null 2>&1 &
echo "== 已请求启动/重启，3 秒后生效 =="
