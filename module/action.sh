#!/system/bin/sh
MODDIR=${0%/*}
RUNDIR=/data/adb/antiwipe
echo "== 防格机卫士 == 状态 =="
n=0
for p in /proc/[0-9]*; do
  e=$(readlink "$p/exe" 2>/dev/null)
  case "$e" in "$RUNDIR"/run/*|"$MODDIR"/bin/*) echo "  运行中: ${p#/proc/} $e"; n=$((n+1));; esac
done
[ "$n" = "0" ] && echo "  未运行，正在启动..."
TK=$(cat "$RUNDIR/web.token" 2>/dev/null | tr -d '\r\n')
PORT=$(grep -m1 '^WEB_PORT' "$RUNDIR/config.conf" 2>/dev/null | cut -d= -f2)
echo "== 控制台 =="
echo "  http://127.0.0.1:${PORT:-8099}/?tk=$TK"
[ -f "$RUNDIR/events.log" ] && { echo "== 最近事件 =="; tail -n 8 "$RUNDIR/events.log"; }
setsid sh "$MODDIR/service.sh" </dev/null >/dev/null 2>&1 &
