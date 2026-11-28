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

BB=""
for p in /data/adb/ksu/bin/busybox /data/adb/magisk/busybox /system/xbin/busybox /system/bin/busybox; do
  [ -x "$p" ] && { BB=$p; break; }
done
# 关掉旧版 C 控制台（它占着 8099，会让 httpd 起不来）
for q in /proc/[0-9]*; do
  c=$(tr '\0' ' ' < "$q/cmdline" 2>/dev/null)
  case "$c" in *"/antiwipe/bin/web"*) kill -9 "${q#/proc/}" 2>/dev/null;; esac
done
PORT=$(grep -m1 '^WEB_PORT' "$RUNDIR/config.conf" 2>/dev/null | cut -d= -f2)
[ -z "$PORT" ] && PORT=8099
if [ -n "$BB" ] && [ "$PORT" != "0" ]; then
  ALREADY=0
  for q in /proc/[0-9]*; do
    c=$(tr '\0' ' ' < "$q/cmdline" 2>/dev/null)
    case "$c" in *"httpd -f -p 127.0.0.1:$PORT"*) ALREADY=1;; esac
  done
  if [ "$ALREADY" = "0" ]; then
    chmod 755 "$MODDIR"/webroot/cgi-bin/api/*.sh 2>/dev/null
    ( while :; do "$BB" httpd -f -p "127.0.0.1:$PORT" -h "$MODDIR/webroot"; sleep 3; done ) &
    echo "  控制台已启动: http://127.0.0.1:$PORT/?tk=$(cat "$RUNDIR/web.token" 2>/dev/null | tr -d '\r\n')"
  fi
fi
setsid sh "$MODDIR/service.sh" </dev/null >/dev/null 2>&1 &
