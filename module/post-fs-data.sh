#!/system/bin/sh
# 防格机卫士 · 纯脚本控制台（busybox httpd + CGI），无需任何编译产物
MODDIR=${0%/*}
RUNDIR=/data/adb/antiwipe
BB=""
for p in /data/adb/ksu/bin/busybox /data/adb/magisk/busybox /system/xbin/busybox /system/bin/busybox; do
  [ -x "$p" ] && { BB=$p; break; }
done
mkdir -p "$RUNDIR/log"
[ -f "$RUNDIR/config.conf" ] || cp -f "$MODDIR/config.conf" "$RUNDIR/config.conf" 2>/dev/null
chmod 755 "$MODDIR/bin/guard" 2>/dev/null
chmod 755 "$MODDIR"/webroot/cgi-bin/api/*.sh 2>/dev/null

write_token() {
  [ -f "$RUNDIR/web.token" ] || return 0
  TK=$(cat "$RUNDIR/web.token" 2>/dev/null)
  [ -n "$TK" ] || return 0
  W="$MODDIR/webroot/token.js"
  NEW="window.ANTIWIPE_TK=\"$TK\";"
  [ "$(cat "$W" 2>/dev/null)" = "$NEW" ] && return 0
  printf '%s\n' "$NEW" > "$W" 2>/dev/null
}

start_web() {
  [ -n "$BB" ] || return 0
  PORT=$(grep -m1 '^WEB_PORT' "$RUNDIR/config.conf" 2>/dev/null | cut -d= -f2)
  [ -z "$PORT" ] && PORT=8099
  [ "$PORT" = "0" ] && return 0
  for p in /proc/[0-9]*; do
    tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q "httpd -f -p 127.0.0.1:$PORT" && return 0
  done
  ( while :; do
      chmod 755 "$MODDIR"/webroot/cgi-bin/api/*.sh 2>/dev/null
      "$BB" httpd -f -p "127.0.0.1:$PORT" -h "$MODDIR/webroot" 2>>"$RUNDIR/web.log"
      sleep 3
    done ) &
}

write_token
start_web

for p in /proc/[0-9]*; do
  [ "$(readlink "$p/exe" 2>/dev/null)" = "$MODDIR/bin/guard" ] && exit 0
done
if command -v setsid >/dev/null 2>&1; then
  setsid "$MODDIR/bin/guard" >/dev/null 2>&1 </dev/null &
else
  "$MODDIR/bin/guard" >/dev/null 2>&1 </dev/null &
fi
