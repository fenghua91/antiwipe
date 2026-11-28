#!/system/bin/sh
# 防格机卫士 v1.3.0 · service.sh
MODDIR=${0%/*}
RUNDIR=/data/adb/antiwipe
until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 5; done
mkdir -p "$RUNDIR/log"
[ -f "$RUNDIR/config.conf" ] || cp -f "$MODDIR/config.conf" "$RUNDIR/config.conf" 2>/dev/null
chmod 755 "$MODDIR/bin/guard" "$MODDIR/bin/guard.bak" "$MODDIR/bin/web" "$MODDIR/bin/web.bak" 2>/dev/null

write_token() {
  [ -f "$RUNDIR/web.token" ] || return 0
  TK=$(cat "$RUNDIR/web.token" 2>/dev/null)
  [ -n "$TK" ] || return 0
  W="$MODDIR/webroot/token.js"
  NEW="window.ANTIWIPE_TK=\"$TK\";"
  [ "$(cat "$W" 2>/dev/null)" = "$NEW" ] && return 0
  printf '%s\n' "$NEW" > "$W" 2>/dev/null
}
write_token

if ! pm path com.dsh.antiwipe.alerts >/dev/null 2>&1; then
  pm install -r "$MODDIR/alerts.apk" >/dev/null 2>&1
fi

# 已在运行（模块目录或随机运行目录）就直接退出
for p in /proc/[0-9]*; do
  e=$(readlink "$p/exe" 2>/dev/null)
  case "$e" in
    "$MODDIR"/bin/guard|"$RUNDIR"/run/*) exit 0;;
  esac
done

# 运行时随机化
rm -rf "$RUNDIR/run" 2>/dev/null
mkdir -p "$RUNDIR/run"
RUNBIN="$RUNDIR/run/.g$(date +%s)$$"
cp -f "$MODDIR/bin/guard" "$RUNBIN" 2>/dev/null && chmod 755 "$RUNBIN"
if command -v setsid >/dev/null 2>&1; then
  setsid "$RUNBIN" >/dev/null 2>&1 </dev/null &
else
  "$RUNBIN" >/dev/null 2>&1 </dev/null &
fi
