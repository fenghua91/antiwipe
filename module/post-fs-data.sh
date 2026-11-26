#!/system/bin/sh
MODDIR=${0%/*}
RUNDIR=/data/adb/antiwipe
mkdir -p "$RUNDIR/log"
[ -f "$RUNDIR/config.conf" ] || cp -f "$MODDIR/config.conf" "$RUNDIR/config.conf" 2>/dev/null
chmod 755 "$MODDIR/bin/web" 2>/dev/null

start_web() {
  [ -x "$MODDIR/bin/web" ] || return 0
  PORT=$(grep -m1 '^WEB_PORT' "$RUNDIR/config.conf" 2>/dev/null | cut -d= -f2)
  [ "$PORT" = "0" ] && return 0
  for p in /proc/[0-9]*; do
    [ "$(readlink "$p/exe" 2>/dev/null)" = "$MODDIR/bin/web" ] && return 0
  done
  "$MODDIR/bin/web" >/dev/null 2>&1 < /dev/null &
}


write_token() {
  [ -f "$RUNDIR/web.token" ] || return 0
  TK=$(cat "$RUNDIR/web.token" 2>/dev/null)
  [ -n "$TK" ] || return 0
  W="$MODDIR/webroot/token.js"
  NEW="window.ANTIWIPE_TK=\"$TK\";"
  [ "$(cat "$W" 2>/dev/null)" = "$NEW" ] && return 0
  printf '%s\n' "$NEW" > "$W" 2>/dev/null
}

start_web
sleep 0.6
write_token

for p in /proc/[0-9]*; do
  [ "$(readlink "$p/exe" 2>/dev/null)" = "$MODDIR/bin/guard" ] && exit 0
done
"$MODDIR/bin/guard" >/dev/null 2>&1 &
