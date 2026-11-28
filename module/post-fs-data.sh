#!/system/bin/sh
# 防格机卫士 v1.3.0 · post-fs-data
# v1.3.0 的 guard/web 是静态构建；万一在本机跑不起来，自动回退 .bak 旧版，
# 保证「开机必有防护」而不是「新版本挂了就全裸」。
MODDIR=${0%/*}
RUNDIR=/data/adb/antiwipe
mkdir -p "$RUNDIR/log"
[ -f "$RUNDIR/config.conf" ] || cp -f "$MODDIR/config.conf" "$RUNDIR/config.conf" 2>/dev/null
chmod 755 "$MODDIR/bin/guard" "$MODDIR/bin/guard.bak" "$MODDIR/bin/web" "$MODDIR/bin/web.bak" 2>/dev/null

log() { echo "$(date '+%F %T') $*" >> "$RUNDIR/startup.log" 2>/dev/null; }

running() {
  for p in /proc/[0-9]*; do
    [ "$(readlink "$p/exe" 2>/dev/null)" = "$1" ] && return 0
  done
  return 1
}

start_guard() {
  running "$MODDIR/bin/guard" && return 0
  if command -v setsid >/dev/null 2>&1; then
    setsid "$MODDIR/bin/guard" >/dev/null 2>&1 </dev/null &
  else
    "$MODDIR/bin/guard" >/dev/null 2>&1 </dev/null &
  fi
  sleep 2
  running "$MODDIR/bin/guard" && { log "guard 启动成功(v1.3.0)"; return 0; }
  if [ -f "$MODDIR/bin/guard.bak" ]; then
    log "guard 未启动，回退 v1.2.2"
    cp -f "$MODDIR/bin/guard.bak" "$MODDIR/bin/guard" 2>/dev/null
    chmod 755 "$MODDIR/bin/guard" 2>/dev/null
    if command -v setsid >/dev/null 2>&1; then
      setsid "$MODDIR/bin/guard" >/dev/null 2>&1 </dev/null &
    else
      "$MODDIR/bin/guard" >/dev/null 2>&1 </dev/null &
    fi
    sleep 1
    running "$MODDIR/bin/guard" && log "guard 已回退启动(v1.2.2)" || log "guard 回退也失败"
  fi
}

start_web() {
  [ -x "$MODDIR/bin/web" ] || return 0
  PORT=$(grep -m1 '^WEB_PORT' "$RUNDIR/config.conf" 2>/dev/null | cut -d= -f2)
  [ -z "$PORT" ] && PORT=8099
  [ "$PORT" = "0" ] && return 0
  running "$MODDIR/bin/web" && return 0
  "$MODDIR/bin/web" -p "$PORT" >/dev/null 2>&1 </dev/null &
  sleep 1
  running "$MODDIR/bin/web" && return 0
  if [ -f "$MODDIR/bin/web.bak" ]; then
    log "web 未启动，回退旧控制台"
    cp -f "$MODDIR/bin/web.bak" "$MODDIR/bin/web" 2>/dev/null
    chmod 755 "$MODDIR/bin/web" 2>/dev/null
    "$MODDIR/bin/web" -p "$PORT" >/dev/null 2>&1 </dev/null &
  fi
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
write_token
start_guard
