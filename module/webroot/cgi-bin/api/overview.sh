#!/system/bin/sh
cd "$(dirname "$0")" && . ./_lib.sh
authed || deny
json_head
G1=$("$BK" pgrep -f "$RUNTIME/run/" 2>/dev/null | wc -l)
G2=$("$BK" pgrep -f "$MODDIR/bin/guard" 2>/dev/null | wc -l)
G=$((G1 + G2))
MAIN=0; [ "$G" -gt 0 ] && MAIN=1
TOT=0; TDY=0
if [ -f "$LOGF" ]; then
  TOT=$("$BK" grep -c '\[拦截\]' "$LOGF" 2>/dev/null)
  TDY=$("$BK" grep -c "^$(date +%m-%d).*\[拦截\]" "$LOGF" 2>/dev/null)
fi
case "$TOT" in ''|*[!0-9]*) TOT=0;; esac
case "$TDY" in ''|*[!0-9]*) TDY=0;; esac
UP=0
if [ -f "$RUNTIME/guard.pid" ]; then
  n=$(date +%s); t=$("$BK" stat -c %Y "$RUNTIME/guard.pid" 2>/dev/null)
  case "$t" in ''|*[!0-9]*) t=0;; esac
  [ "$t" -gt 0 ] && UP=$((n - t))
fi
K=$(cfg_get KILL); P=$(cfg_get POPUP); B=$(cfg_get BLOCK_FD); S=$(cfg_get PROTECT_SD)
SC=$(cfg_get SCAN_SCRIPTS); R=$(cfg_get RESCUE_GUARD); RM=$(cfg_get BLOCK_REMOUNT); PO=$(cfg_get POWEROFF)
POLL=$(cfg_get POLL_MS); BFM=$(cfg_get BLOCK_FD_MS); WPORT=$(cfg_get WEB_PORT)
printf '{"procs":%d,"main":%d,"keeper":0,"watchdog":0,"total":%d,"today":%d,"uptime":%d,' "$G" "$MAIN" "$TOT" "$TDY" "$UP"
printf '"kill":%d,"popup":%d,"blockfd":%d,"sd":%d,"scripts":%d,"rescue":%d,"remount":%d,"poweroff":%d,' \
  "${K:-0}" "${P:-0}" "${B:-0}" "${S:-0}" "${SC:-0}" "${R:-0}" "${RM:-0}" "${PO:-0}"
printf '"poll":%d,"bfdms":%d,"port":%d}\n' "${POLL:-0}" "${BFM:-0}" "${WPORT:-0}"
