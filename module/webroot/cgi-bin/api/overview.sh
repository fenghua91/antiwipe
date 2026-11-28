#!/system/bin/sh
cd "$(dirname "$0")" && . ./_lib.sh
authed || deny
m=0; k=0; w=0
for p in /proc/[0-9]*; do
  e=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$e" in
    "$MODDIR"/bin/guard|"$RUNTIME"/run/*)
      c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
      case "$c" in *" -k"*) k=$((k+1));; *" -w"*) w=$((w+1));; *) m=$((m+1));; esac;;
  esac
done
TOT=0; TDY=0
if [ -f "$LOGF" ]; then TOT=$("$BK" grep -c '\[拦截\]' "$LOGF" 2>/dev/null); fi
if [ -f "$LOGF" ]; then TDY=$("$BK" grep -c "^$(date +%m-%d).*\[拦截\]" "$LOGF" 2>/dev/null); fi
UP=0
if [ -f "$RUNTIME/guard.pid" ]; then
  n=$(date +%s); t=$("$BK" stat -c %Y "$RUNTIME/guard.pid" 2>/dev/null)
  case "$t" in ''|*[!0-9]*) t=0;; esac
  [ "$t" -gt 0 ] && UP=$((n - t))
fi
K=$(cfg_get KILL); P=$(cfg_get POPUP); B=$(cfg_get BLOCK_FD); S=$(cfg_get PROTECT_SD)
SC=$(cfg_get SCAN_SCRIPTS); R=$(cfg_get RESCUE_GUARD); RM=$(cfg_get BLOCK_REMOUNT); PO=$(cfg_get POWEROFF)
POLL=$(cfg_get POLL_MS); BFM=$(cfg_get BLOCK_FD_MS); WPORT=$(cfg_get WEB_PORT)
json_head
printf '{"main":%d,"keeper":%d,"watchdog":%d,"total":%d,"today":%d,"uptime":%d,' "$m" "$k" "$w" "${TOT:-0}" "${TDY:-0}" "$UP"
printf '"kill":%d,"popup":%d,"blockfd":%d,"sd":%d,"scripts":%d,"rescue":%d,"remount":%d,"poweroff":%d,' \
  "${K:-0}" "${P:-0}" "${B:-0}" "${S:-0}" "${SC:-0}" "${R:-0}" "${RM:-0}" "${PO:-0}"
printf '"poll":%d,"bfdms":%d,"port":%d}\n' "${POLL:-0}" "${BFM:-0}" "${WPORT:-0}"
