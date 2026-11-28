#!/system/bin/sh
cd "$(dirname "$0")" && . ./_lib.sh
authed || deny
json_head
for p in /proc/[0-9]*; do
  e=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$e" in "$MODDIR"/bin/guard|"$RUNTIME"/run/*) kill -9 "${p#/proc/}" 2>/dev/null;; esac
done
sleep 1
rm -f "$RUNTIME"/keeper.lock "$RUNTIME"/watchdog.lock "$RUNTIME"/guard.lock "$RUNTIME"/guard.pid
mkdir -p "$RUNTIME/run"
NEW="$RUNTIME/run/.g$(date +%s)$$"
cp -f "$MODDIR/bin/guard" "$NEW" && chmod 755 "$NEW"
setsid "$NEW" >/dev/null 2>&1 </dev/null &
sleep 1
P=""; [ -f "$RUNTIME/guard.pid" ] && P=$(cat "$RUNTIME/guard.pid")
printf '{"ok":true,"pid":"%s"}' "$P"
