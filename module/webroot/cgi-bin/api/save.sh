#!/system/bin/sh
cd "$(dirname "$0")" && . ./_lib.sh
authed || deny
json_head
if [ "$REQUEST_METHOD" != "POST" ]; then printf '{"ok":false,"error":"method"}'; exit 0; fi
LEN=${CONTENT_LENGTH:-0}
BODY=$(dd bs=1 count="$LEN" 2>/dev/null)
# 逐个 k=v 重写 config.conf，值做 URL 解码（+ 与 %XX）
echo "$BODY" | "$BK" tr '&' '\n' | while IFS= read -r kv; do
  k=${kv%%=*}
  v=${kv#*=}
  case "$k" in ''|*[!A-Za-z_]*) continue;; esac
  dv=$(printf '%s' "$v" | "$BK" sed -e 's/+/ /g' -e 's/%\([0-9A-Fa-f][0-9A-Fa-f]\)/\\x\1/g')
  dv=$(printf '%b' "$dv" 2>/dev/null)
  [ -f "$CONF" ] || continue
  if "$BK" grep -q "^$k=" "$CONF"; then
    "$BK" sed -i "s|^$k=.*|$k=$dv|" "$CONF"
  else
    printf '%s=%s\n' "$k" "$dv" >> "$CONF"
  fi
done
setsid "$MODDIR/service.sh" >/dev/null 2>&1 &
printf '{"ok":true}'
