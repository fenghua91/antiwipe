#!/system/bin/sh
cd "$(dirname "$0")" && . ./_lib.sh
authed || deny
json_head
printf '{"text":"'
cat "$CONF" 2>/dev/null | jesc
printf '"}'
