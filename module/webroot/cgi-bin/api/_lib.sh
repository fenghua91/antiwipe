#!/system/bin/sh
# 公共定义：路径、busybox、令牌校验、JSON 转义
RUNTIME=/data/adb/antiwipe
MODDIR=/data/adb/modules/antiwipe
CONF=$RUNTIME/config.conf
LOGF=$RUNTIME/events.log
TOKF=$RUNTIME/web.token
BB=""
for p in /data/adb/ksu/bin/busybox /data/adb/magisk/busybox /system/xbin/busybox /system/bin/busybox; do
  [ -x "$p" ] && { BB=$p; break; }
done
BK=${BB:-busybox}
TOKEN=$(cat "$TOKF" 2>/dev/null | tr -d '\r\n')

json_head() { printf 'Content-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\n\r\n'; }
html_head() { printf 'Content-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n\r\n'; }
deny() { printf 'Status: 401 Unauthorized\r\n'; json_head; printf '{"error":"unauthorized"}'; exit 0; }

authed() {
  [ -n "$TOKEN" ] || return 1
  case "$QUERY_STRING" in *"tk=$TOKEN"*) return 0;; esac
  case "${HTTP_COOKIE:-}" in *"tk=$TOKEN"*) return 0;; esac
  return 1
}

# 把 stdin 转成合法 JSON 字符串内容（不含引号）
jesc() { "$BK" sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/ /g' | "$BK" tr -d '\r' | "$BK" tr '\n' ' '; }

cfg_get() { "$BK" grep -m1 "^$1=" "$CONF" 2>/dev/null | "$BK" cut -d= -f2- | tr -d '\r\n '; }
