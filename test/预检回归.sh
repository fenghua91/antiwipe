#!/system/bin/sh
# 预检回归：用 guard -P 判定样本脚本，全程只做文本读取，不执行样本内容
# 用法：sh test/预检回归.sh [guard 可执行文件]
# 依赖：v1.3.0 起提供的 -P 模式

GUARD="$1"
if [ -z "$GUARD" ]; then
  D="${0%/*}"
  GUARD="$D/../bin/guard"
fi
[ -x "$GUARD" ] || { echo "找不到 guard: $GUARD"; exit 2; }

TMP=/data/local/tmp/antiwipe-regress
rm -rf "$TMP"; mkdir -p "$TMP"
pass=0; fail=0

check() { # $1=用例名 $2=期望规则 $3=guard -P 的参数
  got=$("$GUARD" -P "$3" 2>/dev/null | cut -f1)
  if [ "$got" = "$2" ]; then
    pass=$((pass+1)); printf '  ok   %-28s %s\n' "$1" "$got"
  else
    fail=$((fail+1)); printf '  FAIL %-28s 期望 %s 实得 %s\n' "$1" "$2" "${got:-空}"
  fi
}

w() { printf '%s\n' "$2" > "$TMP/$1"; }

w setenforce.sh  'setenforce 0 2>/dev/null'
w usb.sh         'setprop sys.usb.config none 2>/dev/null'
w ifdown.sh      'ip link set eth0 down 2>/dev/null'
w rmrf.sh        'rm -rf /data 2>/dev/null'
w blk.sh         'dd if=/dev/urandom of=/dev/block/by-name/abl bs=4M conv=fsync'
w clean.sh       'echo hello'
w clean.sh       'ls -l /'

echo "== 预检回归 =="
check "关 SELinux"        SETENFORCE "sh $TMP/setenforce.sh"
check "关 USB"            USB_KILL   "sh $TMP/usb.sh"
check "网卡 down"         NET_DOWN   "sh $TMP/ifdown.sh"
check "递归删 /data"      RM_RF      "sh $TMP/rmrf.sh"
check "写块设备"          BLOCK_WRITE "sh $TMP/blk.sh"
check "正常脚本放行"      MISS       "sh $TMP/clean.sh"
check "卫士自身脚本放行"  MISS       "sh /data/adb/antiwipe/service.sh"

# 相对路径：旧版会整个跳过预检
OLDPWD=$PWD
cd "$TMP" 2>/dev/null && check "相对路径 sh x.sh" SETENFORCE "sh setenforce.sh"
cd "$OLDPWD" 2>/dev/null

# 危险行藏在 2MB 之后：旧版 1MB 截断会漏
{ printf 'echo safe\n'; dd if=/dev/zero bs=1024 count=2048 2>/dev/null; printf 'rm -rf /data\n'; } > "$TMP/big.sh" 2>/dev/null
check "危险行在 2MB 之后"  RM_RF      "sh $TMP/big.sh"

rm -rf "$TMP"
echo "== 通过 $pass，失败 $fail =="
[ "$fail" = "0" ] || exit 1
