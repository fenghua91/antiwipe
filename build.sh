#!/system/bin/sh
# 构建两个二进制。在 Termux 里执行：
#   pkg install clang
#   sh build.sh
CC=${CC:-clang}
TARGET=aarch64-unknown-linux-android24
set -e
$CC --target=$TARGET -O2 -fPIE -pie -o module/bin/guard src/guard.c
$CC --target=$TARGET -O2 -fPIE -pie -o module/bin/web   src/web.c
chmod 755 module/bin/guard module/bin/web
echo "OK: module/bin/guard module/bin/web"
