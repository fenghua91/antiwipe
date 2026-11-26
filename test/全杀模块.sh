#!/system/bin/sh
# 全杀模块测试脚本：把所有模块目录下的进程一轮轮杀光，用来验证防格机卫士能不能自己回来
# 用法：
#   sh 全杀模块.sh              连杀 3 轮（默认，不动 disable 标记）
#   sh 全杀模块.sh --disable    杀完后给所有模块打 disable（下次开机也不启动，测试更彻底）
#   sh 全杀模块.sh --rounds 5   杀 5 轮
#   sh 全杀模块.sh --undo       撤销 --disable 打的标记
# 它不会碰任何分区、不删模块文件，只杀进程 + 可选打标记。
MODROOT=/data/adb/modules
UNDO=/data/adb/antiwipe/mods_stop.undo
ROUNDS=3; DISABLE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --disable) DISABLE=1;;
    --rounds) shift; ROUNDS=$1;;
    --undo)
      [ -f "$UNDO" ] || { echo "没有可撤销记录"; exit 0; }
      n=0
      while IFS= read -r f; do [ -f "$f" ] && { rm -f "$f"; n=$((n+1)); echo "恢复: $f"; }; done < "$UNDO"
      rm -f "$UNDO"; echo "已恢复 $n 个模块（下次开机生效）"; exit 0;;
    -h|--help) sed -n '2,10p' "$0"; exit 0;;
  esac
  shift
done
[ "$(id -u)" = "0" ] || { echo "需要 root：su -c 'sh $0'"; exit 1; }

module_pids() {
  for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$exe" in /data/adb/modules/*) echo "${p#/proc/} $exe"; continue;; esac
    cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$cmd" in *"/data/adb/modules/"*) echo "${p#/proc/} $cmd";; esac
  done
}

i=1
while [ "$i" -le "$ROUNDS" ]; do
  list=$(module_pids)
  cnt=$(printf '%s\n' "$list" | grep -c . )
  echo "== 第 $i 轮：发现模块进程 $cnt 个 =="
  printf '%s\n' "$list" | while read -r pid rest; do
    [ -n "$pid" ] || continue
    kill -9 "$pid" 2>/dev/null && echo "  杀 $pid $rest"
  done
  i=$((i+1)); sleep 0.4
done

if [ "$DISABLE" = "1" ]; then
  mkdir -p /data/adb/antiwipe; : > "$UNDO.new"; n=0
  for M in "$MODROOT"/*; do
    [ -d "$M" ] || continue
    [ -f "$M/disable" ] || printf '%s\n' "$M/disable" >> "$UNDO.new"
    : > "$M/disable"; echo "已停用: ${M##*/}"; n=$((n+1))
  done
  sort -u "$UNDO.new" > "$UNDO"; rm -f "$UNDO.new"
  echo "共停用 $n 个模块（撤销：sh $0 --undo）"
fi

echo "== 等 4 秒看谁自己回来了 =="
sleep 4
list=$(module_pids)
cnt=$(printf '%s\n' "$list" | grep -c .)
echo "存活/复活 $cnt 个："
printf '%s\n' "$list" | while read -r pid rest; do [ -n "$pid" ] && echo "  $pid $rest"; done
echo "---- 说明：guard 出现 3 个（main/-k/-w）说明互拉成功；只出现 0 个说明被彻底按住"
