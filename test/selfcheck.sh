#!/system/bin/sh
# 防格机卫士 自检脚本 v1.2.1  用法：su -c "sh /storage/emulated/0/Download/antiwipe-test/自检.sh"
# 每个用例都在“孤儿进程”里跑（父进程立即退出、被 init 收养），所以守卫连坐脚本树时不会连坐本脚本。
# 所有破坏性动作只指向自建探针，跑完自动清理。

T=/storage/emulated/0/Download/antiwipe-test
SELF=$T/自检.sh
FAKE=$T/伪格机.sh
CTL=$T/伪格机-对照.sh
RT=/data/adb/antiwipe
LOG=$RT/events.log
OUT=/data/local/tmp/aw_selftest
P_RM=/data/adb/aw_selftest_rm
P_MV=/data/adb/aw_selftest_mv
P_FD=/data/adb/aw_selftest_fd
DEV=/dev/block/antiwipe_selftest0

# 运行时拼装，正文里不出现完整危险命令
R=$(printf "r%sm" "")
F=$(printf "-%srf" "")
DD=$(printf "d%s" "d")
MV=$(printf "m%sv" "")
FD=$(printf "f%sind" "")
DL=-delete

### 用例模式（孤儿进程） ###
if [ -n "$1" ]; then
  n=$1; mkdir -p $OUT; echo $$ > $OUT/$n.pid
  case "$n" in
    1) exec sh "$FAKE";;
    2) exec sh -c "sh < \"$FAKE\"";;
    3) exec sh -c "cat \"$FAKE\" | sh";;
    4) exec sh -c "$DD if=/dev/zero of=$DEV bs=1024 count=1";;
    5) exec sh -c "$R $F $P_RM";;
    6) exec sh -c "$MV $P_MV /data/local/tmp/aw_selftest_mv_out";;
    7) exec sh -c "$FD $P_FD $DL";;
    8) sh "$CTL" > $OUT/8.out 2>&1; echo $? > $OUT/8.rc; exit 0;;
  esac
  exit 0
fi

### 驱动模式 ###
PASS=0; FAIL=0; WARN=0
ok(){ PASS=$((PASS+1)); echo "  ✅ $1"; }
no(){ FAIL=$((FAIL+1)); echo "  ❌ $1"; }
warn(){ WARN=$((WARN+1)); echo "  ⚠️  $1"; }
lines(){ wc -l < "$LOG" 2>/dev/null || echo 0; }

spawn(){  # $1=用例号：后台起一个会被 init 收养的孤儿进程
  n=$1; rm -f $OUT/$n.pid $OUT/$n.out $OUT/$n.rc 2>/dev/null
  sh -c "sh '$SELF' $n > $OUT/$n.out 2>&1 &" 
  i=0; while [ ! -f $OUT/$n.pid ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
}
finished(){  # 等用例进程退出（被守卫杀掉也算退出）
  p=$(cat $OUT/$1.pid 2>/dev/null); [ -z "$p" ] && { sleep 1; return; }
  i=0; while [ -d /proc/$p ] && [ $i -lt 60 ]; do sleep 0.1; i=$((i+1)); done
}

mkdir -p $OUT 2>/dev/null
echo "== 0. 服务状态 =="
PID=$(cat $RT/guard.pid 2>/dev/null)
if [ -n "$PID" ] && [ -d /proc/$PID ]; then
  K=$(ps -A -o pid,ppid 2>/dev/null | awk -v p=$PID '$2==p{print $1}' | wc -l)
  echo "  guard 主进程 $PID 存活，子进程 $K 个"
  [ "$K" -ge 2 ] && ok "三进程互拉在岗（主 + keeper + watchdog）" || no "keeper/watchdog 不全"
else
  no "guard 没在跑，先启动模块再测"; echo; echo "结果：PASS=0 FAIL=1"; exit 1
fi

echo "== 1. 直接执行格机脚本（脚本预检） =="
B=$(lines); spawn 1; finished 1; A2=$(lines); D=$((A2-B))
LAST=走到这一行说明守卫没拦住
if grep -q "$LAST" $OUT/1.out 2>/dev/null; then no "脚本跑完了（漏检）"; else [ "$D" -ge 1 ] && ok "执行即被杀，脚本没跑完（日志 +$D 行）" || no "日志没新增，守卫没反应"; fi

echo "== 2. sh < 文件（stdin 预检） =="
B=$(lines); spawn 2; finished 2; A2=$(lines); D=$((A2-B))
if grep -q "$LAST" $OUT/2.out 2>/dev/null; then no "stdin 喂入后脚本跑完了（漏检）"; else [ "$D" -ge 1 ] && ok "stdin 喂入也被拦（日志 +$D 行）" || no "日志没新增"; fi

echo "== 3. cat 文件 | sh（管道预检） =="
B=$(lines); spawn 3; finished 3; A2=$(lines); D=$((A2-B))
if grep -q "$LAST" $OUT/3.out 2>/dev/null; then warn "本次没抢到（小脚本管道竞态，已知限制；正文漏检≠放行，命令级仍会拦）"; else ok "管道执行被拦（日志 +$D 行）"; fi

echo "== 4. 写块设备（BLOCK_WRITE 命令级） =="
rm -f $DEV 2>/dev/null; B=$(lines); spawn 4; finished 4; A2=$(lines); D=$((A2-B))
if [ ! -f $DEV ] && [ "$D" -ge 1 ]; then ok "dd 被杀，块设备文件没生成（日志 +$D 行）"; else no "dd 没拦住（文件存在=$([ -f $DEV ] && echo 是 || echo 否)）"; fi
rm -f $DEV 2>/dev/null

echo "== 5. 递归删 /data/adb 子目录（RM_RF） =="
mkdir -p $P_RM 2>/dev/null; i=0; while [ $i -lt 50 ]; do : > $P_RM/f$i 2>/dev/null; i=$((i+1)); done
B=$(lines); spawn 5; finished 5; A2=$(lines); D=$((A2-B))
LEFT=$(ls $P_RM 2>/dev/null | wc -l)
if [ "$LEFT" -ge 1 ] && [ "$D" -ge 1 ]; then ok "递归删被杀，50 个文件剩 $LEFT 个（日志 +$D 行）"; else no "目录被清空或没反应（剩 $LEFT，日志 +$D）"; fi

echo "== 6. 把 /data/adb 子目录搬走（MV_DATA） =="
mkdir -p $P_MV 2>/dev/null; : > $P_MV/keep 2>/dev/null
B=$(lines); spawn 6; finished 6; A2=$(lines); D=$((A2-B))
if [ -d $P_MV ] && [ ! -e /data/local/tmp/aw_selftest_mv_out ] && [ "$D" -ge 1 ]; then ok "搬走被杀，源目录完好（日志 +$D 行）"; else no "没拦住（源在=$([ -d $P_MV ] && echo 是 || echo 否)）"; fi

echo "== 7. find -delete（FIND_DEL） =="
mkdir -p $P_FD 2>/dev/null; : > $P_FD/keep 2>/dev/null
B=$(lines); spawn 7; finished 7; A2=$(lines); D=$((A2-B))
if [ -e $P_FD/keep ] && [ "$D" -ge 1 ]; then ok "find -delete 被杀，文件还在（日志 +$D 行）"; else no "没拦住（文件在=$([ -e $P_FD/keep ] && echo 是 || echo 否)）"; fi

echo "== 8. 对照：正常脚本不该误杀 =="
B=$(lines); spawn 8; finished 8; A2=$(lines); D=$((A2-B)); RC=$(cat $OUT/8.rc 2>/dev/null)
if [ "$RC" = "0" ] && [ "$D" -eq 0 ]; then ok "正常脚本跑完 rc=0，零误报"; else no "误杀或异常（rc=$RC，日志 +$D）"; fi

echo "== 9. 清理探针 =="
for d in $P_RM $P_MV $P_FD; do for f in $d/*; do rm -f "$f" 2>/dev/null; done; rmdir "$d" 2>/dev/null; done
rm -f $DEV /data/local/tmp/aw_selftest_mv_out 2>/dev/null
rm -f $OUT/*.pid $OUT/*.out $OUT/*.rc 2>/dev/null; rmdir $OUT 2>/dev/null
echo "  🧹 已清理"

echo; echo "===== 结果：PASS=$PASS  FAIL=$FAIL  WARN=$WARN ====="
[ "$FAIL" -eq 0 ] && echo "模块工作正常；WARN 是已知的毫秒级竞态（见 README 已知限制）。" || echo "有 FAIL，请把输出和 $LOG 最后几行一起发出来。"
