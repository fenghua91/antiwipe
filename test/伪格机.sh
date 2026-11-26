#!/system/bin/sh
# ============================================================
#  伪格机脚本（纯测试，零破坏）
#  目标全是永不存在的假路径；重启/防火墙/格式化/移动/回显 全部用
#  /data/local/tmp/fakebin 里的假程序顶替。卫士关掉也炸不了。
#
#  用法：
#    sh 伪格机.sh 9      # 只跑第 9 步（单步体验）
#    sh 伪格机.sh        # 从第 1 步开始；卫士会在第 1 步终止整个脚本
# ============================================================
set +e
FB=/data/local/tmp/fakebin
mkdir -p "$FB" 2>/dev/null
for n in reboot poweroff iptables echo mkfs.ext4 mv; do
  printf '#!/system/bin/sh\necho "[假] $(basename "$0") $*"\n' > "$FB/$n" 2>/dev/null
  chmod 755 "$FB/$n" 2>/dev/null
done

run() { sh -c "$1" & wait; }

step1() { echo; echo "▶ [1] 写假块设备"; run "dd if=/dev/zero of=/dev/block/antiwipe_fake0 bs=1M count=1"; }

step2() { echo; echo "▶ [2] 递归删系统假目录"; run "rm -rf /system/antiwipe_fake_$RANDOM"; }

step3() { echo; echo "▶ [3] 递归删 data/adb 假文件"; run "rm -rf /data/adb/antiwipe_fake_$RANDOM"; }

step4() { echo; echo "▶ [4] 递归删 dev/input 假节点"; run "rm -rf /dev/input/antiwipe_fake_$RANDOM"; }

step5() { echo; echo "▶ [5] 卸载假挂载点"; run "umount -l /mnt/antiwipe_fake"; }

step6() { echo; echo "▶ [6] 查找删除假文件"; run "find /data/adb -maxdepth 1 -name 'antiwipe_fake*' -delete"; }

step7() { echo; echo "▶ [7] 清空不存在包的数据"; run "pm clear com.example.antiwipe_fake"; }

step8() { echo; echo "▶ [8] 格式化假设备"; run "/data/local/tmp/fakebin/mkfs.ext4 /dev/block/antiwipe_fake0"; }

step9() { echo; echo "▶ [9] 假重启"; run "/data/local/tmp/fakebin/reboot -f"; }

step10() { echo; echo "▶ [10] 假防火墙丢弃策略"; run "/data/local/tmp/fakebin/iptables -P INPUT DROP"; }

step11() { echo; echo "▶ [11] 假 echo 打内核路径（不写）"; run "/data/local/tmp/fakebin/echo /proc/sysrq-trigger"; }

step12() { echo; echo "▶ [12] 假移动 /data"; run "/data/local/tmp/fakebin/mv /data /data_backup_fake"; }

step13() { echo; echo "▶ [13] 正常命令（对照，不该被拦）"; run "/system/bin/ls /"; }

if [ -n "$1" ]; then
  case "$1" in
    1|2|3|4|5|6|7|8|9|10|11|12|13) step"$1" ;;
    *) echo "步骤编号 1-13"; echo "1 写假块设备 / 2-4 递归删除 / 5 卸载 / 6 查找删除 / 7 清空包 / 8 格式化 / 9 重启 / 10 防火墙 / 11 sysrq / 12 移动 / 13 正常命令" ;;
  esac
  exit 0
fi

echo "==== 伪格机脚本：全流程（卫士会在第 1 步终止整个脚本）===="
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13; do step"$i"; done
echo
echo "==== 结束（如果没有被终止，说明卫士未运行；此时也零破坏）===="
