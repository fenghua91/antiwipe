#!/system/bin/sh
# 伪格机对照脚本：只含正常命令，用来验证卫士不误杀
echo "[对照] uid=$(id -u)"
echo "[对照] 列 /："
/system/bin/ls / | head -3
mkdir -p /data/local/tmp/antiwipe_ok && echo x > /data/local/tmp/antiwipe_ok/a.txt
rm -rf /data/local/tmp/antiwipe_ok
echo "[对照] 完整跑完 = 没被误杀"
