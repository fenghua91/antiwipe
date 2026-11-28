#!/system/bin/sh
cd "$(dirname "$0")" && . ./_lib.sh
authed || deny
N=20
case "$QUERY_STRING" in *n=*) N=$(echo "$QUERY_STRING" | sed 's/.*[?&]n=\([0-9][0-9]*\).*/\1/');; esac
case "$N" in ''|*[!0-9]*) N=20;; esac
[ "$N" -gt 200 ] && N=200
json_head
printf '['
if [ -f "$LOGF" ]; then
  "$BK" tail -n 500 "$LOGF" | "$BK" awk -v n="$N" '
function lab(r){
  if(r=="BLOCK_WRITE")return "向分区写数据|c";
  if(r=="BLOCK_FD")return "偷开分区设备|c";
  if(r=="RM_RF")return "递归删系统目录|c";
  if(r=="RM_CWD")return "敏感目录批量删除|w";
  if(r=="FIND_DEL")return "查找并删除|w";
  if(r=="MKFS")return "格式化分区|c";
  if(r=="WIPE_BCAST")return "清机广播|c";
  if(r=="REBOOT")return "强制重启|w";
  if(r=="SYS_REQ")return "内核紧急重启|c";
  if(r=="PANIC")return "改 panic 参数|c";
  if(r=="IPT_POLICY")return "防火墙全丢包|w";
  if(r=="SHRED")return "粉碎文件|w";
  if(r=="UMOUNT")return "卸载分区|c";
  if(r=="MV_DATA")return "搬走 /data|c";
  if(r=="PM_CLEAR")return "清应用数据|w";
  if(r=="SETENFORCE")return "关 SELinux|c";
  if(r=="USB_KILL")return "拆 USB/ADB|c";
  if(r=="NET_DOWN")return "网卡 down|w";
  if(r=="MOUNT_RW")return "重挂系统可写|w";
  if(r=="shell"||r=="bash"||r=="mksh")return "连带杀掉 shell|i";
  if(r=="脚本树终止")return "结束脚本树|i";
  return "";
}
function esc(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/\t/," ",s); gsub(/\r/,"",s); return s }
{
  L=$0
  if(L=="" || index(L,"[调试]")) next
  if(!index(L,"[")) next
  t=""; if(match(L,/^[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) t=substr(L,7,8)
  a=index(L,"["); b=index(L,"]"); if(a==0||b==0) next
  tag=substr(L,a+1,b-a-1)
  rest=substr(L,b+1); sub(/^ +/,"",rest)
  if(tag=="弹窗") next
  isb=0; r=""; pid=""; desc=""; cmd=""
  if(tag=="拦截"){
    isb=1
    i1=index(rest," | ")
    if(i1>0){ r=substr(rest,1,i1-1); tail=substr(rest,i1+3) } else { r=rest; tail="" }
    i2=index(tail," | ")
    if(i2>0){ pd=substr(tail,1,i2-1); cmd=substr(tail,i2+3) } else { pd=tail; cmd="" }
    if(match(pd,/pid=[0-9]+/)) pid=substr(pd,RSTART+4,RLENGTH-4)
    desc=pd; sub(/pid=[0-9]+ */,"",desc); sub(/^ +/,"",desc); sub(/[ \t]+$/,"",desc)
    sub(/^[ \t]+/,"",cmd); sub(/[ \t]+$/,"",cmd)
    if(desc!="" && index(desc,"脚本预检")>0){ sub(/.*脚本预检:?[ ]*/,"",desc); desc="脚本预检命中: " desc }
    if(desc=="") desc=cmd
  } else {
    if(tag=="加固"){ desc=rest; r="加固" }
    else if(tag=="告警"){ desc=rest; r="告警" }
    else if(tag=="已移除"){ desc=rest; r="已移除" }
    else if(tag=="启动"){ desc=rest; r="启动" }
    else next
  }
  z=lab(r); c="w"; l=""
  if(z!=""){ split(z,zz,"|"); l=zz[1]; if(zz[2]=="c")c="c"; else if(zz[2]=="i")c="i" }
  if(l==""){ if(isb){l=r} else if(r=="加固"){l="自我加固"} else if(r=="告警"){l="注意"} else if(r=="已移除"){l="已处理"} else {l="启动"} }
  n2++
  out[n2]=sprintf("{\"t\":\"%s\",\"b\":%d,\"lb\":\"%s\",\"c\":\"%s\",\"r\":\"%s\",\"pid\":\"%s\",\"d\":\"%s\",\"cmd\":\"%s\"}", t, isb, esc(l), c, esc(r), pid, esc(desc), esc(cmd))
}
END{ s=n2-n+1; if(s<1)s=1; f=1; for(i=s;i<=n2;i++){ if(!first){} if(f){f=0}else printf ","; printf "%s", out[i] } }
'
fi
printf ']\n'
