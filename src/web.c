/* 防格机卫士 · Web 控制台 v2.5
 * 纯用户态，只读 /data 下的日志与配置，不写任何分区。
 * 设计目标：一眼看懂「现在安不安全」+ 日志说人话。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <dirent.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define RUNTIME "/data/adb/antiwipe"
#define MODDIR  "/data/adb/modules/antiwipe"
#define TOKENF  RUNTIME "/web.token"
#define CONFF   RUNTIME "/config.conf"
#define LOGF    RUNTIME "/events.log"
#define WEBLOG  RUNTIME "/web.log"
#define GUARDBIN MODDIR "/bin/guard"
#define RUNDIR  RUNTIME "/run"
#define VIEWMAX (512*1024)
#define VERSION "2.5"

typedef struct { char *p; size_t len, cap; } sb_t;
static void sb_init(sb_t *b){ b->cap=16384; b->len=0; b->p=malloc(b->cap); b->p[0]=0; }
static void sb_need(sb_t *b,size_t n){ if(b->len+n+1>b->cap){ while(b->cap<b->len+n+1) b->cap*=2; b->p=realloc(b->p,b->cap);} }
static void sb_putn(sb_t *b,const char*s,size_t n){ sb_need(b,n); memcpy(b->p+b->len,s,n); b->len+=n; b->p[b->len]=0; }
static void sb_put(sb_t *b,const char*s){ sb_putn(b,s,strlen(s)); }
static void sb_putc(sb_t *b,char c){ sb_putn(b,&c,1); }
static void sb_printf(sb_t *b,const char*fmt,...){ va_list ap; char tmp[8192]; va_start(ap,fmt); int n=vsnprintf(tmp,sizeof tmp,fmt,ap); va_end(ap); if(n>0) sb_putn(b,tmp,(size_t)n); }
static void esc(sb_t *b,const char*s){ for(;*s;s++){ unsigned char c=*s; if(c=='&')sb_put(b,"&amp;"); else if(c=='<')sb_put(b,"&lt;"); else if(c=='>')sb_put(b,"&gt;"); else if(c=='"')sb_put(b,"&quot;"); else sb_putc(b,(char)c);} }
static void escn(sb_t *b,const char*s,size_t n){ for(size_t i=0;i<n;i++){ unsigned char c=(unsigned char)s[i]; if(c=='&')sb_put(b,"&amp;"); else if(c=='<')sb_put(b,"&lt;"); else if(c=='>')sb_put(b,"&gt;"); else if(c=='"')sb_put(b,"&quot;"); else sb_putc(b,(char)c);} }

static char TOKEN[33];

static void ensure_token(void){
    FILE *f=fopen(TOKENF,"r");
    if(f){ if(fgets(TOKEN,sizeof TOKEN,f)) TOKEN[strcspn(TOKEN,"\r\n")]=0; fclose(f); if(strlen(TOKEN)>=8) return; }
    unsigned char b[8]; int fd=open("/dev/urandom",O_RDONLY); int i;
    if(fd>=0){ if(read(fd,b,8)!=8) memset(b,0,8); close(fd);} else { srand((unsigned)time(0)); for(i=0;i<8;i++) b[i]=(unsigned char)(rand()&0xff); }
    for(i=0;i<8;i++) sprintf(TOKEN+2*i,"%02x",b[i]);
    f=fopen(TOKENF,"w"); if(f){ fprintf(f,"%s\n",TOKEN); fclose(f);} chmod(TOKENF,0600);
}

static void urldecode(const char*s,char*out,size_t on){
    size_t j=0;
    while(*s && j+1<on){
        if(*s=='%' && isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2])){
            char h[3]={s[1],s[2],0}; out[j++]=(char)strtol(h,0,16); s+=3;
        } else if(*s=='+'){ out[j++]=' '; s++; } else out[j++]=*s++;
    }
    out[j]=0;
}

static int get_param(const char*q,const char*name,char*out,size_t on){
    size_t nl=strlen(name); const char*p=q;
    while(p && *p){
        const char*amp=strchr(p,'&');
        size_t seg=amp?(size_t)(amp-p):strlen(p);
        if(seg>nl && !strncmp(p,name,nl) && p[nl]=='='){
            char tmp[4096];
            if(seg-nl-1<sizeof tmp){ memcpy(tmp,p+nl+1,seg-nl-1); tmp[seg-nl-1]=0; urldecode(tmp,out,on); return 1; }
        }
        p=amp?amp+1:NULL;
    }
    return 0;
}

static void urlenc(const char*s,char*out,size_t on){
    size_t j=0;
    for(;*s && j+3<on;s++){
        unsigned char c=(unsigned char)*s;
        if(isalnum(c)||c=='/'||c=='-'||c=='_'||c=='.'||c=='~') out[j++]=(char)c;
        else j+=(size_t)snprintf(out+j,on-j,"%%%02X",c);
    }
    out[j]=0;
}

static int authed(const char*q,const char*hdr){
    char tk[64];
    if(get_param(q,"tk",tk,sizeof tk) && !strcmp(tk,TOKEN)) return 1;
    const char*c=strstr(hdr,"Cookie:");
    if(c){ c=strstr(c,"tk="); if(c){ c+=3; size_t n=strcspn(c,";\r\n"); if(n==strlen(TOKEN) && !strncmp(c,TOKEN,n)) return 1; } }
    return 0;
}

static int read_all(const char*path,char**out,size_t*outlen,size_t max){
    int fd=open(path,O_RDONLY); if(fd<0) return -1;
    struct stat st; if(fstat(fd,&st)<0){ close(fd); return -1; }
    size_t n=(size_t)st.st_size; if(n>max) n=max;
    char*buf=malloc(n+1); if(!buf){ close(fd); return -1; }
    size_t got=0; while(got<n){ ssize_t r=read(fd,buf+got,n-got); if(r<=0) break; got+=(size_t)r; }
    close(fd); buf[got]=0; *out=buf; *outlen=got; return 0;
}

static void send_all(int fd,const char*buf,size_t n){ size_t off=0; while(off<n){ ssize_t w=send(fd,buf+off,n-off,MSG_NOSIGNAL); if(w<=0) return; off+=(size_t)w; } }

static void respond(int fd,int code,const char*type,const char*extra,const char*body,size_t len){
    char h[1024];
    const char*reason = code==200?"OK":code==302?"Found":code==400?"Bad Request":code==401?"Unauthorized":code==404?"Not Found":code==500?"Error":"OK";
    int n=snprintf(h,sizeof h,"HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nCache-Control: no-store\r\nConnection: close\r\n%s\r\n",code,reason,type,len,extra?extra:"");
    send_all(fd,h,(size_t)n);
    send_all(fd,body,len);
}
static void respond_sb(int fd,int code,const char*extra,sb_t*b){ respond(fd,code,"text/html; charset=utf-8",extra,b->p,b->len); }

/* ---------------- 外观 ---------------- */
static const char *CSS =
":root{--bg:#05070b;--pan:#0a1018;--pan2:#0d141e;--line:rgba(120,200,255,.13);--tx:#e6edf7;--dim:#6b7a90;--dim2:#93a3b8;--cy:#22d3ee;--gr:#34d399;--am:#fbbf24;--rd:#f87171;--vi:#a78bfa}"
"*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}"
"body{margin:0;background:radial-gradient(900px 480px at 50% -8%,#0c1a2b 0%,#05070b 62%) fixed,#05070b;color:var(--tx);"
"font:15px/1.55 -apple-system,'SF Pro Text','PingFang SC',Roboto,sans-serif;-webkit-font-smoothing:antialiased}"
"body:before{content:'';position:fixed;inset:0;pointer-events:none;"
"background-image:linear-gradient(rgba(120,200,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(120,200,255,.05) 1px,transparent 1px);"
"background-size:46px 46px;-webkit-mask-image:radial-gradient(circle at 50% 0,#000 0%,transparent 72%)}"
".wrap{position:relative;max-width:660px;margin:0 auto;padding:22px 16px 56px}"
".mono{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-variant-numeric:tabular-nums}"
"a{color:var(--cy);text-decoration:none}a:hover{opacity:.82}"
"header.hero{padding:6px 0 18px;border-bottom:1px solid var(--line);margin-bottom:18px}"
".brand{display:flex;align-items:center;gap:8px;font-size:11px;letter-spacing:.2em;color:var(--dim);text-transform:uppercase}"
".live{width:7px;height:7px;border-radius:50%;background:var(--gr);box-shadow:0 0 0 0 rgba(52,211,153,.7);animation:pulse 2.2s infinite}"
"@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(52,211,153,.55)}70%{box-shadow:0 0 0 9px rgba(52,211,153,0)}100%{box-shadow:0 0 0 0 rgba(52,211,153,0)}}"
"h1{margin:10px 0 2px;font-size:26px;letter-spacing:-.02em;font-weight:650}"
".sub{color:var(--dim);font-size:12.5px;letter-spacing:.02em}"
".pills{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}"
".pill{font-size:11px;letter-spacing:.06em;padding:3px 9px;border-radius:999px;border:1px solid var(--line);color:var(--dim2);background:rgba(10,16,24,.65)}"
".pill.on{color:var(--gr);border-color:rgba(52,211,153,.35);background:rgba(52,211,153,.08)}"
".pill.off{color:var(--rd);border-color:rgba(248,113,113,.35);background:rgba(248,113,113,.08)}"
"nav{display:flex;gap:2px;margin:0 0 18px;padding:4px;background:var(--pan);border:1px solid var(--line);border-radius:12px}"
"nav a{flex:1;text-align:center;font-size:13px;padding:8px 0;border-radius:9px;color:var(--dim2)}"
"nav a.on{background:var(--pan2);color:var(--tx);box-shadow:inset 0 1px 0 rgba(255,255,255,.04)}"
".grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:16px 0}"
".stat{background:linear-gradient(180deg,var(--pan2),var(--pan));border:1px solid var(--line);border-radius:14px;padding:13px 14px}"
".stat .k{font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim)}"
".stat .v{font-size:27px;line-height:1.25;letter-spacing:-.01em;margin-top:5px;font-weight:600}"
".stat .u{font-size:11px;color:var(--dim);margin-left:4px;font-weight:400;letter-spacing:0}"
".cy{color:var(--cy)}.gr{color:var(--gr)}.am{color:var(--am)}.rd{color:var(--rd)}.vi{color:var(--vi)}"
".card{background:linear-gradient(180deg,rgba(13,20,30,.92),rgba(10,16,24,.92));border:1px solid var(--line);border-radius:14px;padding:14px 15px;margin:12px 0}"
".card h2{margin:0 0 2px;font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim);font-weight:600}"
".hint{font-size:12px;color:var(--dim);margin-top:2px}"
".ev{padding:11px 0;border-bottom:1px solid rgba(120,200,255,.08)}.ev:last-child{border-bottom:0}"
".evh{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:11px;color:var(--dim)}"
".badge{font-size:10.5px;letter-spacing:.08em;padding:2px 7px;border-radius:6px;font-weight:600;text-transform:uppercase}"
".b-crit{background:rgba(248,113,113,.12);color:#fca5a5;border:1px solid rgba(248,113,113,.32)}"
".b-warn{background:rgba(251,191,36,.1);color:#fcd34d;border:1px solid rgba(251,191,36,.3)}"
".b-info{background:rgba(167,139,250,.1);color:#c4b5fd;border:1px solid rgba(167,139,250,.3)}"
".evd{font-size:14px;margin-top:4px;line-height:1.45}"
".evd b{color:var(--tx);font-weight:600}"
".evc{font-size:11.5px;color:var(--dim);margin-top:3px;font-family:ui-monospace,Menlo,monospace;word-break:break-all}"
"pre{background:#05080d;border:1px solid var(--line);border-radius:11px;padding:12px;overflow:auto;font:12px/1.55 ui-monospace,Menlo,monospace;color:#b9c7d9;white-space:pre-wrap;word-break:break-all;margin:8px 0 0}"
"table{width:100%;border-collapse:collapse;font-size:13.5px}td{padding:9px 0;border-bottom:1px solid rgba(120,200,255,.08);vertical-align:top}"
"td.r{text-align:right;color:var(--dim);font-size:12px;white-space:nowrap;padding-left:10px}"
".fol{color:var(--cy);opacity:.85;margin-right:6px;font-size:12px}"
"input[type=text],input[type=number],textarea{background:#05080d;color:var(--tx);border:1px solid rgba(120,200,255,.16);border-radius:10px;padding:9px 11px;"
"font:13px ui-monospace,Menlo,monospace;width:100%;outline:none}"
"input:focus,textarea:focus{border-color:rgba(34,211,238,.55);box-shadow:0 0 0 3px rgba(34,211,238,.08)}"
"textarea{min-height:120px;resize:vertical}"
"label.sw{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 0;border-bottom:1px solid rgba(120,200,255,.08);font-size:14px}"
"label.sw:last-of-type{border-bottom:0}"
"label.sw .d{font-size:11.5px;color:var(--dim);margin-top:2px;line-height:1.4}"
"input[type=checkbox]{appearance:none;width:42px;height:24px;border-radius:999px;background:#131b27;border:1px solid var(--line);position:relative;flex:0 0 auto;cursor:pointer;transition:.18s}"
"input[type=checkbox]:checked{background:rgba(34,211,238,.22);border-color:rgba(34,211,238,.55)}"
"input[type=checkbox]:after{content:'';position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:50%;background:#8b98ab;transition:.18s}"
"input[type=checkbox]:checked:after{left:20px;background:var(--cy);box-shadow:0 0 10px rgba(34,211,238,.75)}"
"button{background:linear-gradient(180deg,#1b2a3d,#131c28);color:var(--tx);border:1px solid rgba(120,200,255,.2);border-radius:10px;padding:10px 16px;"
"font-size:13.5px;letter-spacing:.02em;margin-top:12px;cursor:pointer}"
"button.pri{background:linear-gradient(180deg,rgba(34,211,238,.22),rgba(34,211,238,.1));border-color:rgba(34,211,238,.45);color:#b8f3ff}"
"button:hover{border-color:rgba(120,200,255,.4)}"
".row{display:flex;gap:10px;flex-wrap:wrap}.row>div{flex:1;min-width:130px}"
"details{margin-top:8px}summary{font-size:12px;color:var(--dim);cursor:pointer;outline:none}"
".banner{border:1px solid rgba(248,113,113,.35);background:rgba(248,113,113,.08);border-radius:12px;padding:11px 13px;font-size:13px;color:#fca5a5;margin:12px 0}"
".banner.ok{border-color:rgba(52,211,153,.3);background:rgba(52,211,153,.07);color:#86efac}"
".foot{text-align:center;font-size:11px;color:#465468;margin-top:26px;letter-spacing:.08em}";

static const char*NAV[][2]={{"概览","/"},{"事件","/logs"},{"配置","/config"},{"文件","/dir"}};

static void page_head(sb_t*b,const char*title,const char*cur){
    sb_put(b,"<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>");
    sb_put(b,"<meta name='viewport' content='width=device-width,initial-scale=1,viewport-fit=cover'>");
    sb_put(b,"<meta name='theme-color' content='#05070b'>");
    sb_printf(b,"<title>%s · 防格机卫士</title><style>",title);
    sb_put(b,CSS);
    sb_put(b,"</style></head><body><div class='wrap'>");
    sb_put(b,"<header class='hero'><div class='brand'><span class='live'></span><span>anti-wipe</span><span class='mono' style='color:#3d4a5c'>v" VERSION "</span></div>");
    sb_put(b,"<h1>防格机卫士</h1><div class='sub'>纯用户态防护 · 不写任何分区 · 仅监听 127.0.0.1</div></header>");
    sb_put(b,"<nav>");
    for(size_t i=0;i<sizeof NAV/sizeof NAV[0];i++){
        sb_printf(b,"<a href='%s'%s>%s</a>",NAV[i][1],
            (cur && !strcmp(cur,NAV[i][0]))?" class='on'":"",NAV[i][0]);
    }
    sb_put(b,"</nav>");
}
static void page_tail(sb_t*b){
    sb_printf(b,"<div class='foot'>ANTI-WIPE v" VERSION " · 用户态 · 零分区写入</div></div></body></html>");
}

/* ---------------- 日志解析：把机器日志翻成人话 ---------------- */
typedef struct {
    char ts[24]; char tag[24]; char rule[40];
    int  pid; int has_pid;
    char desc[512];
    char cmd[512];
} ev_t;

static void clean_inplace(char*s){
    size_t L=strlen(s);
    while(L && (s[L-1]=='\r'||s[L-1]=='\n'||s[L-1]==' '||s[L-1]=='\t'||s[L-1]=='"')) s[--L]=0;
    while(*s==' '||*s=='\t'||*s=='"') memmove(s,s+1,strlen(s));
}

static int parse_ev(const char*line,size_t len,ev_t*e){
    memset(e,0,sizeof *e);
    char buf[1024];
    if(len>=sizeof buf) len=sizeof buf-1;
    memcpy(buf,line,len); buf[len]=0; clean_inplace(buf);
    if(!buf[0]) return 0;
    const char*p=buf;
    /* 时间戳 MM-DD HH:MM:SS.mmm */
    if(strlen(p)>18 && p[2]=='-' && p[5]==' ' && p[8]==':' && p[11]==':' && p[14]=='.'){ memcpy(e->ts,p,18); e->ts[18]=0; p+=19; }
    if(*p=='['){ const char*e2=strchr(p,']'); if(e2){ size_t n=(size_t)(e2-p-1); if(n>=sizeof e->tag) n=sizeof e->tag-1; memcpy(e->tag,p+1,n); e->tag[n]=0; p=e2+1; } }
    while(*p==' ') p++;
    /* 规则名：第一个 token（拦截行的规则；其它行可能是中文短语） */
    {
        size_t n=0;
        while(p[n] && p[n]!=' ' && p[n]!='|' && n<sizeof e->rule-1){ e->rule[n]=p[n]; n++; }
        e->rule[n]=0;
    }
    const char*pipe=strchr(p,'|');
    const char*pidp=strstr(p,"pid=");
    if(pidp) e->pid=atoi(pidp+4), e->has_pid=(e->pid>0);
    if(pipe){
        const char*rest=pipe+1;
        while(*rest==' ') rest++;
        /* 跳过 pid=N 前缀 */
        if(!strncmp(rest,"pid=",4)){ const char*s=rest; while(*s && *s!=' ') s++; while(*s==' ')s++; rest=s; }
        const char*pipe2=strchr(rest,'|');
        size_t n=pipe2?(size_t)(pipe2-rest):strlen(rest);
        if(n>=sizeof e->desc) n=sizeof e->desc-1;
        memcpy(e->desc,rest,n); e->desc[n]=0; clean_inplace(e->desc);
        if(pipe2){ const char*c=pipe2+1; while(*c==' ')c++; snprintf(e->cmd,sizeof e->cmd,"%s",c); clean_inplace(e->cmd); }
    } else {
        snprintf(e->desc,sizeof e->desc,"%s",p);
        clean_inplace(e->desc);
    }
    /* 弹窗行：[弹窗] [RULE] 已拦截 pid=N desc */
    if(!strcmp(e->tag,"弹窗")){
        const char*b1=strchr(e->desc,'[');
        if(b1){ const char*b2=strchr(b1,']'); if(b2){ size_t n=(size_t)(b2-b1-1); if(n<sizeof e->rule){ memcpy(e->rule,b1+1,n); e->rule[n]=0; } } }
    }
    /* BLOCK_FD 进程已杀: desc | exe=... */
    char*k, *hit=strstr(e->desc,"进程已杀:");
    if(hit){ memmove(e->desc,hit+strlen("进程已杀:"),strlen(hit+strlen("进程已杀:"))+1); clean_inplace(e->desc); }
    if((k=strstr(e->desc,"exe="))){ snprintf(e->cmd,sizeof e->cmd,"%s",k+4); *k=0; clean_inplace(e->desc); }
    return 1;
}

typedef struct { const char*code; const char*zh; const char*cls; } rulemap_t;
static const rulemap_t RULES[]={
    {"BLOCK_WRITE","向分区直接写数据","crit"},
    {"BLOCK_FD",   "进程偷偷打开了分区设备","crit"},
    {"RM_RF",      "递归删除系统目录","crit"},
    {"RM_CWD",     "在敏感目录里批量删除","warn"},
    {"FIND_DEL",   "查找并删除文件","warn"},
    {"MKFS",       "格式化分区","crit"},
    {"WIPE_BCAST", "发送清机 / 恢复出厂广播","crit"},
    {"REBOOT",     "强制重启设备","warn"},
    {"SYS_REQ",    "触发内核紧急重启","crit"},
    {"PANIC",      "改内核崩溃参数","crit"},
    {"IPT_POLICY", "把防火墙设成全部丢包","warn"},
    {"SHRED",      "粉碎文件","warn"},
    {"UMOUNT",     "卸载分区","crit"},
    {"MV_DATA",    "搬走 /data 目录","crit"},
    {"PM_CLEAR",   "清空应用数据","warn"},
    {"shell",      "连带终止了它的 shell","info"},
    {"bash",       "连带终止了它的 shell","info"},
    {"mksh",       "连带终止了它的 shell","info"},
    {"脚本树终止", "结束整棵脚本树","info"},
    {"包装shell",  "结束了外层包装 shell","info"},
    {NULL,NULL,NULL}
};
static const rulemap_t* rule_find(const char*r){
    for(int i=0;RULES[i].code;i++) if(!strcmp(RULES[i].code,r)) return &RULES[i];
    return NULL;
}
static const char* rule_cls(const char*r){
    const rulemap_t*m=rule_find(r); return m?m->cls:"info";
}

/* 从命令行里猜「谁在干」：只认「直接调用某个路径」或「sh 某个脚本」 */
static void actor_of(const ev_t*e,char*out,size_t on){
    out[0]=0;
    const char*c=e->cmd[0]?e->cmd:NULL;
    if(!c || !c[0]) return;
    char tmp[512]; snprintf(tmp,sizeof tmp,"%s",c);
    char*tok[32]; int nt=0; char*save=NULL;
    for(char*t=strtok_r(tmp," \t",&save); t && nt<32; t=strtok_r(NULL," \t",&save)) tok[nt++]=t;
    if(!nt) return;
    if(strchr(tok[0],'/')){ const char*sl=strrchr(tok[0],'/'); snprintf(out,on,"%s",sl+1); return; }
    const char*b0=strrchr(tok[0],'/'); b0=b0?b0+1:tok[0];
    if(!strcmp(b0,"sh")||!strcmp(b0,"bash")||!strcmp(b0,"mksh")||!strcmp(b0,"dash")||
       !strcmp(b0,"ash")||!strcmp(b0,"busybox")||!strcmp(b0,"toybox")){
        for(int i=1;i<nt;i++){
            if(tok[i][0]=='-') continue;
            if(strchr(tok[i],'/')){ const char*sl=strrchr(tok[i],'/'); snprintf(out,on,"%s",sl+1); return; }
            break;
        }
    }
    snprintf(out,on,"%s",b0);
}

static int is_today(const char*ts){
    if(!ts[0]) return 0;
    time_t now=time(0); struct tm tmv; localtime_r(&now,&tmv);
    char cur[8]; strftime(cur,sizeof cur,"%m-%d",&tmv);
    return !strncmp(ts,cur,5);
}

/* 渲染一批事件；max<0 表示全部。弹窗/调试属冗余行，只在原始日志里出现 */
static int render_events(sb_t*b,const char*log,size_t ll,int max,int only_block){
    int total=0;
    for(size_t i=0;i<ll;i++) if(log[i]=='\n') total++;
    int startline=0;
    if(max>=0 && total>max) startline=total-max;
    int line=0, shown=0;
    const char*p=log; size_t off=0;
    while(off<ll){
        const char*e=memchr(log+off,'\n',ll-off);
        size_t n=e?(size_t)(e-(log+off)):ll-off;
        ev_t ev;
        if(line>=startline && parse_ev(log+off,n,&ev)){
            int blocked=!strcmp(ev.tag,"拦截");
            int noise=!strcmp(ev.tag,"弹窗")||!strcmp(ev.tag,"调试");
            int keep=blocked||!strcmp(ev.tag,"加固")||!strcmp(ev.tag,"告警")||
                     !strcmp(ev.tag,"已移除")||!strcmp(ev.tag,"启动");
            if(!noise && keep && (!only_block || blocked || !strcmp(ev.tag,"加固") || !strcmp(ev.tag,"告警"))){
                const rulemap_t*m=rule_find(ev.rule);
                const char*zh=m?m->zh:NULL;
                const char*cls=m?m->cls:"info";
                char actor[128]=""; if(blocked) actor_of(&ev,actor,sizeof actor);
                char hh[9]=""; if(ev.ts[0]) snprintf(hh,sizeof hh,"%s",ev.ts+6);
                sb_put(b,"<div class='ev'><div class='evh'>");
                if(blocked){
                    if(zh) sb_printf(b,"<span class='badge b-%s'>%s</span>",cls,zh);
                    else if(ev.rule[0]){ sb_put(b,"<span class='badge b-warn'>"); esc(b,ev.rule); sb_put(b,"</span>"); }
                    else sb_put(b,"<span class='badge b-warn'>已拦截</span>");
                } else if(!strcmp(ev.tag,"加固")) sb_put(b,"<span class='badge b-info'>自我加固</span>");
                else if(!strcmp(ev.tag,"告警")) sb_put(b,"<span class='badge b-warn'>注意</span>");
                else if(!strcmp(ev.tag,"已移除")) sb_put(b,"<span class='badge b-info'>已处理</span>");
                else if(!strcmp(ev.tag,"启动")) sb_put(b,"<span class='badge b-info'>启动</span>");
                else { sb_put(b,"<span class='badge b-info'>"); esc(b,ev.tag); sb_put(b,"</span>"); }
                if(hh[0]) sb_printf(b,"<span class='mono'>%s</span>",hh);
                if(ev.has_pid) sb_printf(b,"<span class='mono'>pid %d</span>",ev.pid);
                sb_put(b,"</div>");
                sb_put(b,"<div class='evd'>");
                if(strstr(ev.desc,"脚本预检")){
                    const char*s2=strchr(ev.desc,':');
                    sb_put(b,"脚本还没执行就被读出来了");
                    if(s2 && s2[1]){ sb_put(b," · "); esc(b,s2+1); }
                } else if(ev.desc[0] && strcmp(ev.desc,ev.rule)){
                    esc(b,ev.desc);
                } else if(blocked){
                    sb_put(b,"已终止该进程");
                } else {
                    esc(b,ev.desc);
                }
                sb_put(b,"</div>");
                if(blocked && (actor[0] || ev.cmd[0])){
                    sb_put(b,"<div class='evc'>");
                    if(actor[0]){ sb_put(b,"来自 "); esc(b,actor); }
                    if(ev.cmd[0] && strcmp(ev.cmd,actor)){
                        if(actor[0]) sb_put(b," · ");
                        char sc[120]; snprintf(sc,sizeof sc,"%s",ev.cmd); esc(b,sc);
                    }
                    sb_put(b,"</div>");
                }
                sb_put(b,"</div>");
                shown++;
            }
        }
        line++;
        if(!e) break;
        off=(size_t)(e-log)+1;
    }
    if(!shown) sb_put(b,"<div class='ev'><div class='evd' style='color:#6b7a90'>暂无记录</div></div>");
    return shown;
}

/* ---------------- 进程/运行状态 ---------------- */
static char SELFEXE[PATH_MAX];
static int is_guard_exe(const char*ex){
    if(SELFEXE[0] && !strcmp(ex,SELFEXE)) return 0;   /* 自己（含每个请求的 fork 子进程）不算守护进程 */
    if(!strncmp(ex,MODDIR "/bin/guard",strlen(MODDIR "/bin/guard"))) return 1;
    if(!strncmp(ex,RUNDIR "/",strlen(RUNDIR "/"))) return 1;
    if(!strncmp(ex,RUNTIME "/run/",strlen(RUNTIME "/run/"))) return 1;
    return 0;
}

static void scan_guard(int*m,int*k,int*w){
    *m=0;*k=0;*w=0;
    DIR*d=opendir("/proc"); if(!d) return;
    struct dirent*de;
    while((de=readdir(d))){
        if(!isdigit((unsigned char)de->d_name[0])) continue;
        char p[64]; snprintf(p,sizeof p,"/proc/%s/exe",de->d_name);
        char ex[PATH_MAX]; ssize_t n=readlink(p,ex,sizeof ex-1);
        if(n<=0) continue; ex[n]=0;
        if(!is_guard_exe(ex)) continue;
        {   /* 跳过本进程的 fork 子进程（每个 HTTP 请求一个），否则会虚增计数 */
            char sp[64]; snprintf(sp,sizeof sp,"/proc/%s/stat",de->d_name);
            char sb[512]; int sf=open(sp,O_RDONLY);
            if(sf>=0){ ssize_t sr=read(sf,sb,sizeof sb-1); close(sf);
                if(sr>0){ sb[sr]=0; char*rp2=strrchr(sb,')');
                    if(rp2){ int pp=atoi(rp2+1); /* state 之后第一个数是 ppid */
                        if(pp==(int)getpid()) continue; } } }
        }
        char cp[96]; snprintf(cp,sizeof cp,"/proc/%s/cmdline",de->d_name);
        char cmd[256]={0}; int fd=open(cp,O_RDONLY);
        if(fd>=0){ ssize_t r=read(fd,cmd,sizeof cmd-1); if(r>0){ cmd[r]=0; for(int i=0;i<r;i++) if(cmd[i]==0) cmd[i]=' '; } close(fd); }
        if(strstr(cmd,"-k")) (*k)++;
        else if(strstr(cmd,"-w")) (*w)++;
        else (*m)++;
    }
    closedir(d);
}

static long guard_pid(void){
    char b[32]={0}; int fd=open(RUNTIME "/guard.pid",O_RDONLY);
    if(fd<0) return 0;
    ssize_t r=read(fd,b,sizeof b-1); close(fd);
    if(r<=0) return 0; b[r]=0; return strtol(b,0,10);
}
static long guard_uptime(void){
    long pid=guard_pid(); if(pid<=0) return 0;
    char p[64]; snprintf(p,sizeof p,"/proc/%ld/stat",pid);
    char buf[1024]; int fd=open(p,O_RDONLY); if(fd<0) return 0;
    ssize_t r=read(fd,buf,sizeof buf-1); close(fd); if(r<=0) return 0; buf[r]=0;
    char*e=strrchr(buf,')'); if(!e) return 0;
    /* starttime 是第 22 个字段 */
    long fields[24]={0}; int i=0;
    char*q=e+1;
    while(*q && i<24){ while(*q==' ')q++; if(!*q)break; fields[i++]=strtol(q,&q,10); }
    long start=fields[19];            /* i 从 state(0)... starttime 索引 19 */
    long up=0;
    struct timespec bt;
    if(clock_gettime(CLOCK_BOOTTIME,&bt)==0) up=(long)bt.tv_sec;
    else { char ub[64]; int uf=open("/proc/uptime",O_RDONLY);
        if(uf>=0){ ssize_t ur=read(uf,ub,sizeof ub-1); close(uf); if(ur>0){ ub[ur]=0; up=(long)strtod(ub,0); } } }
    long sec=up-start/100; return sec>0?sec:0;
}

static void cfg_get(const char*buf,const char*key,char*out,size_t on,const char*def){
    size_t kl=strlen(key);
    const char*p=buf;
    out[0]=0;
    while(p && *p){
        const char*nl=strchr(p,'\n');
        size_t L=nl?(size_t)(nl-p):strlen(p);
        if(L>kl && !strncmp(p,key,kl) && p[kl]=='='){
            size_t vl=L-kl-1; if(vl>=on) vl=on-1;
            memcpy(out,p+kl+1,vl); out[vl]=0; return;
        }
        p=nl?nl+1:NULL;
    }
    snprintf(out,on,"%s",def?def:"");
}
static int cfg_int(const char*buf,const char*key,int def){
    char v[64]; cfg_get(buf,key,v,sizeof v,NULL); return v[0]?atoi(v):def;
}

/* 统计：累计拦截 / 今日拦截 / 弹窗 */
static void count_events(const char*log,size_t ll,int*total,int*today,int*popup){
    *total=0;*today=0;*popup=0;
    const char*p=log; size_t off=0;
    while(off<ll){
        const char*e=memchr(log+off,'\n',ll-off);
        size_t n=e?(size_t)(e-(log+off)):ll-off;
        ev_t ev;
        if(parse_ev(log+off,n,&ev)){
            if(!strcmp(ev.tag,"拦截")){ (*total)++; if(is_today(ev.ts)) (*today)++; }
            else if(!strcmp(ev.tag,"弹窗")) (*popup)++;
        }
        if(!e) break; off=(size_t)(e-log)+1;
    }
}

static void fmt_dur(long s,char*out,size_t on){
    if(s<=0){ snprintf(out,on,"—"); return; }
    long d=s/86400, h=(s%86400)/3600, m=(s%3600)/60;
    if(d>0) snprintf(out,on,"%ld 天 %ld 时",d,h);
    else if(h>0) snprintf(out,on,"%ld 时 %ld 分",h,m);
    else snprintf(out,on,"%ld 分 %ld 秒",m,s%60);
}

/* ---------------- 页面 ---------------- */
static void page_home(sb_t*b){
    int m,k,w; scan_guard(&m,&k,&w);
    char*log=NULL; size_t ll=0; int tot=0,tdy=0,pop=0;
    if(read_all(LOGF,&log,&ll,VIEWMAX)==0) count_events(log,ll,&tot,&tdy,&pop);
    char*cfg=NULL; size_t cl=0;
    if(read_all(CONFF,&cfg,&cl,64*1024)!=0){ cfg=strdup(""); cl=0; }
    int kill_on=cfg_int(cfg,"KILL",1), popup_on=cfg_int(cfg,"POPUP",1);
    int blockfd=cfg_int(cfg,"BLOCK_FD",1), poweroff=cfg_int(cfg,"POWEROFF",0);
    int poll=cfg_int(cfg,"POLL_MS",250), bfms=cfg_int(cfg,"BLOCK_FD_MS",100);
    long up=guard_uptime(); char upbuf[64]; fmt_dur(up,upbuf,sizeof upbuf);
    int alive=(m>0);

    page_head(b,"概览","概览");
    /* 状态横幅 */
    sb_put(b,"<div class='banner");
    sb_put(b,alive?" ok'>":"'>");
    if(alive) sb_printf(b,"防护运行中 · 主进程 %d 个，已守 %s",m,upbuf);
    else sb_put(b,"<b>防护已停止</b> · 没有检测到守护进程，请到配置页点「重启守护」");
    sb_put(b,"</div>");

    sb_put(b,"<div class='pills'>");
    sb_printf(b,"<span class='pill %s'>%s</span>",kill_on?"on":"off",kill_on?"命中即杀":"只记录不杀");
    sb_printf(b,"<span class='pill %s'>%s</span>",blockfd?"on":"off",blockfd?"分区句柄监控":"句柄监控关");
    sb_printf(b,"<span class='pill %s'>%s</span>",popup_on?"on":"off",popup_on?"拦截弹窗":"不弹窗");
    sb_printf(b,"<span class='pill %s'>%s</span>",poweroff?"off":"on",poweroff?"断电保护开(慎用)":"断电保护关");
    sb_printf(b,"<span class='pill mono'>刷新 %dms</span>",poll);
    sb_printf(b,"<span class='pill mono'>句柄 %dms</span>",bfms);
    sb_put(b,"</div>");

    sb_put(b,"<div class='grid'>");
    sb_printf(b,"<div class='stat'><div class='k'>累计拦截</div><div class='v cy mono'>%d<span class='u'>次</span></div></div>",tot);
    sb_printf(b,"<div class='stat'><div class='k'>今天拦截</div><div class='v %s mono'>%d<span class='u'>次</span></div></div>",tdy>0?"am":"gr",tdy);
    sb_printf(b,"<div class='stat'><div class='k'>已守护</div><div class='v gr' style='font-size:19px'>%s</div></div>",upbuf);
    sb_printf(b,"<div class='stat'><div class='k'>守护进程</div><div class='v %s mono'>%d<span class='u'>主</span> %d<span class='u'>守</span> %d<span class='u'>看</span></div></div>",
        alive?"gr":"rd",m,k,w);
    sb_put(b,"</div>");

    sb_put(b,"<div class='card'><h2>最近拦截</h2><div class='hint'>按时间从新到旧，只显示最近的拦截与告知</div>");
    if(log) render_events(b,log,ll,10,1); else sb_put(b,"<div class='ev'><div class='evd'>暂无记录</div></div>");
    sb_put(b,"<div style='margin-top:10px'><a href='/logs' class='mono' style='font-size:12.5px'>查看全部事件 →</a></div></div>");

    sb_put(b,"<div class='card'><h2>说明</h2>");
    sb_put(b,"<div class='hint'>卫士只读 /proc、只杀进程，从不写任何分区、不刷 boot、不动 SELinux。");
    sb_put(b,"「断电保护」默认关闭；在没 recovery 的机器上开启它，等于用可能丢数据换“宁可关机也不出事”，请自行判断。</div></div>");
    page_tail(b);
    if(log) free(log);
    free(cfg);
}

static void page_logs(sb_t*b,const char*q){
    char all[8]=""; get_param(q,"a",all,sizeof all);
    int only=!all[0];
    char*log=NULL; size_t ll=0;
    page_head(b,"事件","事件");
    int tot=0,tdy=0,pop=0;
    if(read_all(LOGF,&log,&ll,VIEWMAX)==0) count_events(log,ll,&tot,&tdy,&pop);
    sb_put(b,"<div class='pills'>");
    sb_printf(b,"<a class='pill %s' href='/logs'>只看拦截</a>",only?"on":"");
    sb_printf(b,"<a class='pill %s' href='/logs?a=1'>全部记录</a>",only?"":"on");
    sb_printf(b,"<span class='pill mono'>累计 %d</span>",tot);
    sb_printf(b,"<span class='pill mono'>今日 %d</span>",tdy);
    sb_put(b,"</div>");
    sb_put(b,"<div class='card'><h2>事件流</h2><div class='hint'>已翻译成人话；想看原始行点左下「原始日志」</div>");
    if(log) render_events(b,log,ll,-1,only);
    else sb_put(b,"<div class='ev'><div class='evd'>日志文件不存在</div></div>");
    sb_put(b,"</div>");
    sb_put(b,"<div class='card'><details><summary>原始日志（纯文本）</summary><pre>");
    if(log) escn(b,log,ll>60000?60000:ll); else sb_put(b,"(暂无)");
    sb_put(b,"</pre></details></div>");
    page_tail(b);
    if(log) free(log);
}

static void page_config(sb_t*b){
    char*cfg=NULL; size_t cl=0;
    if(read_all(CONFF,&cfg,&cl,64*1024)!=0){ cfg=strdup(""); cl=0; }
    char wl[512]=""; cfg_get(cfg,"ADMIN_WHITELIST",wl,sizeof wl,"");
    int poll=cfg_int(cfg,"POLL_MS",250), bfms=cfg_int(cfg,"BLOCK_FD_MS",100);
    int port=cfg_int(cfg,"WEB_PORT",8099), safe=cfg_int(cfg,"SAFE_UPTIME",180);
    int kill_on=cfg_int(cfg,"KILL",1), popup_on=cfg_int(cfg,"POPUP",1), rmad=cfg_int(cfg,"AUTO_REMOVE_ADMIN",1);
    int sd=cfg_int(cfg,"PROTECT_SD",1), bfd=cfg_int(cfg,"BLOCK_FD",1), scn=cfg_int(cfg,"SCAN_SCRIPTS",1);
    int pw=cfg_int(cfg,"POWEROFF",0), hold=cfg_int(cfg,"POWEROFF_HOLD",0), dry=cfg_int(cfg,"POWEROFF_DRYRUN",0);

    page_head(b,"配置","配置");
    sb_put(b,"<div class='card'><h2>拦截策略</h2>");
    sb_put(b,"<form method='get' action='/set'>");
    sb_printf(b,"<label class='sw'><span>命中就杀掉<span class='d'>关掉后只记日志，不阻止任何操作</span></span><input type='checkbox' name='kill' value='1'%s></label>",kill_on?" checked":"");
    sb_printf(b,"<label class='sw'><span>拦截时弹窗<span class='d'>用系统弹窗告诉你刚才有东西被拦了</span></span><input type='checkbox' name='popup' value='1'%s></label>",popup_on?" checked":"");
    sb_printf(b,"<label class='sw'><span>分区句柄监控<span class='d'>有进程拿到可写分区句柄就动手，这是最关键的一层</span></span><input type='checkbox' name='blockfd' value='1'%s></label>",bfd?" checked":"");
    sb_printf(b,"<label class='sw'><span>脚本预检<span class='d'>脚本还没执行就先读内容，命中危险行立刻终止</span></span><input type='checkbox' name='scripts' value='1'%s></label>",scn?" checked":"");
    sb_printf(b,"<label class='sw'><span>保护用户存储<span class='d'>/sdcard、/data/user 下的删除也拦，只放行 cache/tmp</span></span><input type='checkbox' name='sd' value='1'%s></label>",sd?" checked":"");
    sb_printf(b,"<label class='sw'><span>自动移除新设备管理器<span class='d'>防止被装一个 MDM 锁机</span></span><input type='checkbox' name='rmadmin' value='1'%s></label>",rmad?" checked":"");
    sb_put(b,"</div>");

    sb_put(b,"<div class='card'><h2>性能</h2>");
    sb_printf(b,"<div class='row'><div><div class='hint'>进程扫描间隔 ms</div><input type='number' name='poll' value='%d' min='50' max='2000'></div>",poll);
    sb_printf(b,"<div><div class='hint'>分区句柄扫描 ms</div><input type='number' name='bfdms' value='%d' min='20' max='2000'></div></div>",bfms);
    sb_printf(b,"<div class='row' style='margin-top:10px'><div><div class='hint'>控制台端口</div><input type='number' name='port' value='%d' min='0' max='65535'></div>",port);
    sb_printf(b,"<div><div class='hint'>开机安全期 秒</div><input type='number' name='safe' value='%d' min='0' max='3600'></div></div>",safe);
    sb_put(b,"<div class='hint' style='margin-top:10px'>数值越小越灵敏、越费电。句柄扫描建议 300–400；进程扫描 400–500 足够，真正兜底的是内核 exec 事件通道。</div>");
    sb_put(b,"</div>");

    sb_put(b,"<div class='card'><h2>断电保护</h2>");
    sb_put(b,"<div class='banner' style='margin-top:0'>默认关闭。开启后命中写分区会「冻结进程 → 刷盘 → 强制关机」。在没有 recovery 的机器上，这等于用可能丢数据换“宁可关机也不出事”。</div>");
    sb_printf(b,"<label class='sw'><span>命中后强制断电<span class='d'>POWEROFF，请确认能接受数据风险</span></span><input type='checkbox' name='poweroff' value='1'%s></label>",pw?" checked":"");
    sb_printf(b,"<label class='sw'><span>只冻结不断电<span class='d'>调试用</span></span><input type='checkbox' name='hold' value='1'%s></label>",hold?" checked":"");
    sb_printf(b,"<label class='sw'><span>断电演练<span class='d'>走完整流程但不真关机</span></span><input type='checkbox' name='dry' value='1'%s></label>",dry?" checked":"");
    sb_put(b,"</div>");

    sb_put(b,"<div class='card'><h2>设备管理器白名单</h2><div class='hint'>逗号分隔，支持前缀 *</div>");
    sb_put(b,"<input type='text' name='whitelist' value='");
    esc(b,wl);
    sb_put(b,"' style='margin-top:8px'></div>");

    sb_put(b,"<div style='display:flex;gap:10px;flex-wrap:wrap'><button class='pri' type='submit'>保存并重启守护</button></form>");
    sb_put(b,"<form method='get' action='/act'><input type='hidden' name='do' value='restart'><button type='submit'>仅重启守护</button></form></div>");

    sb_put(b,"<div class='card'><details><summary>原始 config.conf（高级）</summary>");
    sb_put(b,"<form method='post' action='/save'><textarea name='c' rows='14'>");
    escn(b,cfg,cl);
    sb_put(b,"</textarea><button type='submit'>原样保存</button></form></details></div>");
    page_tail(b);
    free(cfg);
}

/* ---------------- 配置写入 ---------------- */
static int set_keys_in_file(const char**keys,const char**vals,int n){
    char*old=NULL; size_t ol=0;
    if(read_all(CONFF,&old,&ol,256*1024)!=0) old=strdup("");
    sb_t out; sb_init(&out);
    int found[32]; for(int i=0;i<n;i++) found[i]=0;
    const char*p=old;
    while(p && *p){
        const char*nl=strchr(p,'\n');
        size_t L=nl?(size_t)(nl-p):strlen(p);
        int done=0;
        for(int i=0;i<n;i++){
            size_t kl=strlen(keys[i]);
            if(L>kl && !strncmp(p,keys[i],kl) && p[kl]=='='){
                sb_printf(&out,"%s=%s\n",keys[i],vals[i]); found[i]=1; done=1; break;
            }
        }
        if(!done) sb_putn(&out,p,L), sb_putc(&out,'\n');
        p=nl?nl+1:NULL;
    }
    for(int i=0;i<n;i++) if(!found[i]) sb_printf(&out,"\n%s=%s\n",keys[i],vals[i]);
    int fd=open(CONFF,O_WRONLY|O_CREAT|O_TRUNC,0644);
    int ok=0;
    if(fd>=0){ size_t off=0; while(off<out.len){ ssize_t wr=write(fd,out.p+off,out.len-off); if(wr<=0) break; off+=(size_t)wr; } close(fd); ok=1; }
    free(out.p); free(old);
    return ok;
}

/* 把守护进程换成最新二进制（保持“随机路径运行”特性，避免被按模块目录杀） */
static void restart_guard(void){
    DIR*d=opendir("/proc");
    if(d){
        struct dirent*de;
        while((de=readdir(d))){
            if(!isdigit((unsigned char)de->d_name[0])) continue;
            char p[64]; snprintf(p,sizeof p,"/proc/%s/exe",de->d_name);
            char ex[PATH_MAX]; ssize_t n=readlink(p,ex,sizeof ex-1);
            if(n<=0) continue; ex[n]=0;
            if(!is_guard_exe(ex)) continue;
            char q[64]; snprintf(q,sizeof q,"/proc/%s/cmdline",de->d_name);
            (void)q;
            kill((pid_t)atoi(de->d_name),SIGKILL);
        }
        closedir(d);
    }
    usleep(300000);
    unlink(RUNTIME "/keeper.lock");
    unlink(RUNTIME "/watchdog.lock");
    unlink(RUNTIME "/guard.lock");
    unlink(RUNTIME "/guard.pid");

    /* 拷一份到随机路径再启动：既保持随机名，又让自愈链路有稳定文件可 exec */
    mkdir(RUNTIME,0755); mkdir(RUNDIR,0755);
    char dst[PATH_MAX]; snprintf(dst,sizeof dst,RUNDIR "/.g%ld%d",(long)time(0),(int)getpid());
    int in=open(GUARDBIN,O_RDONLY);
    if(in>=0){
        int out=open(dst,O_WRONLY|O_CREAT|O_TRUNC,0755);
        if(out>=0){
            char buf[65536]; ssize_t r;
            while((r=read(in,buf,sizeof buf))>0){ char*wr=buf; ssize_t left=r; while(left>0){ ssize_t w=write(out,wr,(size_t)left); if(w<=0) break; wr+=w; left-=w; } }
            close(out); chmod(dst,0755);
        }
        close(in);
    }
    pid_t pid=fork();
    if(pid==0){
        setsid();
        int dn=open("/dev/null",O_RDWR);
        if(dn>=0){ dup2(dn,0); dup2(dn,1); dup2(dn,2); if(dn>2) close(dn); }
        if(access(dst,X_OK)==0) execl(dst,dst,(char*)0);
        execl(GUARDBIN,"guard",(char*)0);
        _exit(1);
    }
    usleep(400000);
}

static void page_set(int fd,const char*q){
    const char*keys[32]; const char*vals[32]; char store[32][128]; int n=0;
#define ADDOPT(pname,keyname,def) do{ char _v[32]; \
        if(get_param(q,pname,_v,sizeof _v)) { snprintf(store[n],sizeof store[n],"%s",strcmp(_v,"1")?"0":"1"); } \
        else snprintf(store[n],sizeof store[n],"%s",def); \
        keys[n]=keyname; vals[n]=store[n]; n++; }while(0)
#define ADDNUM(pname,keyname,def,lo,hi) do{ char _v[32]; int _n=def; \
        if(get_param(q,pname,_v,sizeof _v) && _v[0]){ _n=atoi(_v); if(_n<lo)_n=lo; if(_n>hi)_n=hi; } \
        snprintf(store[n],sizeof store[n],"%d",_n); \
        keys[n]=keyname; vals[n]=store[n]; n++; }while(0)
    ADDOPT("kill","KILL","1");
    ADDOPT("popup","POPUP","1");
    ADDOPT("rmadmin","AUTO_REMOVE_ADMIN","1");
    ADDOPT("sd","PROTECT_SD","1");
    ADDOPT("blockfd","BLOCK_FD","1");
    ADDOPT("scripts","SCAN_SCRIPTS","1");
    ADDOPT("poweroff","POWEROFF","0");
    ADDOPT("hold","POWEROFF_HOLD","0");
    ADDOPT("dry","POWEROFF_DRYRUN","0");
    ADDNUM("poll","POLL_MS",250,50,2000);
    ADDNUM("bfdms","BLOCK_FD_MS",100,20,2000);
    ADDNUM("port","WEB_PORT",8099,0,65535);
    ADDNUM("safe","SAFE_UPTIME",180,0,3600);
    char wl[1024];
    if(get_param(q,"whitelist",wl,sizeof wl)){
        for(char*t=wl;*t;t++) if(*t=='"') *t=' ';
        keys[n]="ADMIN_WHITELIST"; vals[n]=strdup(wl);
        int wlidx=n; n++;
        int ok=set_keys_in_file(keys,vals,n);
        free((void*)vals[wlidx]);
        if(ok) restart_guard();
    } else {
        if(set_keys_in_file(keys,vals,n)) restart_guard();
    }
#undef ADDOPT
#undef ADDNUM
    char h[256]; snprintf(h,sizeof h,"Location: /config\r\n");
    respond(fd,302,"text/html; charset=utf-8",h,"",0);
}

static void save_cfg(int fd,const char*body){
    char c[64*1024];
    const char*eq = body ? strstr(body,"c=") : NULL;
    if(!eq || (eq!=body && eq[-1]!='&')){ respond(fd,400,"text/plain; charset=utf-8","","bad request",11); return; }
    char raw[48*1024]; snprintf(raw,sizeof raw,"%s",eq+2);
    char *amp=strchr(raw,'&'); if(amp) *amp=0;
    urldecode(raw,c,sizeof c);
    int f=open(CONFF,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(f<0){ respond(fd,500,"text/plain","","save failed",11); return; }
    write(f,c,strlen(c)); close(f);
    restart_guard();
    char h[256]; snprintf(h,sizeof h,"Location: /config\r\n");
    respond(fd,302,"text/html; charset=utf-8",h,"",0);
}

/* ---------------- 文件浏览 ---------------- */
static int allowed(const char*rp){
    size_t rl=strlen(RUNTIME), ml=strlen(MODDIR);
    if(!strncmp(rp,RUNTIME,rl) && (rp[rl]==0||rp[rl]=='/')) return 1;
    if(!strncmp(rp,MODDIR,ml) && (rp[ml]==0||rp[ml]=='/')) return 1;
    return 0;
}
static int cmpname(const void*a,const void*b){ return strcmp(*(char*const*)a,*(char*const*)b); }

static void page_dir(sb_t*b,const char*path){
    char rp[PATH_MAX];
    if(!realpath(path,rp) || !allowed(rp)){
        page_head(b,"文件","文件"); sb_printf(b,"<div class='card'>路径不可访问：%s</div>",path); page_tail(b); return;
    }
    struct stat st;
    if(stat(rp,&st)<0 || !S_ISDIR(st.st_mode)){
        page_head(b,"文件","文件"); sb_printf(b,"<div class='card'>不是目录：%s</div>",rp); page_tail(b); return;
    }
    page_head(b,"文件","文件");
    sb_put(b,"<div class='card'><h2>目录</h2>");
    sb_printf(b,"<div class='evc' style='margin-top:2px'>%s</div>",rp);
    sb_put(b,"<table>");
    DIR*d=opendir(rp); char**names=NULL; int n=0,cap=0; struct dirent*de;
    while(d && (de=readdir(d))){
        if(!strcmp(de->d_name,".")) continue;
        if(n==cap){ cap=cap?cap*2:64; names=realloc(names,sizeof(char*)*(size_t)cap); }
        names[n++]=strdup(de->d_name);
    }
    if(d) closedir(d);
    if(n) qsort(names,(size_t)n,sizeof(char*),cmpname);
    for(int i=0;i<n;i++){
        if(!strcmp(names[i],"..") && (!strcmp(rp,RUNTIME)||!strcmp(rp,MODDIR))){ free(names[i]); continue; }
        char full[PATH_MAX]; snprintf(full,sizeof full,"%s/%s",rp,names[i]);
        struct stat fs; int isdir=(stat(full,&fs)==0)&&S_ISDIR(fs.st_mode);
        char u[PATH_MAX*3]; urlenc(full,u,sizeof u);
        char tbuf[64]=""; struct tm tmv;
        if(stat(full,&fs)==0){ localtime_r(&fs.st_mtime,&tmv); strftime(tbuf,sizeof tbuf,"%m-%d %H:%M",&tmv); }
        long long sz=0; if(stat(full,&fs)==0) sz=(long long)fs.st_size;
        char szbuf[32];
        if(isdir) snprintf(szbuf,sizeof szbuf,"目录");
        else if(sz<1024) snprintf(szbuf,sizeof szbuf,"%lld B",sz);
        else snprintf(szbuf,sizeof szbuf,"%.1f KB",(double)sz/1024.0);
        sb_printf(b,"<tr><td>%s<a href='%s?p=%s'>%s</a></td><td class='r'>%s<br>%s</td></tr>",
            isdir?"<span class='fol'>▸</span>":"", isdir?"/dir":"/view", u, names[i], szbuf, tbuf);
        free(names[i]);
    }
    free(names);
    sb_put(b,"</table></div>");
    sb_put(b,"<div class='card'><div class='hint'>快捷：<a href='/dir?p=/data/adb/antiwipe'>运行目录</a> · <a href='/dir?p=/data/adb/modules/antiwipe'>模块目录</a></div></div>");
    page_tail(b);
}

static void page_view(sb_t*b,const char*path){
    char rp[PATH_MAX];
    if(!realpath(path,rp) || !allowed(rp)){
        page_head(b,"文件","文件"); sb_put(b,"<div class='card'>路径不可访问</div>"); page_tail(b); return;
    }
    char*f=NULL; size_t fl=0;
    if(read_all(rp,&f,&fl,VIEWMAX)!=0){
        page_head(b,"文件","文件"); sb_printf(b,"<div class='card'>读取失败：%s</div>",rp); page_tail(b); return;
    }
    page_head(b,"文件","文件");
    sb_printf(b,"<div class='card'><h2>文件</h2><div class='evc'>%s · %zu B</div><pre>",rp,fl);
    escn(b,f,fl);
    sb_put(b,"</pre></div>");
    page_tail(b); free(f);
}

static void page_act(sb_t*b,const char*q){
    char what[32]=""; get_param(q,"do",what,sizeof what);
    if(!strcmp(what,"restart")) restart_guard();
    page_head(b,"操作","概览");
    sb_printf(b,"<div class='banner ok'>已执行：%s</div>",what[0]?what:"(空)");
    sb_put(b,"<div class='card'><a href='/'>返回概览</a></div>");
    page_tail(b);
}

static void weblog(const char*m,const char*t){
    int fd=open(WEBLOG,O_WRONLY|O_CREAT|O_APPEND,0600); if(fd<0) return;
    time_t now=time(0); struct tm tmv; localtime_r(&now,&tmv);
    char ts[32]; strftime(ts,sizeof ts,"%m-%d %H:%M:%S",&tmv);
    char line[1024]; int n=snprintf(line,sizeof line,"%s %s %s\n",ts,m,t);
    if(n>0) write(fd,line,(size_t)n);
    close(fd);
}

static void handle(int fd){
    char req[16384]; ssize_t n=recv(fd,req,sizeof req-1,0);
    if(n<=0) return; req[n]=0;
    char method[8]={0}, target[4096]={0};
    if(sscanf(req,"%7s %4095s",method,target)!=2){ respond(fd,400,"text/plain","","bad",3); return; }
    char*p=strchr(target,'?'); char q[4096]="";
    if(p){ *p=0; snprintf(q,sizeof q,"%s",p+1); }
    weblog(method,target);
    char*body=strstr(req,"\r\n\r\n"); if(body) body+=4;
    char*cookie=""; const char*ck=strstr(req,"Cookie:");
    if(ck){ static char cbuf[1024]; const char*nl=strstr(ck,"\r\n"); size_t cl=nl?(size_t)(nl-ck):strlen(ck);
        if(cl<sizeof cbuf){ memcpy(cbuf,ck,cl); cbuf[cl]=0; cookie=cbuf; } }
    if(!authed(q,cookie)){
        sb_t b; sb_init(&b);
        sb_put(&b,"<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>令牌</title><style>");
        sb_put(&b,CSS);
        sb_put(&b,"</style></head><body><div class='wrap'><header class='hero'><div class='brand'><span class='live'></span><span>anti-wipe</span></div>");
        sb_put(&b,"<h1>需要访问令牌</h1><div class='sub'>令牌在 <span class='mono'>/data/adb/antiwipe/web.token</span>，或点模块的「操作」按钮</div></header>");
        sb_put(&b,"<div class='card'><form method='get' action='/'><input type='text' name='tk' placeholder='粘贴令牌' autofocus><button class='pri' type='submit'>进入控制台</button></form></div>");
        sb_put(&b,"<div class='foot'>ANTI-WIPE</div></div></body></html>");
        respond_sb(fd,401,"",&b); free(b.p); return;
    }
    sb_t b; sb_init(&b);
    char extra[256]="";
    char tkv[64]; if(get_param(q,"tk",tkv,sizeof tkv)) snprintf(extra,sizeof extra,"Set-Cookie: tk=%s; Path=/; Max-Age=604800\r\n",TOKEN);
    if(!strcmp(method,"POST") && !strcmp(target,"/save")){ save_cfg(fd,body); free(b.p); return; }
    if(!strcmp(target,"/set")){ page_set(fd,q); free(b.p); return; }
    if(!strcmp(target,"/")) page_home(&b);
    else if(!strcmp(target,"/dir")){ char pp[PATH_MAX*2]=""; if(!get_param(q,"p",pp,sizeof pp)) snprintf(pp,sizeof pp,"%s",RUNTIME); page_dir(&b,pp); }
    else if(!strcmp(target,"/view")){ char pp[PATH_MAX*2]=""; get_param(q,"p",pp,sizeof pp); page_view(&b,pp); }
    else if(!strcmp(target,"/logs")) page_logs(&b,q);
    else if(!strcmp(target,"/config")) page_config(&b);
    else if(!strcmp(target,"/act")) page_act(&b,q);
    else { page_head(&b,"404",NULL); sb_printf(&b,"<div class='card'>404 %s</div>",target); page_tail(&b); }
    respond_sb(fd,200,extra,&b);
    free(b.p);
}

int main(int argc,char**argv){
    { ssize_t sn=readlink("/proc/self/exe",SELFEXE,sizeof SELFEXE-1); SELFEXE[sn>0?sn:0]=0; }
    int port=8099;
    for(int i=1;i<argc;i++){ if(!strcmp(argv[i],"-p") && i+1<argc) port=atoi(argv[++i]); }
    ensure_token();
    signal(SIGCHLD,SIG_IGN);
    signal(SIGPIPE,SIG_IGN);
    int s=socket(AF_INET,SOCK_STREAM,0); if(s<0) return 1;
    int one=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_port=htons((unsigned short)port); a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(s,(void*)&a,sizeof a)<0) return 1;
    if(listen(s,16)<0) return 1;
    for(;;){
        int c=accept(s,0,0); if(c<0) continue;
        pid_t pid=fork();
        if(pid==0){ close(s); handle(c); close(c); _exit(0); }
        close(c);
    }
    return 0;
}
