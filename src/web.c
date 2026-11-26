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
#define VIEWMAX (512*1024)

typedef struct { char *p; size_t len, cap; } sb_t;
static void sb_init(sb_t *b){ b->cap=8192; b->len=0; b->p=malloc(b->cap); b->p[0]=0; }
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
    const char*reason = code==200?"OK":code==302?"Found":code==401?"Unauthorized":code==404?"Not Found":code==500?"Error":"OK";
    int n=snprintf(h,sizeof h,"HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nCache-Control: no-store\r\nConnection: close\r\n%s\r\n",code,reason,type,len,extra?extra:"");
    send_all(fd,h,(size_t)n);
    send_all(fd,body,len);
}

static void respond_sb(int fd,int code,const char*extra,sb_t*b){
    respond(fd,code,"text/html; charset=utf-8",extra,b->p,b->len);
}

static const char*CSS =
"body{margin:0;background:#0f1115;color:#e6e8ee;font:15px/1.6 -apple-system,'Segoe UI',Roboto,sans-serif}"
"a{color:#7cc4ff;text-decoration:none}a:hover{text-decoration:underline}"
".wrap{max-width:860px;margin:0 auto;padding:18px}"
"h1{font-size:20px;margin:8px 0 2px}.sub{color:#8b93a7;font-size:13px;margin-bottom:16px}"
".card{background:#171a21;border:1px solid #262b36;border-radius:12px;padding:14px 16px;margin:12px 0}"
".row{display:flex;flex-wrap:wrap;gap:10px}.k{color:#8b93a7;font-size:12px}.v{font-size:15px;margin-right:18px}"
".ok{color:#5fd38d}.bad{color:#ff7b72}.warn{color:#e3b341}"
"pre{background:#0b0d11;border:1px solid #262b36;border-radius:10px;padding:12px;overflow:auto;font:12px/1.5 ui-monospace,monospace;white-space:pre-wrap}"
"table{width:100%;border-collapse:collapse}td,th{padding:6px 8px;border-bottom:1px solid #222733;text-align:left;font-size:14px}"
"input,textarea{background:#0b0d11;color:#e6e8ee;border:1px solid #2c3340;border-radius:8px;padding:8px;font:13px ui-monospace,monospace;width:100%%;box-sizing:border-box}"
"button{background:#2b6cb0;color:#fff;border:0;border-radius:8px;padding:9px 16px;font-size:14px;margin:6px 6px 0 0}"
"button.gray{background:#2a3040}.tag{display:inline-block;background:#20242e;border-radius:6px;padding:1px 8px;font-size:12px;color:#9aa4b8;margin-right:6px}"
"nav a{margin-right:14px;font-size:14px}.crumb{color:#8b93a7;font-size:13px;margin:6px 0 12px}"
"code{background:#20242e;border-radius:5px;padding:1px 6px;font-size:13px}";

static void page_head(sb_t*b,const char*title){
    sb_put(b,"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>");
    sb_printf(b,"<title>%s</title><style>%s</style></head><body><div class='wrap'>",title,CSS);
    sb_put(b,"<h1>防格机卫士 <span class='tag'>web</span></h1><div class='sub'>KernelSU 模块控制台 · 127.0.0.1</div>");
    sb_put(b,"<nav><a href='/'>概览</a><a href='/dir'>目录</a><a href='/logs'>日志</a><a href='/config'>配置</a></nav>");
}
static void page_tail(sb_t*b){ sb_put(b,"</div></body></html>"); }

static void count_procs(int*mainp,int*keeper,int*killc,int*popc){
    DIR*d=opendir("/proc"); struct dirent*de; int m=0,k=0;
    if(d){ while((de=readdir(d))){ if(!isdigit((unsigned char)de->d_name[0])) continue;
        char p[64]; snprintf(p,sizeof p,"/proc/%s/exe",de->d_name);
        char ex[PATH_MAX]; ssize_t n=readlink(p,ex,sizeof ex-1);
        if(n<=0) continue; ex[n]=0;
        if(strcmp(ex,MODDIR "/bin/guard")) continue;
        char cp[64]; snprintf(cp,sizeof cp,"/proc/%s/cmdline",de->d_name);
        char cmd[256]={0}; int fd=open(cp,O_RDONLY);
        if(fd>=0){ ssize_t r=read(fd,cmd,sizeof cmd-1); if(r>0) cmd[r]=0; close(fd);}
        if(strstr(cmd,"-k")) k++; else m++;
    } closedir(d);}
    *mainp=m; *keeper=k;
    int c1=0,c2=0; char*buf=NULL; size_t len=0;
    if(read_all(LOGF,&buf,&len,VIEWMAX)==0){
        for(size_t i=0;i+6<len;i++){ if(!strncmp(buf+i,"[拦截]",6)) c1++; }
        const char*tag="[弹窗]"; size_t tl=strlen(tag);
        for(size_t i=0;i+tl<=len;i++){ if(!strncmp(buf+i,tag,tl)) c2++; }
        free(buf);
    }
    *killc=c1; *popc=c2;
}

static void page_home(sb_t*b){
    int m,k,kc,pc; count_procs(&m,&k,&kc,&pc);
    char*buf=NULL; size_t len=0;
    if(read_all(CONFF,&buf,&len,64*1024)!=0){ buf=strdup("(配置缺失)"); len=strlen(buf); }
    page_head(b,"概览");
    sb_put(b,"<div class='card'><div class='row'>");
    sb_printf(b,"<div><div class='k'>主进程</div><div class='v %s'>%d</div></div>",m>0?"ok":"bad",m);
    sb_printf(b,"<div><div class='k'>keeper</div><div class='v %s'>%d</div></div>",k>0?"ok":"bad",k);
    sb_printf(b,"<div><div class='k'>累计拦截</div><div class='v'>%d</div></div>",kc);
    sb_printf(b,"<div><div class='k'>弹窗次数</div><div class='v'>%d</div></div>",pc);
    sb_put(b,"</div></div>");
    sb_put(b,"<div class='card'><div class='k'>配置</div><pre>");
    escn(b,buf,len);
    sb_put(b,"</pre><form method='get' action='/act'><input type='hidden' name='do' value='restart'><button>重启守护</button></form></div>");
    sb_put(b,"<div class='card'><div class='k'>最近拦截</div><pre>");
    char*lb=NULL; size_t ll=0;
    if(read_all(LOGF,&lb,&ll,VIEWMAX)==0){
        size_t start=0; int lines=0;
        for(size_t i=ll;i>0;i--){ if(lb[i-1]=='\n'){ lines++; if(lines>25){ start=i; break; } } }
        escn(b,lb+start,ll-start);
        free(lb);
    } else sb_put(b,"(暂无日志)");
    sb_put(b,"</pre><a href='/logs'>查看完整日志 →</a></div>");
    page_tail(b); free(buf);
}

static int allowed(const char*rp){
    size_t rl=strlen(RUNTIME), ml=strlen(MODDIR);
    if(!strncmp(rp,RUNTIME,rl) && (rp[rl]==0||rp[rl]=='/')) return 1;
    if(!strncmp(rp,MODDIR,ml) && (rp[ml]==0||rp[ml]=='/')) return 1;
    return 0;
}

static int cmpname(const void*a,const void*b){ return strcmp(*(char*const*)a,*(char*const*)b); }

static void page_dir(sb_t*b,const char*path,const char*extra){
    char rp[PATH_MAX];
    if(!realpath(path,rp) || !allowed(rp)){
        page_head(b,"目录"); sb_printf(b,"<div class='card bad'>路径不可访问: %s</div>",path); page_tail(b); return;
    }
    struct stat st; if(stat(rp,&st)<0 || !S_ISDIR(st.st_mode)){
        page_head(b,"目录"); sb_printf(b,"<div class='card'>不是目录: %s</div>",rp); page_tail(b); return;
    }
    page_head(b,"目录");
    sb_printf(b,"<div class='crumb'>%s</div>",rp);
    sb_put(b,"<div class='card'><table><tr><th>名称</th><th>大小</th><th>时间</th></tr>");
    DIR*d=opendir(rp); char**names=NULL; int n=0,cap=0;
    struct dirent*de;
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
        struct stat fs; int isdir = (stat(full,&fs)==0) && S_ISDIR(fs.st_mode);
        char u[PATH_MAX*3]; urlenc(full,u,sizeof u);
        char tbuf[64]=""; struct tm tmv;
        if(stat(full,&fs)==0){ localtime_r(&fs.st_mtime,&tmv); strftime(tbuf,sizeof tbuf,"%m-%d %H:%M",&tmv); }
        long long sz = (stat(full,&fs)==0)?(long long)fs.st_size:0;
        char szbuf[32]; if(sz<1024) snprintf(szbuf,sizeof szbuf,"%lld B",sz); else snprintf(szbuf,sizeof szbuf,"%.1f KB",(double)sz/1024.0);
        sb_printf(b,"<tr><td>%s<a href='%s?p=%s'>%s</a>%s</td><td>%s</td><td>%s</td></tr>",
            isdir?"📁 ":"", isdir?"/dir":"/view", u, names[i], isdir?"/":"",
            isdir?"-":szbuf, tbuf);
        free(names[i]);
    }
    free(names);
    sb_put(b,"</table></div>");
    sb_put(b,"<div class='card'><div class='k'>快捷入口</div><a href='/dir?p=/data/adb/antiwipe'>运行目录</a> · <a href='/dir?p=/data/adb/modules/antiwipe'>模块目录</a> · <a href='/logs'>日志</a></div>");
    page_tail(b);
}

static void page_view(sb_t*b,const char*path){
    char rp[PATH_MAX];
    if(!realpath(path,rp) || !allowed(rp)){
        page_head(b,"文件"); sb_printf(b,"<div class='card bad'>路径不可访问</div>"); page_tail(b); return;
    }
    char*f=NULL; size_t fl=0;
    if(read_all(rp,&f,&fl,VIEWMAX)!=0){
        page_head(b,"文件"); sb_printf(b,"<div class='card bad'>读取失败: %s</div>",rp); page_tail(b); return;
    }
    page_head(b,"文件");
    sb_printf(b,"<div class='crumb'>%s · %zu B</div>",rp,fl);
    sb_put(b,"<div class='card'><pre>");
    escn(b,f,fl);
    sb_put(b,"</pre></div>");
    page_tail(b); free(f);
}

static void restart_guard(void){
    DIR*d=opendir("/proc"); struct dirent*de;
    if(d){
        while((de=readdir(d))){
            if(!isdigit((unsigned char)de->d_name[0])) continue;
            char p[64]; snprintf(p,sizeof p,"/proc/%s/exe",de->d_name);
            char ex[PATH_MAX]; ssize_t n=readlink(p,ex,sizeof ex-1);
            if(n<=0) continue; ex[n]=0;
            if(!strcmp(ex,MODDIR "/bin/guard")) kill((pid_t)atoi(de->d_name),SIGKILL);
        }
        closedir(d);
    }
    usleep(400000);
    unlink(RUNTIME "/keeper.lock");
    unlink(RUNTIME "/guard.pid");
    pid_t pid=fork();
    if(pid==0){ execl(MODDIR "/bin/guard","guard",(char*)0); _exit(1); }
    usleep(300000);
}

static void page_config(sb_t*b){
    char*f=NULL; size_t fl=0;
    if(read_all(CONFF,&f,&fl,64*1024)!=0){ f=strdup(""); fl=0; }
    page_head(b,"配置");
    sb_put(b,"<div class='card'><form method='post' action='/save'>");
    sb_put(b,"<div class='k'>config.conf</div><textarea name='c' rows='12'>");
    escn(b,f,fl);
    sb_put(b,"</textarea><button>保存并重启</button></form>");
    sb_put(b,"<div class='k' style='margin-top:10px'>POLL_MS 扫描间隔 · KILL 1/0 是否击杀 · POPUP 1/0 是否弹窗 · ADMIN_WHITELIST 设备管理员白名单</div></div>");
    page_tail(b); free(f);
}

static void page_logs(sb_t*b){
    char*f=NULL; size_t fl=0;
    page_head(b,"日志");
    sb_put(b,"<div class='card'><pre>");
    if(read_all(LOGF,&f,&fl,VIEWMAX)==0) escn(b,f,fl); else sb_put(b,"(暂无)");
    sb_put(b,"</pre></div>");
    page_tail(b); free(f);
}

static void page_login(sb_t*b){
    sb_put(b,"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><style>");
    sb_put(b,CSS);
    sb_put(b,"</style></head><body><div class='wrap'><h1>防格机卫士</h1><div class='sub'>需要访问令牌 · 令牌在 /data/adb/antiwipe/web.token 或模块操作按钮里</div><div class='card'><form method='get' action='/'><input name='tk' placeholder='令牌'><button>进入</button></form></div></div></body></html>");
}

static void act(sb_t*b,const char*q){
    char what[32]="";
    get_param(q,"do",what,sizeof what);
    if(!strcmp(what,"restart")){ restart_guard(); }
    page_head(b,"操作");
    sb_printf(b,"<div class='card'>已执行: %s</div><div class='card'><a href='/'>返回概览</a></div>",what);
    page_tail(b);
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

static void weblog(const char*m,const char*t){
    int fd=open(WEBLOG,O_WRONLY|O_CREAT|O_APPEND,0600);
    if(fd<0) return;
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
    char*p=strchr(target,'?'); char q[4096]=""; if(p){ *p=0; snprintf(q,sizeof q,"%s",p+1); } else p=target+strlen(target);
    weblog(method,target);
    char*body=strstr(req,"\r\n\r\n"); if(body) body+=4;
    char*cookie=""; const char*ck=strstr(req,"Cookie:");
    if(ck){ static char cbuf[1024]; const char*nl=strstr(ck,"\r\n"); size_t cl=nl?(size_t)(nl-ck):strlen(ck); if(cl<sizeof cbuf){ memcpy(cbuf,ck,cl); cbuf[cl]=0; cookie=cbuf; } }
    if(!authed(q,cookie)){ sb_t b; sb_init(&b); page_login(&b); respond_sb(fd,401,"",&b); free(b.p); return; }
    sb_t b; sb_init(&b);
    char extra[256]="";
    char tkv[64]; if(get_param(q,"tk",tkv,sizeof tkv)) snprintf(extra,sizeof extra,"Set-Cookie: tk=%s; Path=/; Max-Age=604800\r\n",TOKEN);
    if(!strcmp(method,"POST") && !strcmp(target,"/save")){ save_cfg(fd,body); free(b.p); return; }
    if(!strcmp(target,"/")) page_home(&b);
    else if(!strcmp(target,"/dir")){ char pp[PATH_MAX*2]=""; if(!get_param(q,"p",pp,sizeof pp)) snprintf(pp,sizeof pp,"%s",RUNTIME); page_dir(&b,pp,extra); }
    else if(!strcmp(target,"/view")){ char pp[PATH_MAX*2]=""; get_param(q,"p",pp,sizeof pp); page_view(&b,pp); }
    else if(!strcmp(target,"/logs")) page_logs(&b);
    else if(!strcmp(target,"/config")) page_config(&b);
    else if(!strcmp(target,"/act")) act(&b,q);
    else { page_head(&b,"404"); sb_printf(&b,"<div class='card'>404 %s</div>",target); page_tail(&b); }
    respond_sb(fd,200,extra,&b);
    free(b.p);
}

int main(int argc,char**argv){
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
