# Linux 主机应急排查清单

> 一张表跑完一台 Linux 主机的"是否被入侵"。蓝队照单跑命令，逐项核对输出。
> **何时使用**：ir 模式收到客户主机采集包后逐项核查；audit 模式快速例行健康检查也适用。

约定：所有命令默认在客户机本地由客户跑，回传输出。本 Skill 不远连客户主机。

> 每项格式：**命令** / **关注点** / **常见误报** / **关联 IOC**

---

## 1. 基础信息

### 检查项 1.1: 主机标识
- **命令**：`hostnamectl; uname -a; cat /etc/os-release`
- **关注点**：内核版本（是否远低于安全基线 / 已知 LPE 漏洞）、发行版与 CMDB 是否一致
- **常见误报**：长期未升级但未失陷的存量机
- **关联 IOC 类型**：host metadata

### 检查项 1.2: 运行时长 / 负载
- **命令**：`uptime; w; cat /proc/loadavg`
- **关注点**：异常负载（挖矿 → load 飙高）、最近是否被重启（攻击者重启冲会话痕迹）
- **常见误报**：业务高峰
- **关联 IOC 类型**：anomaly:cpu

### 检查项 1.3: 内存与磁盘
- **命令**：`free -h; df -h; du -sh /tmp /var/tmp /dev/shm /var/log 2>/dev/null`
- **关注点**：`/tmp` `/var/tmp` `/dev/shm` 异常大（落马常用临时区）、`/var/log` 异常小（被清空）
- **常见误报**：业务缓存
- **关联 IOC 类型**：path

---

## 2. 账户审计

### 检查项 2.1: /etc/passwd 末尾新增
- **命令**：`tail -20 /etc/passwd; stat /etc/passwd`
- **关注点**：最近 mtime + 末尾出现陌生账户、UID < 1000 非系统账户
- **常见误报**：管理员近期合法添加
- **关联 IOC 类型**：user:new
### 检查项 2.2: UID=0 非 root 账户
- **命令**：`awk -F: '$3==0 {print}' /etc/passwd`
- **关注点**：只有一行 `root:x:0:0:...` 才正常，多于一行 → 后门账户
- **常见误报**：极少
- **关联 IOC 类型**：user:backdoor

### 检查项 2.3: 空密码账户
- **命令**：`awk -F: '($2=="" || $2=="!") {print $1}' /etc/shadow 2>/dev/null` (需 root)
- **关注点**：空密码可登录账户、`*`/`!` 表示锁定为正常
- **常见误报**：服务账户用 `!` 锁登录但允许 shell
- **关联 IOC 类型**：user:weakpass

### 检查项 2.4: shadow 弱口令 / 长期未改密
- **命令**：`awk -F: '{print $1, $3, $5, $9}' /etc/shadow | column -t` (需 root)
- **关注点**：last-change（第 3 字段）远古时间 / max-age（第 5 字段）=99999 → 长期未轮换
- **常见误报**：长期不动的系统账户
- **关联 IOC 类型**：user:weakpass

### 检查项 2.5: sudoers 异常
- **命令**：`cat /etc/sudoers; ls -la /etc/sudoers.d/; cat /etc/sudoers.d/*`
- **关注点**：`NOPASSWD: ALL` 给非运维账户、新近添加的非常规账户、`sudoers.d/` 下隐藏文件（前缀点）
- **常见误报**：CI/CD 账户合法 NOPASSWD
- **关联 IOC 类型**：persistence:sudo

### 检查项 2.6: 最近账户改动
- **命令**：`stat /etc/passwd /etc/shadow /etc/sudoers /etc/group | grep -E 'Modify|File'`
- **关注点**：mtime 在事件窗口内即可疑
- **常见误报**：管理员近期变更
- **关联 IOC 类型**：persistence:account

---

## 3. 登录历史

### 检查项 3.1: 成功登录历史
- **命令**：`last -F -i -n 200`
- **关注点**：陌生 IP、非常规账户、root 异地、非工作时间登录、不完整会话 `still logged in` / `gone - no logout`
- **常见误报**：运维 jumphost 合法连接
- **关联 IOC 类型**：ip / user

### 检查项 3.2: 失败登录历史
- **命令**：`lastb -F -i -n 200` (需 root)
- **关注点**：单 IP 海量失败 + 突然停止（成功暴破）、密码喷洒（多账户单 IP）
- **常见误报**：监控误用错口令
- **关联 IOC 类型**：ip:bruteforce

### 检查项 3.3: 当前在线会话
- **命令**：`who -a; w`
- **关注点**：陌生用户在线、非常规 IP、shell 跑非常规命令
- **常见误报**：管理员当前在维护
- **关联 IOC 类型**：session:active

### 检查项 3.4: ssh 登录日志梳理
- **命令**：`grep -aE 'Accepted|Failed' /var/log/auth.log /var/log/secure 2>/dev/null | tail -200`
- **关注点**：成功登录前是否有同 IP 大量失败、key vs password 切换
- **常见误报**：—
- **关联 IOC 类型**：ip / user / fingerprint

---

## 4. 进程审计

### 检查项 4.1: 全量进程含完整命令行
- **命令**：`ps -eo pid,ppid,user,start,etime,pcpu,pmem,cmd --sort=-pcpu | head -50`
- **关注点**：CPU/MEM 异常进程（挖矿）、cmd 含 `/tmp` `/dev/shm` 路径、cmd 含 base64 长串、命名伪装（`[kworker/u8:0]` `[kthreadd]` 但 ppid 异常）
- **常见误报**：业务批处理高峰
- **关联 IOC 类型**：process / path

### 检查项 4.2: 隐藏进程检测
- **命令**：`for p in $(ls /proc | grep -E '^[0-9]+$'); do ps -p $p >/dev/null || echo "Hidden PID: $p"; done`
- **关注点**：`/proc` 中存在但 `ps` 看不到 → rootkit 隐藏
- **常见误报**：极短生命周期进程，重复跑几遍取交集
- **关联 IOC 类型**：rootkit

### 检查项 4.3: 进程二进制路径与原始位置不一致
- **命令**：`for p in $(pgrep -a . | awk '{print $1}' | head); do ls -la /proc/$p/exe 2>/dev/null; done`
- **关注点**：`/proc/<pid>/exe` 指向 `(deleted)` → 文件已删但进程在跑（典型马）、指向 `/tmp` / `/dev/shm` / `/var/tmp`
- **常见误报**：升级中的服务（旧 binary 被替换但旧进程未重启）
- **关联 IOC 类型**：process:deleted-exe

### 检查项 4.4: 父子进程异常
- **命令**：`ps -eo pid,ppid,user,cmd --forest`
- **关注点**：`nginx` / `httpd` / `php-fpm` / `tomcat` / `java` 之下出现 `bash` / `sh` / `curl` / `wget` / `nc` / `python -c` → 强信号 webshell；`cron` 之下出现非业务命令
- **常见误报**：备份脚本由 cron 拉起 curl 同步
- **关联 IOC 类型**：webshell / lateral

### 检查项 4.5: 进程网络关联（哪个进程在出网）
- **命令**：`ss -tnp; ss -unp` （需 root 看 PID）
- **关注点**：web 进程出网到非业务 IP、root 进程监听高端口（4444/1337/8888 等）
- **常见误报**：APM / 监控 agent 长连接
- **关联 IOC 类型**：process / ip

### 检查项 4.6: 进程的打开文件
- **命令**：`lsof -p <suspect_pid>` 或 `ls -la /proc/<pid>/{cwd,exe,fd}`
- **关注点**：可疑临时文件、被删除的 binary、异常 socket
- **常见误报**：—
- **关联 IOC 类型**：file / socket

---

## 5. 网络连接

### 检查项 5.1: 当前 TCP/UDP 连接
- **命令**：`ss -tnp; ss -unp; ss -lntp`
- **关注点**：监听非业务端口（4444 / 1337 / 8888 / 6666 / 31337 / 7777 / 5555 / 9999）、外联陌生公网 IP、内网某机大量出向外网
- **常见误报**：sshd / nginx / mysql 标准端口
- **关联 IOC 类型**：ip / port

### 检查项 5.2: 反弹 shell 监听
- **命令**：`ss -lntp | awk '{print $4, $6}' | grep -vE ':22\\b|:80\\b|:443\\b|:3306\\b|:6379\\b'`
- **关注点**：非标准业务端口的监听
- **常见误报**：业务自定义端口 → 对比 CMDB
- **关联 IOC 类型**：listener

### 检查项 5.3: 反代 / 隧道工具
- **命令**：`ps -ef | grep -E 'frpc|frps|nps|npc|chisel|gost|stowaway|earthworm|reGeorg|neo-reGeorg|ssh.*-R|ssh.*-D' | grep -v grep`
- **关注点**：任何命中即可疑（除非业务明确使用 frp 等）
- **常见误报**：合法 frp 反代 → 看配置文件 / 来源 IP
- **关联 IOC 类型**：tunnel

### 检查项 5.4: 路由表 / iptables 异常
- **命令**：`ip route; iptables-save; nft list ruleset 2>/dev/null`
- **关注点**：异常 NAT 规则、转发到陌生外网、iptables 链中陌生 jump
- **常见误报**：容器网络 (docker/k8s) 默认规则
- **关联 IOC 类型**：network:rule

### 检查项 5.5: DNS 配置
- **命令**：`cat /etc/resolv.conf; cat /etc/nsswitch.conf; cat /etc/hosts`
- **关注点**：DNS 被改到陌生服务器、`/etc/hosts` 中可疑域名固定到内网或攻击者 IP
- **常见误报**：业务用内部 DNS
- **关联 IOC 类型**：dns / domain

---

## 6. 文件系统

### 检查项 6.1: 最近 7 天修改的文件
- **命令**：`find / -xdev -type f -mtime -7 -not -path "/proc/*" -not -path "/sys/*" -not -path "/var/log/*" 2>/dev/null | head -200`
- **关注点**：webroot / `/tmp` / `/dev/shm` / `/var/spool/cron` / 系统二进制目录 (`/usr/bin /usr/sbin /usr/local/bin`) 出现的新文件
- **常见误报**：业务发布
- **关联 IOC 类型**：path / file:new

### 检查项 6.2: 最近 1 天修改的文件
- **命令**：`find / -xdev -type f -mtime -1 -not -path "/proc/*" -not -path "/sys/*" -not -path "/var/log/*" 2>/dev/null`
- **关注点**：同 6.1，时间窗更聚焦
- **常见误报**：—
- **关联 IOC 类型**：path / file:new

### 检查项 6.3: SUID / SGID
- **命令**：`find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null`
- **关注点**：标准 SUID 清单外的（参考 GTFOBins 列表）、`/tmp /home /var/tmp` 下 SUID
- **常见误报**：发行版自带（passwd / sudo / mount / ping）
- **关联 IOC 类型**：suid / privesc

### 检查项 6.4: 可疑路径文件
- **命令**：`ls -la /tmp /var/tmp /dev/shm 2>/dev/null; find /tmp /var/tmp /dev/shm -type f 2>/dev/null | head -50`
- **关注点**：点开头的隐藏文件、无后缀大体积可执行、空格 / 不可见字符命名
- **常见误报**：systemd-private 临时目录、ssh-agent socket
- **关联 IOC 类型**：path

### 检查项 6.5: 异常大文件
- **命令**：`find / -xdev -type f -size +100M 2>/dev/null | head`
- **关注点**：陌生压缩包（含 dump 数据外传准备）、`.tar.gz` `.zip` 出现在异常路径
- **常见误报**：业务日志 / 数据库 dump
- **关联 IOC 类型**：file / exfil

### 检查项 6.6: 文件时间戳异常（被回拨）
- **命令**：`stat /tmp/<suspect>`
- **关注点**：atime / mtime / ctime 出现"恰好整点"（攻击者 touch）、ctime 远晚于 mtime 但 mtime 是远古时间
- **常见误报**：rsync -t 保留时间戳
- **关联 IOC 类型**：anti-forensics

### 检查项 6.7: 隐藏文件
- **命令**：`find / -xdev -type f -name ".*" -not -path "*/\\.git/*" -not -path "*/\\.cache/*" 2>/dev/null | head -100`
- **关注点**：`/tmp/.X11-lock` 类伪装、家目录陌生点文件
- **常见误报**：.bashrc / .ssh / .config 正常
- **关联 IOC 类型**：path:hidden

---

## 7. 持久化机制

### 检查项 7.1: cron - 系统级
- **命令**：`cat /etc/crontab; ls -la /etc/cron.{hourly,daily,weekly,monthly,d}/; cat /etc/cron.d/*`
- **关注点**：陌生条目、调用 `/tmp` / `/dev/shm` 路径、含 `curl` `wget` `base64 -d`、注释中 obfuscated 命令
- **常见误报**：logrotate / 备份脚本
- **关联 IOC 类型**：persistence:cron

### 检查项 7.2: cron - 用户级
- **命令**：`for u in $(cut -f1 -d: /etc/passwd); do echo "=== $u ==="; crontab -u $u -l 2>/dev/null; done; ls -la /var/spool/cron/`
- **关注点**：非业务账户 crontab 不空
- **常见误报**：开发账户日常使用
- **关联 IOC 类型**：persistence:cron

### 检查项 7.3: systemd unit
- **命令**：`systemctl list-unit-files --state=enabled; ls -la /etc/systemd/system/ /usr/lib/systemd/system/`
- **关注点**：最近新增的 service / timer、unit 描述异常、ExecStart 指向 `/tmp` / `/dev/shm`
- **常见误报**：发行版预装服务
- **关联 IOC 类型**：persistence:systemd

### 检查项 7.4: systemd timer（替代 cron）
- **命令**：`systemctl list-timers --all`
- **关注点**：陌生 timer + 短间隔 + ExecStart 异常路径
- **常见误报**：apt-daily / unattended-upgrades / fstrim
- **关联 IOC 类型**：persistence:systemd-timer

### 检查项 7.5: rc.local / init.d
- **命令**：`cat /etc/rc.local 2>/dev/null; ls -la /etc/init.d/`
- **关注点**：rc.local 末尾新增、init.d 陌生脚本
- **常见误报**：—
- **关联 IOC 类型**：persistence:rc

### 检查项 7.6: bash 启动脚本
- **命令**：`cat /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc 2>/dev/null`
- **关注点**：执行 `curl|sh`、`alias` 异常、`PROMPT_COMMAND` 设置
- **常见误报**：— 
- **关联 IOC 类型**：persistence:profile

### 检查项 7.7: 用户 bash 启动脚本（家目录）
- **命令**：`for u in $(awk -F: '$3>=1000 {print $1":"$6}' /etc/passwd); do d=${u#*:}; ls -la $d/.bashrc $d/.bash_profile $d/.profile $d/.bash_login 2>/dev/null; done`
- **关注点**：最近修改、含 `nc` / `bash -i` / `curl http`
- **常见误报**：oh-my-zsh / nvm 自动注入
- **关联 IOC 类型**：persistence:rc-user

### 检查项 7.8: PAM 后门
- **命令**：`ls -la /etc/pam.d/; md5sum /lib*/security/pam_*.so /usr/lib*/security/pam_*.so 2>/dev/null`
- **关注点**：`/etc/pam.d/sshd` `/etc/pam.d/system-auth` 新增 module 行、`pam_*.so` 文件 hash 与发行版基线不一致
- **常见误报**：—（PAM 通常不动）
- **关联 IOC 类型**：persistence:pam

### 检查项 7.9: ld.so.preload / LD_PRELOAD 后门
- **命令**：`cat /etc/ld.so.preload 2>/dev/null; ls -la /etc/ld.so.preload`
- **关注点**：文件存在且非空 → 高度可疑（指向 rootkit so）
- **常见误报**：性能调优工具偶用
- **关联 IOC 类型**：persistence:ldpreload

### 检查项 7.10: 动态库劫持
- **命令**：`ldconfig -p | head; strings /etc/ld.so.conf.d/*.conf`
- **关注点**：陌生路径加入搜索列表
- **常见误报**：包管理自动写入
- **关联 IOC 类型**：persistence:ld

---

## 8. SSH 后门

### 检查项 8.1: 所有账户 authorized_keys
- **命令**：`for u in $(awk -F: '{print $1":"$6}' /etc/passwd); do n=${u%:*}; d=${u#*:}; if [ -f "$d/.ssh/authorized_keys" ]; then echo "=== $n ==="; cat $d/.ssh/authorized_keys; fi; done`
- **关注点**：陌生公钥 comment（部分马的 comment 写死如 `mdrfckr` 等已知 IOC）、出现 `command=` `from=` 前缀但未配过的
- **常见误报**：跳板机批量下发的 ops 公钥
- **关联 IOC 类型**：ssh-key

### 检查项 8.2: authorized_keys 文件权限与所有者
- **命令**：`find / -name "authorized_keys*" -ls 2>/dev/null`
- **关注点**：权限非 600、owner 非账户本身
- **常见误报**：—
- **关联 IOC 类型**：file:perm

### 检查项 8.3: sshd_config 异常
- **命令**：`grep -vE '^\\s*(#|$)' /etc/ssh/sshd_config; ls -la /etc/ssh/sshd_config.d/ 2>/dev/null`
- **关注点**：`PermitRootLogin yes`、`PasswordAuthentication yes`、新增 `Match` 段、`AllowUsers` 含陌生账户、`Port` 改非标
- **常见误报**：业务要求 root password 登录
- **关联 IOC 类型**：persistence:sshd

### 检查项 8.4: ssh known_hosts 异常
- **命令**：`for u in $(cut -f1,6 -d: /etc/passwd | tr ':' ' '); do d=$(echo $u | awk '{print $2}'); [ -f "$d/.ssh/known_hosts" ] && wc -l "$d/.ssh/known_hosts"; done`
- **关注点**：服务账户却有大量 known_hosts → 该账户被用于横向
- **常见误报**：CI 账户合法 git clone
- **关联 IOC 类型**：lateral

---

## 9. 环境变量与 alias

### 检查项 9.1: 当前 shell 环境
- **命令**：`env; alias`
- **关注点**：`LD_PRELOAD` `LD_LIBRARY_PATH` 指向异常路径、`PROMPT_COMMAND` 含命令、alias 把 `ls / ps / netstat` 重定向（隐藏命令）
- **常见误报**：开发环境别名
- **关联 IOC 类型**：env

### 检查项 9.2: 所有用户 alias 与启动脚本
- **命令**：`grep -rE 'alias (ls|ps|netstat|ss|find|grep)=' /home /root /etc 2>/dev/null`
- **关注点**：核心排查命令被 alias 替换 → 反取证
- **常见误报**：颜色化 `alias ls='ls --color=auto'`
- **关联 IOC 类型**：anti-forensics

---

## 10. 历史命令

### 检查项 10.1: 所有账户 bash_history
- **命令**：`for u in $(awk -F: '{print $1":"$6}' /etc/passwd); do n=${u%:*}; d=${u#*:}; [ -f "$d/.bash_history" ] && echo "=== $n ===" && tail -100 "$d/.bash_history"; done`
- **关注点**：`wget` / `curl` 外网、`nc -e`、`chmod +x`、`history -c`、对 `/etc/passwd /etc/shadow` 操作
- **常见误报**：运维日常
- **关联 IOC 类型**：command:history

### 检查项 10.2: zsh / fish history
- **命令**：`for u in $(awk -F: '$3>=1000 {print $6}' /etc/passwd); do ls -la $u/.zsh_history $u/.local/share/fish/fish_history 2>/dev/null; done`
- **关注点**：同 10.1
- **常见误报**：—
- **关联 IOC 类型**：command:history

### 检查项 10.3: history 时间戳
- **命令**：`HISTTIMEFORMAT="%F %T " history` (当前会话) 或检查 `~/.bash_history` 中 `#timestamp` 行
- **关注点**：时间断档（攻击者抹了一段）、未来时间戳
- **常见误报**：未启用 HISTTIMEFORMAT 时无时间戳
- **关联 IOC 类型**：anti-forensics

### 检查项 10.4: history 被禁用 / 重定向
- **命令**：`grep -rE 'HISTFILE|HISTSIZE|HISTCONTROL|HISTIGNORE' /etc/profile* /etc/bashrc /home/*/.bashrc /root/.bashrc 2>/dev/null`
- **关注点**：`HISTFILE=/dev/null`、`HISTSIZE=0`、`set +o history`
- **常见误报**：—
- **关联 IOC 类型**：anti-forensics

---

## 11. 审计日志完整性

### 检查项 11.1: /var/log 完整性
- **命令**：`ls -la /var/log/ | head -30; for f in auth.log secure syslog messages wtmp btmp lastlog; do [ -f /var/log/$f ] && stat /var/log/$f | grep -E 'Size|Modify'; done`
- **关注点**：Size = 0、Modify 时间在事件窗口内 + 文件很小
- **常见误报**：logrotate 周期切割
- **关联 IOC 类型**：log:tampered

### 检查项 11.2: journald 完整性
- **命令**：`journalctl --verify 2>&1 | tail`
- **关注点**：报错 PASS 之外的状态
- **常见误报**：journal 损坏（非攻击导致）
- **关联 IOC 类型**：log:tampered

### 检查项 11.3: wtmp 是否被清
- **命令**：`utmpdump /var/log/wtmp 2>/dev/null | head; stat /var/log/wtmp`
- **关注点**：文件大小为 0 / 远小于历史 / 输出条数远少于 last -F | wc -l
- **常见误报**：—
- **关联 IOC 类型**：log:tampered

### 检查项 11.4: auditd 状态
- **命令**：`systemctl is-active auditd; auditctl -l 2>/dev/null; ls /var/log/audit/`
- **关注点**：auditd 被停用、规则被清空
- **常见误报**：未部署 auditd
- **关联 IOC 类型**：anti-forensics

---

## 12. WebShell 排查（如有 web 目录）

### 检查项 12.1: 列出 web root 路径
- **命令**：`grep -rE '^\\s*(root|DocumentRoot)\\s+' /etc/nginx/ /etc/apache2/ /etc/httpd/ 2>/dev/null`
- **关注点**：所有 webroot 路径
- **常见误报**：—
- **关联 IOC 类型**：path:webroot

### 检查项 12.2: 最近 30 天新增 / 修改的 web 文件
- **命令**：`find <webroot> -type f \\( -name '*.php' -o -name '*.jsp' -o -name '*.jspx' -o -name '*.aspx' -o -name '*.ashx' \\) -mtime -30 2>/dev/null`
- **关注点**：路径出现在 upload / static / image 子目录 + 含 eval / Runtime.exec / cmd.exe
- **常见误报**：业务正常发布
- **关联 IOC 类型**：webshell

### 检查项 12.3: webshell 关键字快速扫
- **命令**：`grep -rE 'eval\\(|\\bsystem\\(|\\bexec\\(|passthru\\(|preg_replace.*\\/e|Runtime\\.getRuntime|ProcessBuilder|Eval\\(Request|WScript\\.Shell' <webroot> 2>/dev/null | head -50`
- **关注点**：命中关键字 + 文件内容短 + 文件名异常
- **常见误报**：CMS 模板系统含 eval
- **关联 IOC 类型**：webshell

### 检查项 12.4: web 目录可写权限
- **命令**：`find <webroot> -type d -perm -o+w 2>/dev/null`
- **关注点**：其他用户可写目录 → 文件上传落点
- **常见误报**：uploads / tmp 设计如此
- **关联 IOC 类型**：misconfig

### 检查项 12.5: .htaccess 异常
- **命令**：`find <webroot> -name '.htaccess' -exec ls -la {} \\; -exec cat {} \\;`
- **关注点**：新增 RewriteRule 重定向、AddHandler 把陌生扩展当 PHP 解析
- **常见误报**：—
- **关联 IOC 类型**：misconfig

---

## 13. Rootkit 检测

### 检查项 13.1: chkrootkit / rkhunter（如可用）
- **命令**：`chkrootkit 2>/dev/null | grep -iE 'infected|WARN'; rkhunter --check --skip-keypress --quiet 2>/dev/null`
- **关注点**：INFECTED 行、Warning 行的具体内容
- **常见误报**：rkhunter 大量 false warning，需结合其他证据
- **关联 IOC 类型**：rootkit

### 检查项 13.2: 核心系统二进制 hash 校验
- **命令**：`md5sum /bin/ls /bin/ps /bin/netstat /usr/bin/ss /usr/bin/find /usr/bin/who /usr/bin/lsof 2>/dev/null`
- **关注点**：与发行版包基线对比（`debsums` / `rpm -Va`）
- **常见误报**：—
- **关联 IOC 类型**：file:tampered

### 检查项 13.3: debsums / rpm -Va 校验
- **命令**：`debsums -c 2>/dev/null | head; rpm -Va 2>/dev/null | grep -v '^.....T' | head`
- **关注点**：核心包文件被改（`/bin /sbin /usr/bin /usr/sbin /lib /lib64`）
- **常见误报**：配置文件被改是正常的（带 `c` 标记）
- **关联 IOC 类型**：file:tampered

### 检查项 13.4: 内核模块异常
- **命令**：`lsmod; cat /proc/modules; ls -la /lib/modules/$(uname -r)/extra 2>/dev/null`
- **关注点**：陌生 module、`/extra` 目录有非官方 ko、`taint` 状态
- **常见误报**：硬件厂商驱动
- **关联 IOC 类型**：rootkit:kernel

---

## 14. 容器场景

### 检查项 14.1: docker 进程
- **命令**：`docker ps -a; docker images`
- **关注点**：陌生容器、`docker run --privileged`、`--pid=host` `--network=host`、镜像来自陌生 registry
- **常见误报**：业务正常容器
- **关联 IOC 类型**：container:suspicious

### 检查项 14.2: 容器 escape 痕迹
- **命令**：`mount | grep -E 'docker|overlay'; ls -la /var/run/docker.sock 2>/dev/null`
- **关注点**：宿主机的 `/var/run/docker.sock` 被映射到容器内（提权风险）、宿主目录 `/` 被挂入容器
- **常见误报**：CI/CD docker-in-docker 设计如此
- **关联 IOC 类型**：container:escape-risk

### 检查项 14.3: k8s pod 异常（如可用）
- **命令**：`kubectl get pods -A 2>/dev/null; kubectl get serviceaccounts -A 2>/dev/null`
- **关注点**：陌生 namespace、陌生 SA 拥有 cluster-admin、含 hostPath / hostNetwork 的 pod
- **常见误报**：监控 / CI 类系统 pod 合法 hostPath
- **关联 IOC 类型**：k8s:rbac

### 检查项 14.4: 容器内反弹监听
- **命令**：`docker ps -q | xargs -I{} sh -c 'echo "=== {} ==="; docker exec {} ss -lntp 2>/dev/null'`
- **关注点**：容器内监听非业务端口
- **常见误报**：—
- **关联 IOC 类型**：container:listener

---

## 总结：核查完跑一遍输出表

| 类别 | 检查项数 | P0 触发条件示例 |
|---|---|---|
| 基础 | 3 | — |
| 账户 | 6 | UID=0 非 root / 空口令 |
| 登录 | 4 | root 异地 / 暴破后成功 |
| 进程 | 6 | 隐藏进程 / web → bash |
| 网络 | 5 | 非业务端口监听 / tunnel |
| 文件系统 | 7 | /tmp 可执行 + 出网 |
| 持久化 | 10 | cron `/dev/shm` / PAM 后门 |
| SSH | 4 | 陌生 authorized_keys |
| 环境 | 2 | 核心命令被 alias |
| 历史 | 4 | history 被清 |
| 日志 | 4 | wtmp 大小 0 |
| webshell | 5 | upload 目录新 jsp |
| rootkit | 4 | ld.so.preload 非空 / 核心二进制被改 |
| 容器 | 4 | docker.sock 暴露 / privileged |

所有"P0 触发条件"出现一项即应升级到 ir 流程，并产出 incident-report；多项叠加置信度更高。

每一处异常都按 SKILL.md 第 4 节统一 schema 落条目：
- `id` = `IR-NNN`
- `category` = 见每检查项的"关联 IOC 类型"映射
- `evidence` = 命令原始输出（脱敏后）
- `rule_id` = `CHECK-LIN-X.Y`（章号.项号）
- `iocs` = 提取出的 IP / 路径 / 进程 / 公钥指纹
- `recommended_action` = 参考对应 playbook
