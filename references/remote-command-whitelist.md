# 远程命令白名单知识库

> 命令白名单的详细知识库版本。运行时数据（cmd_id → 命令模板 + 参数校验 pattern）在 `../data/remote-command-whitelist.json`。
> 本文档负责"为什么这样设计 / 每条命令什么风险 / 如何安全使用"，是 `data/*.json` 的合规注脚。
> 3 tier 划分：Tier 1 只读 / Tier 2 采集脚本 / Tier 3 处置类（默认关）。
> 关联：`./modes/remote.md`、`./compliance.md` §红线 4 / 7。

## 目录

- [§一 白名单的设计原则](#一白名单的设计原则)
- [§二 Tier 1 —— 只读（默认开，40 条）](#二tier-1--只读默认开)
- [§三 Tier 2 —— 采集脚本（默认开，8 条）](#三tier-2--采集脚本默认开全部记入审计)
- [§四 Tier 3 —— 处置类（默认关，11 条）](#四tier-3--处置类默认关)
- [§五 绝对不入白名单的命令族](#五绝对不入白名单的命令族)
- [§六 变量占位符](#六变量占位符)
- [§七 扩展白名单的流程](#七扩展白名单的流程)
- [§相关引用](#相关引用)

---

## 一、白名单的设计原则

远程命令一旦被 Skill 生成并执行，就构成"乙方对客户资产的操作痕迹"。为把风险压到最小，本白名单遵循以下 5 条硬性原则：

### 1.1 只读优先

- 默认打开的都是 **Tier 1 只读**（`ps` / `ss` / `last` / `crontab -l` / `cat /etc/passwd` 等）
- 采集类（Tier 2）虽然写文件，但只写到**驻场人员本机**的采集包目录，不改动客户主机
- 处置类（Tier 3）永远默认关，需要 `--allow-mutating` + 客户书面授权 + 二次口头确认三重锁

### 1.2 有害动作走人

- 有害动作（kill / block / disable / stop / revoke）绝不"自动化处置"
- 处置类命令仅提供"经过审计的执行渠道"，处置的**决策**始终由现场总指挥人做
- Skill 生成命令 + 客户书面授权 + 现场语音确认 三者缺一不可

### 1.3 无 shell 元字符

- arg 值不允许出现 `|` / `;` / `&` / `>` / `<` / `` ` `` / `$()` / `\n` / `\r`
- 组合命令通过多条独立 cmd_id 串接实现，而不是塞到一条命令里
- `remote_collect.py` 在 arg 组装时统一走 `shlex.quote`，任何 pattern 校验失败即拒绝

### 1.4 无 pivot

绝对禁止入白名单的命令族（详见 §五），核心是**任何可能扩展攻击面的命令**：

- 出向连接类：`ssh` / `scp` / `sftp` / `nc` / `curl` / `wget` / `rsync` (over ssh)
- 任意执行类：`bash -c` / `sh -c` / `python -c` / `perl -e` / `eval`
- 文件写类（对客户主机的破坏）：`rm` / `mv` / `truncate` / `dd` / `mkfs`
- 权限变更类：`chmod` / `chown` / `setfacl` / `chattr`
- 账户变更类：`useradd` / `userdel` / `usermod` / `passwd`
- 系统级：`reboot` / `shutdown` / `halt` / `init`

### 1.5 每条都有 related_check

- 每个 cmd_id 都映射到已有的 `CHECK-LIN-*` / `CHECK-WIN-*`（见 `../data/checklists/`），便于关联审计
- 这样每次远程执行都有对应的分析口径，避免"跑命令但不知道要看什么"

---

## 二、Tier 1 —— 只读（默认开）

Tier 1 命令的共同特征：`exit_code=0` 时输出稳定、无副作用、超时默认 60s。以下列出建议的初始 cmd_id 清单（`data/remote-command-whitelist.json` v0.4-M0 版应至少覆盖这 30+ 条）。

### Tier 1.1 进程审计

- **`list-processes`** / linux+windows
  - 描述：列出当前进程 TOP 50（按 CPU 排序）
  - Linux 模板：`ps -eo pid,ppid,user,stat,pcpu,pmem,etime,cmd --sort=-pcpu | head -50`
  - Windows 模板：`Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 Id,ProcessName,CPU,WS,Path`
  - 风险：极低。只读，标准运维命令
  - 常见误报：容器场景 `ps` 会缺列（busybox），需按 §八 兜底
  - 关联 check：`CHECK-LIN-PROC-01` / `CHECK-WIN-PROC-01`

- **`process-tree`** / linux
  - 描述：以树形展示进程父子关系
  - 模板：`pstree -pa -u | head -200`
  - 风险：极低
  - 关联 check：`CHECK-LIN-PROC-02`

- **`process-inspect`** / linux
  - 描述：审计单进程的 cmdline / cwd / open files
  - 模板：`readlink /proc/<pid>/exe && cat /proc/<pid>/cmdline && ls -la /proc/<pid>/cwd && ls -l /proc/<pid>/fd | head -50`
  - 参数校验：`<pid>` 必须是 `^[1-9][0-9]{0,6}$`
  - 风险：低（只读 `/proc`）
  - 常见误报：进程刚退出会 `No such file`
  - 关联 check：`CHECK-LIN-PROC-03`

- **`process-inspect-win`** / windows
  - 描述：审计单进程的父进程 / 加载 DLL / 命令行
  - 模板：`Get-CimInstance Win32_Process -Filter "ProcessId=<pid>" | Select-Object CommandLine,ParentProcessId,ExecutablePath,CreationDate`
  - 参数校验：`<pid>` 同上
  - 风险：低
  - 关联 check：`CHECK-WIN-PROC-02`

### Tier 1.2 网络连接

- **`list-listen`** / linux
  - 描述：列出所有监听端口 + 进程
  - 模板：`ss -tnlp 2>/dev/null || netstat -tnlp`
  - 风险：低
  - 常见误报：CentOS 7 上 `ss -p` 需 root，否则拿不到进程名（§八）
  - 关联 check：`CHECK-LIN-NET-01`

- **`list-established`** / linux
  - 描述：当前已建立的连接
  - 模板：`ss -tnp state established 2>/dev/null || netstat -tnp | grep ESTABLISHED`
  - 风险：低
  - 关联 check：`CHECK-LIN-NET-02`

- **`list-listen-win`** / windows
  - 描述：Windows 监听端口
  - 模板：`Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess`
  - 风险：低
  - 关联 check：`CHECK-WIN-NET-01`

- **`resolve-dns`** / linux+windows
  - 描述：对指定域名做 DNS 解析（**只读，不发起业务连接**）
  - 模板 Linux：`getent hosts <domain>` （不允许用 `dig` + `@server` 因为可控 nameserver）
  - 模板 Windows：`Resolve-DnsName -Name <domain> -Type A`
  - 参数校验：`<domain>` 匹配 `^[a-zA-Z0-9._-]{1,253}$` 且不允许 `..`
  - 风险：中（会走系统 resolver 产生 DNS 查询）
  - 关联 check：`CHECK-LIN-NET-03`

### Tier 1.3 账户与登录

- **`recent-logins`** / linux
  - 描述：最近 20 条成功登录
  - 模板：`last -F -i -n 20`
  - 风险：低
  - 关联 check：`CHECK-LIN-AUTH-01`

- **`recent-failed-logins`** / linux
  - 描述：最近失败登录（需 root）
  - 模板：`lastb -F -i -n 30 2>/dev/null || echo "requires root"`
  - 风险：低
  - 关联 check：`CHECK-LIN-AUTH-02`

- **`who-online`** / linux
  - 描述：当前在线用户
  - 模板：`who -a`
  - 风险：低
  - 关联 check：`CHECK-LIN-AUTH-03`

- **`list-users`** / linux
  - 描述：所有账户 + shell
  - 模板：`getent passwd | awk -F: '$7!="/usr/sbin/nologin" && $7!="/bin/false"{print $1,$3,$7}'`
  - 风险：低
  - 关联 check：`CHECK-LIN-AUTH-04`

- **`sudoers-audit`** / linux
  - 描述：/etc/sudoers 与 sudoers.d 的规则
  - 模板：`cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d 2>/dev/null; for f in /etc/sudoers.d/*; do echo "--- $f ---"; cat "$f"; done`
  - 风险：中（内容含权限逻辑，需脱敏后回传）
  - 关联 check：`CHECK-LIN-AUTH-05`

- **`recent-logins-win`** / windows
  - 描述：Windows 最近登录（EventID 4624）
  - 模板：`Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 | Select-Object TimeCreated,@{n='User';e={$_.Properties[5].Value}},@{n='IP';e={$_.Properties[18].Value}}`
  - 风险：低（需目标机开启审核策略）
  - 关联 check：`CHECK-WIN-AUTH-01`

### Tier 1.4 文件系统

- **`check-crontab`** / linux
  - 描述：所有用户的 crontab + 系统 cron.d
  - 模板：`for u in $(cut -d: -f1 /etc/passwd); do echo "=== $u ==="; crontab -l -u "$u" 2>/dev/null; done; echo "=== /etc/cron.d ==="; ls -la /etc/cron.d/ 2>/dev/null; echo "=== /etc/crontab ==="; cat /etc/crontab 2>/dev/null`
  - 风险：低
  - 关联 check：`CHECK-LIN-PERSIST-01`

- **`check-systemd-services`** / linux
  - 描述：所有 systemd unit（尤其近期修改的）
  - 模板：`systemctl list-units --type=service --all --no-legend | head -100; echo "---"; find /etc/systemd/system /usr/lib/systemd/system -type f -mtime -30 2>/dev/null | head -50`
  - 风险：低
  - 关联 check：`CHECK-LIN-PERSIST-02`

- **`recent-modified-files`** / linux
  - 描述：/etc、/root、/home 下最近 7 天修改的文件
  - 模板：`find /etc /root /home -type f -mtime -7 2>/dev/null | head -200`
  - 参数：无
  - 风险：中（输出可能含敏感文件名）
  - 关联 check：`CHECK-LIN-FS-01`

- **`suid-audit`** / linux
  - 描述：全盘 SUID 文件（找非标准 SUID）
  - 模板：`find / -perm -4000 -type f 2>/dev/null | head -200`
  - 风险：中（find 全盘会有 IO 开销）
  - 常见误报：正常 SUID 二进制很多（`ping` / `sudo` / `mount`），需按已知白名单过滤
  - 关联 check：`CHECK-LIN-FS-02`

- **`webshell-scan-simple`** / linux
  - 描述：简单 webshell 特征扫描（jsp/php/aspx）
  - 模板：`for d in /var/www /data/www /opt/tomcat/webapps /usr/local/tomcat/webapps; do [ -d "$d" ] && find "$d" -type f \( -name "*.jsp" -o -name "*.php" -o -name "*.aspx" \) -mtime -30 2>/dev/null; done | head -100`
  - 风险：低
  - 常见误报：合法业务代码近期发布
  - 关联 check：`CHECK-LIN-WEBSHELL-01`

- **`authorized-keys-audit`** / linux
  - 描述：所有用户的 authorized_keys
  - 模板：`for h in /root /home/*; do f="$h/.ssh/authorized_keys"; [ -f "$f" ] && echo "=== $f ===" && cat "$f"; done`
  - 风险：中（密钥指纹可能被截图外传，需脱敏）
  - 关联 check：`CHECK-LIN-AUTH-06`

### Tier 1.5 系统信息

- **`os-info`** / linux+windows
  - 描述：OS 版本 + kernel
  - Linux：`cat /etc/os-release; uname -a`
  - Windows：`Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture`
  - 风险：极低
  - 关联 check：`CHECK-LIN-INFO-01`

- **`uptime-load`** / linux
  - 描述：uptime + load
  - 模板：`uptime && cat /proc/loadavg`
  - 风险：极低
  - 关联 check：`CHECK-LIN-INFO-02`

- **`disk-usage`** / linux+windows
  - 描述：磁盘占用（识别异常大文件目录）
  - Linux：`df -h; du -sh /var/log /tmp /var/tmp 2>/dev/null`
  - Windows：`Get-PSDrive -PSProvider FileSystem`
  - 风险：低
  - 关联 check：`CHECK-LIN-INFO-03`

### Tier 1.6 日志查询（受控 tail）

- **`tail-auth-log`** / linux
  - 描述：/var/log/auth.log 或 /var/log/secure 最后 500 行
  - 模板：`tail -n 500 /var/log/auth.log 2>/dev/null || tail -n 500 /var/log/secure 2>/dev/null`
  - 风险：中（含用户名 / IP，需脱敏）
  - 关联 check：`CHECK-LIN-LOG-01`

- **`tail-nginx-access`** / linux
  - 描述：nginx access.log 最后 N 行
  - 模板：`tail -n <lines> <path>`
  - 参数校验：`<lines>` ∈ [1, 5000]；`<path>` 必须以 `/var/log/nginx/` 开头且不含 `..`
  - 风险：中
  - 关联 check：`CHECK-LIN-LOG-02`

- **`grep-auth-fails-by-ip`** / linux
  - 描述：给定 IP 在 auth.log 中的失败记录
  - 模板：`grep -aE 'Failed password.*from <ip>' /var/log/auth.log /var/log/secure 2>/dev/null | tail -n 100`
  - 参数校验：`<ip>` 必须是 IPv4 dotted-quad 或 IPv6 hex
  - 风险：低
  - 关联 check：`CHECK-LIN-LOG-03`

- **`journalctl-sshd`** / linux
  - 描述：journald 里 sshd 最后 200 条
  - 模板：`journalctl -u sshd -n 200 --no-pager 2>/dev/null || echo "no journald"`
  - 风险：低
  - 关联 check：`CHECK-LIN-LOG-04`

### Tier 1.7 Windows 专项

- **`list-services-win`** / windows
  - 描述：Windows 服务列表
  - 模板：`Get-Service | Where-Object Status -eq 'Running' | Select-Object Name,DisplayName,StartType`
  - 关联 check：`CHECK-WIN-PERSIST-01`

- **`scheduled-tasks-win`** / windows
  - 描述：计划任务
  - 模板：`Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object TaskName,TaskPath,State`
  - 关联 check：`CHECK-WIN-PERSIST-02`

- **`recent-modified-win`** / windows
  - 描述：C:\Windows\Temp、C:\ProgramData 最近 7 天修改的文件
  - 模板：`Get-ChildItem -Path "C:\Windows\Temp","C:\ProgramData" -Recurse -File -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddDays(-7) | Select-Object FullName,LastWriteTime | Select-Object -First 200`
  - 关联 check：`CHECK-WIN-FS-01`

---

## 三、Tier 2 —— 采集脚本（默认开，全部记入审计）

Tier 2 是 Tier 1 命令的批量打包，用于"一次性把主机基本状态全部拉回来"。特征：

- 内部只调 Tier 1 命令，不引入新的 shell 元字符或 pivot
- 输出统一打包为 tar.gz 落到驻场机（不落客户主机）
- 每个子命令仍单独记入 audit.jsonl

建议初始清单：

- **`run-linux-collect`**
  - 描述：Linux 主机基础采集（Tier 1 全套）
  - 内部命令：`os-info` + `list-processes` + `process-tree` + `list-listen` + `list-established` + `recent-logins` + `list-users` + `check-crontab` + `check-systemd-services` + `recent-modified-files` + `suid-audit` + `webshell-scan-simple` + `authorized-keys-audit` + `sudoers-audit` + `tail-auth-log` + `journalctl-sshd`
  - 超时：300s
  - 输出：`<host>-<ts>-linux-basic.tar.gz`
  - 关联 profile：`linux-basic`

- **`run-linux-full`**
  - 描述：完整采集，含大文件（10k+ 行日志、find 全盘）
  - 超时：900s
  - 输出：`<host>-<ts>-linux-full.tar.gz`

- **`run-windows-collect`**
  - 描述：Windows 基础采集
  - 内部命令：`os-info` + `list-processes` (win) + `list-listen-win` + `list-services-win` + `scheduled-tasks-win` + `recent-logins-win` + `recent-modified-win`
  - 超时：300s

- **`fetch-nginx-log`** / linux
  - 描述：把指定 nginx 日志文件拉到本地
  - 内部：`tar czf - <path>` + `scp` 回驻场机
  - 参数校验：`<path>` 必须以 `/var/log/nginx/` 或客户自定义 `--allow-log-prefix` 开头，不含 `..`
  - 超时：600s

- **`fetch-audit-log`** / linux
  - 描述：拉取 `/var/log/auth.log*` / `/var/log/secure*`
  - 超时：300s

- **`cleanup-collect-tmp`** / linux
  - 描述：清理驻场机上过期的采集包（**只清本机 `~/.hvv-defender/collects/*` 中 7 天以前的文件**，不动客户主机）
  - 模板：`find ~/.hvv-defender/collects -type f -mtime +7 -name "*.tar.gz" -delete`
  - 风险：中（本机文件删除；虽然是驻场人员自己的机器，但仍需 audit）
  - 特殊：该命令**不通过 ssh_probe.py 走**，仅在驻场机本机执行；但也走 audit.jsonl

---

## 四、Tier 3 —— 处置类（默认关）

Tier 3 命令**默认关闭**，需 `--allow-mutating` + 客户书面授权 + 每次二次口头确认。每条必须写清：使用场景 / 副作用 / 回滚方式 / 授权模板。

### 4.1 `kill-pid`

- **使用场景**：ir 已定性为恶意进程（如 C2 beacon / 挖矿 / 反弹 shell）
- **模板**：`kill -TERM <pid>`（默认 SIGTERM；若 30s 后 PID 仍在则允许 `kill -KILL <pid>`）
- **参数校验**：`<pid>` 必须是 `^[1-9][0-9]{0,6}$`；不允许 `-1` / `0`（会杀所有进程）
- **副作用**：目标进程立即退出；该进程持有的 lock / socket / 子进程受影响
- **回滚方式**：无自动回滚，需重启对应服务（systemd 管理的服务通常会自动 restart，需先关掉 restart policy）
- **授权模板**：
  ```
  授权对主机 <host> 上 PID <pid> 执行 kill-TERM，进程名 <proc>，
  副作用为该进程立即退出，如是业务服务需业务方评估重启方案。
  ```
- **客户话术**：确认"该进程 PID 的父服务、是否被 systemd 管理、是否有健康检查"
- **post_verify**：跑 `list-processes` 确认 PID 不存在或已回收

### 4.2 `block-ip-iptables`

- **使用场景**：ir 定性为 C2 / 攻击源 IP，需立即封禁
- **模板**：`iptables -I INPUT 1 -s <ip> -j DROP && iptables -I OUTPUT 1 -d <ip> -j DROP`
- **参数校验**：`<ip>` IPv4 dotted-quad 或 CIDR `/8~/32`
- **副作用**：该 IP 到主机的所有 TCP/UDP/ICMP 被丢弃；如误封业务 IP 会导致服务不可达
- **回滚方式**：`iptables -D INPUT -s <ip> -j DROP && iptables -D OUTPUT -d <ip> -j DROP`
- **授权模板**：
  ```
  授权对主机 <host> 封禁源 IP <ip>（含入站与出站），
  副作用为该 IP 与主机所有通信立即中断，
  已确认该 IP 不在客户合法业务出口 / NAT 公网列表内。
  ```
- **客户话术**：明确询问"该 IP 是否有反向流量依赖（如 API 回调、监控探针）"
- **post_verify**：`iptables -L INPUT -n | grep <ip>` 应显示两条 DROP 规则

### 4.3 `block-ip-nftables`

- 与 `block-ip-iptables` 类似，仅适用于使用 nftables 的现代发行版
- **模板**：`nft add rule inet filter input ip saddr <ip> drop; nft add rule inet filter output ip daddr <ip> drop`
- **回滚**：`nft delete rule ...`

### 4.4 `disable-user`

- **使用场景**：ir 定性为被入侵的账户 / 攻击者新建账户
- **模板**：`usermod -L <user> && chage -E 0 <user>`（锁密码 + 立即过期）
- **参数校验**：`<user>` 必须是 `^[a-z_][a-z0-9_-]{0,31}$`；不允许 `root` / `daemon` / `bin` / UID<1000 的系统账户
- **副作用**：该账户无法登录；正在运行的进程不受影响；被计划任务 / systemd unit 引用的账户会导致任务失败
- **回滚方式**：`usermod -U <user> && chage -E -1 <user>`
- **授权模板**：
  ```
  授权对主机 <host> 上账户 <user> 执行锁定 + 密码过期，
  副作用为该账户无法交互登录、cron / systemd 若用该账户会失败，
  已确认该账户不属于系统服务账户。
  ```
- **客户话术**：确认"该账户是否被计划任务使用、是否是服务身份账户"
- **post_verify**：`passwd -S <user>` 应显示 `L`

### 4.5 `stop-service`

- **使用场景**：ir 定性为恶意服务（如挖矿 systemd unit / 恶意 sshd 替身）
- **模板**：`systemctl stop <service> && systemctl disable <service>`
- **参数校验**：`<service>` 必须是 `^[a-zA-Z0-9_.@-]{1,64}$`；黑名单包含 `sshd` / `systemd-*` / `network*`（防止误停关键服务导致驻场人员失去连接）
- **副作用**：服务停止 + 开机不启动
- **回滚方式**：`systemctl enable <service> && systemctl start <service>`
- **授权模板**：
  ```
  授权对主机 <host> 停止服务 <service> 并禁用开机启动，
  副作用为该服务提供的能力立即失效，如有依赖服务会一并异常。
  ```
- **客户话术**：确认"该服务是否有依赖服务、是否有健康检查 / 熔断"
- **post_verify**：`systemctl status <service>` 应显示 `inactive` + `disabled`

### 4.6 `revoke-ssh-key`

- **使用场景**：ir 发现 authorized_keys 中有可疑公钥（如无主 comment / 未知 fingerprint）
- **模板**：`cp ~<user>/.ssh/authorized_keys ~<user>/.ssh/authorized_keys.bak-<ts> && sed -i '/<fingerprint>/d' ~<user>/.ssh/authorized_keys`
- **参数校验**：`<user>` 同 §4.4；`<fingerprint>` 必须是 base64 SHA256 hash 格式
- **副作用**：持该密钥的用户无法通过公钥登录（可能是合法运维）
- **回滚方式**：`cp ~<user>/.ssh/authorized_keys.bak-<ts> ~<user>/.ssh/authorized_keys`
- **授权模板**：
  ```
  授权对主机 <host> 从账户 <user> 的 authorized_keys 中移除指纹 <fingerprint>，
  副作用为该密钥持有者无法再通过公钥登录。
  ```
- **客户话术**：确认"该密钥指纹属于谁、最近成功登录的日志是什么"
- **post_verify**：`grep -F <fingerprint> ~<user>/.ssh/authorized_keys` 应无输出；备份文件存在

### 4.7 `snapshot-and-quarantine-file`

- **使用场景**：ir 发现 webshell / 恶意 payload，需要留证 + 隔离
- **模板**：`cp -a <path> ~/hvv-quarantine/<host>-<ts>-$(basename <path>) && mv <path> <path>.quarantined-<ts> && chmod 0000 <path>.quarantined-<ts>`
- **参数校验**：`<path>` 绝对路径，且必须以客户约定的 `webroot` 或 `--allow-quarantine-prefix` 开头
- **副作用**：文件从原路径不可访问（改名 + 权限 0）；驻场机保留副本用于取证
- **回滚方式**：`mv <path>.quarantined-<ts> <path> && chmod <original-mode> <path>`
- **授权模板**：
  ```
  授权对主机 <host> 隔离文件 <path>（改名 + chmod 000），
  同时把副本拷贝到驻场机 ~/hvv-quarantine/ 用于取证，
  副作用为该路径不再可被业务访问；如需回滚有备份。
  ```
- **客户话术**：确认"该路径是否是业务必需资源"
- **post_verify**：`ls -la <path>*` 应显示 quarantined 文件权限 0

### 4.8 `snapshot-forensics-pack`

- **使用场景**：应急响应第一步，采集 forensics 包（内存不采，磁盘元数据 + 日志）
- **模板**：串联多个 T1/T2 命令 + `tar czf` 打包到驻场机
- **副作用**：磁盘 IO 峰值 + 网络传输（可能几百 MB）
- **回滚**：无（只是采集，不改主机状态）
- **归类为 Tier 3 的原因**：会持续几分钟的高 IO，可能影响生产服务的响应，需要在维护窗口内做

---

## 五、绝对不入白名单的命令族

以下命令族**永远**不允许入白名单，即使有客户书面授权也不允许。理由分类如下：

### 5.1 不可逆的破坏操作

| 命令 | 原因 |
|---|---|
| `rm` / `rm -rf` | 误删无回滚，且取证证据可能被销毁。删除动作应由客户运维执行 |
| `mv` | 除 `snapshot-and-quarantine-file` 的受控用法外，其他 mv 都改变文件位置且不可逆 |
| `truncate` / `> file` | 清空文件，通常用于反取证，永远不允许 |
| `dd` | 底层块设备写，可损毁分区 / 磁盘 |
| `mkfs` / `mkswap` | 格式化，永远不允许 |
| `shred` | 安全销毁文件，属于反取证行为 |
| `wipefs` | 清 filesystem 签名 |

### 5.2 权限 / 账户任意变更

| 命令 | 原因 |
|---|---|
| `chmod` | 权限变更影响面广；隔离动作走 §4.7 的受控形式 |
| `chown` / `chgrp` | 属主变更同上 |
| `setfacl` / `chattr` | ACL / 属性变更 |
| `useradd` / `userdel` | 创建 / 删除账户由客户 IAM / 运维执行 |
| `usermod`（除 `-L` 锁定外） | 修改账户属性；仅 `disable-user` 内使用 `-L` 是受控用法 |
| `passwd` | 改密码永远不由 Skill 做 |
| `visudo` | sudoers 编辑必须人工做 |
| `groupadd` / `groupmod` / `groupdel` | 同 useradd 类 |

### 5.3 系统级危险动作

| 命令 | 原因 |
|---|---|
| `reboot` / `shutdown` / `halt` / `poweroff` / `init 0/6` | 生产主机重启由客户决定 |
| `systemctl reboot` / `systemctl poweroff` | 同上 |
| `kexec` | 内核热切换，破坏级 |
| `sysctl -w` | 内核参数变更 |
| `modprobe` / `insmod` / `rmmod` | 内核模块加载 / 卸载 |
| `iptables -F` / `iptables -X` | 全清防火墙规则（非 4.2 §精准封禁） |
| `service stop network*` | 停网卡会立即失联 |

### 5.4 pivot / 出向连接

| 命令 | 原因 |
|---|---|
| `ssh` / `scp` / `sftp` | 二次跳板等于攻击面扩展；Skill 只允许自己的 ssh_probe.py 走一次跳 |
| `rsync` (over ssh) | 同上 |
| `nc` / `ncat` / `socat` | 万能连接工具，攻击套件必带 |
| `curl` / `wget` / `httpie` | 出向 HTTP，可能下载恶意载荷或外发数据 |
| `telnet` / `ftp` | 明文协议 |
| `nmap` / `masscan` | 扫描工具，即使内网扫也不允许（客户其他资产可能敏感） |

### 5.5 任意执行

| 命令 | 原因 |
|---|---|
| `bash -c '...'` / `sh -c '...'` | 通用命令注入入口 |
| `python -c '...'` / `python3 -c` | 同上 |
| `perl -e` / `ruby -e` / `node -e` | 同上 |
| `awk 'BEGIN{system(...)}'` | awk 的 `system()` |
| `eval` / `exec` | shell 内建执行 |
| `bash <(curl ...)` / `sh -c "$(curl ...)"` | 远程脚本执行，永远不允许 |

**特例说明**：Skill 内部会用到 shell pipeline（如 `grep ... | tail`），但这些都是**内嵌在白名单命令模板中**、经过参数校验、无外部输入拼接的。不允许的是"用户 / 命令生成侧自由构造 shell 表达式"。

---

## 六、变量占位符

命令模板中允许的占位符与校验 pattern（`data/remote-command-whitelist.json` 里每条 cmd_id 都要声明）：

| 占位符 | 语义 | 正则 pattern | 说明 |
|---|---|---|---|
| `<pid>` | 进程 ID | `^[1-9][0-9]{0,6}$` | 1 ~ 9999999 |
| `<user>` | Linux 用户名 | `^[a-z_][a-z0-9_-]{0,31}$` | 遵循 POSIX 命名 |
| `<user-win>` | Windows 用户名 | `^[A-Za-z0-9_.-]{1,32}$` | 允许大小写 / `.` |
| `<ip>` | IPv4 | `^(\d{1,3}\.){3}\d{1,3}$` + 每段 ≤ 255 | 不允许 `0.0.0.0` / `255.255.255.255` |
| `<ipv6>` | IPv6 | 标准 IPv6 hex | 严格校验 |
| `<cidr>` | IPv4 CIDR | `^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$` | 前缀 ∈ [8, 32] |
| `<domain>` | 域名 | `^[a-zA-Z0-9._-]{1,253}$` | 不允许 `..` |
| `<path>` | 绝对路径 | `^/[^\x00\r\n]{1,4096}$` 且不含 `..` | 各命令还需额外前缀校验 |
| `<port>` | TCP/UDP 端口 | `^([1-9][0-9]{0,4})$` + ≤ 65535 | |
| `<service>` | systemd unit | `^[a-zA-Z0-9_.@-]{1,64}$` | 不含 `/` |
| `<fingerprint>` | SHA256 fingerprint | `^SHA256:[A-Za-z0-9+/]{43}=?$` | OpenSSH 格式 |
| `<lines>` | 行数 | 数字 ∈ [1, 5000] | tail / head 用 |
| `<ts>` | 时间戳 | ISO8601 UTC | Skill 内部生成，不接受用户输入 |

**统一原则**：所有占位符经 `shlex.quote()` 处理后拼入命令；如 pattern 校验失败，`ssh_probe.py` 直接 `exit 2` 并记录 audit（`action=validation_failed`）。

---

## 七、扩展白名单的流程

新增 cmd_id 时，走以下正规流程：

1. **提议阶段**
   - 在本 md 对应 tier 下新增条目草稿：cmd_id / OS / 描述 / 模板 / 参数校验 / 风险评估 / 回滚 / 关联 check
   - 说明"为什么现有 cmd_id 无法覆盖该场景"
2. **PR review**
   - 至少 2 人 review：一位安全工程师（评估攻击面）+ 一位驻场负责人（评估合规风险）
   - Tier 3 新条目**必须**由安全合规负责人签字
3. **e2e 冒烟**
   - 在 lab 环境（Ubuntu 22.04 / CentOS 7 / Windows Server 2019 至少三种）上跑一次
   - 验证 exit_code / stdout 稳定性 / 参数校验有效性 / audit.jsonl 完整性
4. **落地到 JSON**
   - 更新 `data/remote-command-whitelist.json` 增加条目 + 单元测试
   - 更新 `SKILL.md` 的 rule_id 分层表（如有新 rule_id）
5. **发布**
6. **禁止**
   - 禁止在生产 skill 版本中"临时加命令"绕过流程
   - 禁止把 Tier 3 命令拆解为多条 Tier 1 命令绕过默认关的策略（例如把 `stop-service` 拆成 `mv unit-file + reload daemon` 就是绕过）

**下限清单**：任何新 cmd_id 必须证明自己**不属于 §五 的禁止族**。§五 是硬红线，扩展流程不能突破。

---

## 相关引用

- 远程模式流程：`./modes/remote.md`
- 审计字段：`./log-fields/audit-session.md`
- 合规红线：`./compliance.md` §红线 4 / 7
- 运行时数据：`../data/remote-command-whitelist.json`
- 主机检查清单：`../data/checklists/`
