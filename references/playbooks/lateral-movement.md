# Playbook: 横向移动处置剧本

> 适用模式：audit / ir
> 难度：★★★★☆
> 平均处置时间：90-240 分钟（涉及多主机调查）

## 1. 攻击概述

- **攻击者目的**：在已立足的内网中，从最初的失陷主机扩散到更多内网资产；目标可能是「找域控」「找业务核心库」「找堡垒机」「找跳板到 DMZ 外的隔离环境」。
- **典型攻击链位置**：
  - MITRE ATT&CK 战术映射：`Discovery (T1018, T1046, T1083)` → `Lateral Movement (T1021 Remote Services, T1570 Lateral Tool Transfer)` → `Credential Access (T1003, T1110)` → `Persistence`
  - 横向移动是「单点失陷 → 整网失陷」的转折点，护网期间一旦出现横向痕迹，必须按重大事件应对。
- **护网期间出现频次**：中低（攻击者要先突破边界），但**一旦出现是高危事件**。
- **常见子类**：
  1. SSH 横向（最常见）：拿到主机 root/普通用户后，对内网 22 端口扫描 + 跳跃
  2. SMB / PsExec 横向：Windows 域内或 SMB 共享暴露的内网
  3. WMI / WMIC 横向：Windows 内网，依赖管理员凭据
  4. Redis 未授权 + 写 SSH 公钥：内网 6379 未授权暴露 → 写 root 的 authorized_keys

## 2. 识别特征

> 只描述识别特征，不输出可复现 payload / 利用工具完整命令。

### 2.1 静态特征（流量与连接）

- **内网横向扫描特征**：
  - 单主机短时间内对 /24 网段的多个 IP 同端口（22 / 445 / 3389 / 6379）发起连接
  - SYN 扫描痕迹：单 IP 发起大量未完成的 TCP 握手
  - 服务探测：单 IP 在多主机上发起 nmap 类指纹采集
- **失陷主机的 outbound 异常**：
  - 长连接到 C2 端口（4444 / 5555 / 7777 / 8888 / 1024+ 的非业务端口）
  - 定时 beacon：固定间隔（每 30s / 60s / 5min）的小流量出站连接
  - 心跳包：固定大小（如 64B / 128B）的周期性 TCP / UDP / HTTPS 心跳
  - 异常 DNS：周期性查询 DGA 域名 / 短随机子域名
- **横向移动 payload 落地**：
  - `/tmp/`、`/var/tmp/`、`/dev/shm/` 出现可执行文件（`fscan`、`scan`、`agent`、`x`、`a`、`b` 等单字母）
  - Windows：`C:\ProgramData\`、`C:\Users\Public\`、`C:\Windows\Temp\` 下的新可执行文件
  - 隧道工具落地：`frp`、`nps`、`ngrok`、`chisel`、`gost`、`stowaway`

### 2.2 行为特征

- **凭据复用攻击**：
  - 同账户在多台主机短时间内出现登录（横跨 N 台主机的相同账户）
  - 短时间内 N 个账户在同一台主机失败登录然后成功（pivot 跳板典型）
- **管理员账户异常使用**：
  - 域管理员 / 业务超级管理员账户在「非管理时段」（凌晨）登录
  - 域管理员账户从「不是管理员办公的主机」发起登录
- **共享访问异常**：
  - SMB / NFS 共享被新主机 / 新账户首次访问
  - 内部 git / svn / nas 等被异常账户访问大量项目

### 2.3 上下文特征

- **失陷主机已确认**：发现一台主机失陷后，假设 24h 内攻击者已尝试横向，立即扫所有相邻主机
- **凭据已被窃**：发现攻击者读取了 `/etc/shadow`、`SAM`、`NTDS.dit`、bash_history、`.bash_history`、`.zsh_history` 时，假设凭据已外泄
- **工具落地**：内网主机出现 `fscan` / `cs beacon` / `sliver` / `frp` / `nps` / `impacket` 类工具的运行痕迹

### 2.4 各子类的独有指纹

#### SSH 横向

- **行为特征**：
  - 失陷主机的 bash_history 中出现：`ssh user@<internal-ip>` 模式批量
  - 大量 `Connection refused` / `Permission denied` 来自该失陷主机对内网的连接
  - `~/.ssh/known_hosts` 中突然新增大量内网 IP
  - `~/.ssh/config` 中新增多个 Host 项
- **流量特征**：
  - 失陷主机对内网 /24 段 22 端口的批量探测
- **凭据特征**：
  - 同一公钥指纹出现在多台主机的 `authorized_keys` 中
  - `id_rsa` 私钥被读取（`cat ~/.ssh/id_rsa` 进 bash_history）

#### SMB / PsExec 横向

- **工具特征**：
  - Impacket 套件：`psexec.py`、`smbexec.py`、`wmiexec.py`、`atexec.py`
  - 落地文件：`C:\Windows\` 下的 `PSEXESVC.exe` 服务、`<random>.exe` 服务可执行
- **事件特征**（Windows EventID）：
  - `4624 LogonType=3`（网络登录）/ `LogonType=5`（服务登录）异常账户
  - `5145`（详细文件共享访问）—— 关注 `IPC$`、`ADMIN$`、`C$`
  - `7045`（服务安装）—— 新增名称随机的服务
  - `4697`（服务创建）
- **流量特征**：
  - 内网 445 端口的非业务连接（特别是从非管理主机发起）
  - SMB 协议层的 `\\<target>\IPC$\<random>` 命名管道

#### WMI / WMIC 横向

- **工具特征**：
  - `wmic /node:<target> process call create "..."` 命令痕迹
  - Impacket `wmiexec.py`
- **事件特征**：
  - PowerShell 4104 ScriptBlock 中含 `Invoke-WmiMethod`、`Get-WmiObject`、`Win32_Process`
  - `4688` 进程创建：父进程 `WmiPrvSE.exe` 拉起 cmd / powershell

#### Redis 未授权 + 写公钥

- **行为序列**（识别用）：
  1. Redis 6379 外部 IP 直连成功（无 auth）
  2. `CONFIG SET dir /root/.ssh/`
  3. `CONFIG SET dbfilename authorized_keys`
  4. `SET <key> "<attacker-public-key>"`
  5. `SAVE` / `BGSAVE`
  6. 攻击者 SSH 登录 root
- **流量特征**：
  - 6379 端口外部访问 + RESP 协议中的 `CONFIG SET dir` / `CONFIG SET dbfilename`
  - Redis slow log 中出现这些 CONFIG 命令

### 2.5 攻击工具指纹（识别用）

| 工具 | 用途 | 识别特征 |
|---|---|---|
| `fscan` | 综合内网扫描 | `result.txt` / `1.txt` 落地、批量探测多端口、命令行带 `-h` `-p` 内网段 |
| `Cobalt Strike beacon` | C2 与横向 | 默认 named pipe `\\.\pipe\msagent_*`、`stage` 系列特征、heartbeat 周期 |
| `sliver` | 开源 C2 | mTLS / DNS / HTTP 多通道、二进制大、UPX 加壳 |
| `frp` | 端口转发 | 配置文件 `frpc.ini`/`frps.ini`、默认端口 7000、连接日志特征 |
| `nps` | 端口转发 | 配置文件 `npc.conf`、web 管理 8080、heartbeat |
| `chisel` | TCP/UDP 隧道 | HTTP/HTTPS 上 WebSocket 隧道，长连接 |
| `gost` | 多协议隧道 | 命令行特征 `gost -L` / `gost -F`，多协议适配 |
| `stowaway` | 多级代理 | 多级跳板 + protobuf 流量 |
| `impacket` | Windows 协议套件 | psexec.py / wmiexec.py / smbexec.py / dcomexec.py / secretsdump.py |

### 2.6 关键端口与协议

横向移动相关端口（内网出现这些端口的非业务连接要警惕）：
- SSH: `22`
- SMB: `445`、`139`
- RDP: `3389`
- WinRM: `5985`、`5986`
- WMI / DCOM: `135` + 高位动态端口
- Redis: `6379`
- 中间件 RMI/JMX: `1099`、`1090`、`9999`
- WebLogic T3: `7001`、`7002`
- C2 / 隧道：`4444`、`5555`、`7777`、`8888`（CS 默认 stager 端口）

## 3. 日志查询模式（按日志类型）

### 3.1 auth.log / secure（SSH 横向）

```bash
# 同账户在多主机短时间登录（跨主机分析需要日志聚合）
grep -E 'Accepted (password|publickey)' /var/log/auth.log | awk '{print $9}' | sort | uniq -c

# 失陷主机的 bash_history 中 ssh 横向命令
grep -E '^ssh\s' /home/*/.bash_history /root/.bash_history 2>/dev/null

# authorized_keys 新增条目（与基线对比）
find /home /root -name authorized_keys -mtime -7 -ls

# known_hosts 中的新增内网 IP（攻击者批量 ssh 后会留痕）
find /home /root -name known_hosts -mtime -7 -ls
cat /root/.ssh/known_hosts | awk -F',| ' '{print $1}' | sort -u
```

### 3.2 Windows EventID（SMB/WMI/RDP 横向）

关键 EventID：
- `4624` —— 登录成功，重点 LogonType=3（网络）/5（服务）/10（RDP）
- `4625` —— 登录失败
- `4648` —— 显式凭据登录（横向典型）
- `4672` —— 高权限分配
- `4688` —— 进程创建，父进程异常
- `5140`、`5145` —— 文件共享访问审计
- `5156` —— WFP 允许的连接
- `7045` —— 服务安装
- `4697` —— 服务创建
- `4104` —— PowerShell ScriptBlock
- `1102` —— 安全日志清空（攻击者擦痕迹）

### 3.3 网络层 / Netflow

```bash
# 单主机对内网多 IP 同端口的连接（横向扫描典型）
# 假设有 netflow 或 conntrack 导出
awk -F',' '$3 == "192.168.1.50" {print $5":"$6}' netflow.csv | sort | uniq -c

# 同主机短时间内对 N 个内网 IP 的连接数
ss -tan | awk '$5 ~ /^192\.168\./ {print $5}' | awk -F: '{print $1}' | sort -u | wc -l

# 异常 outbound 持久连接（长连接）
ss -tan | grep ESTAB | awk '{print $5}' | sort | uniq -c | sort -rn | head -20
```

### 3.4 Redis 未授权识别

```bash
# Redis 日志（如启用）—— 关注 CONFIG SET 操作
grep -iE 'CONFIG\s+SET\s+(dir|dbfilename)' /var/log/redis/*.log

# Redis 配置层检查
grep -E '^(bind|requirepass|protected-mode)' /etc/redis/redis.conf
# 如果 bind 是 0.0.0.0、requirepass 空、protected-mode no → 高危
```

### 3.5 主机层（进程 / 文件 / 配置）

```bash
# /tmp、/var/tmp、/dev/shm 下的可执行文件（横向工具落地）
find /tmp /var/tmp /dev/shm -type f -executable -mtime -7 2>/dev/null

# 进程审计 —— 关注异常网络相关进程
ps auxf | grep -E 'nc\s|ncat\s|frpc\s|frps\s|chisel\s|gost\s|nps\s|npc\s|fscan\s'

# 隧道 / 反向代理的监听端口
ss -tlnp | grep -E ':(4444|5555|7777|8888|7000|8080|1080)\s'

# crontab 持久化（攻击者用 cron 重启 beacon）
crontab -l
for u in $(cut -f1 -d: /etc/passwd); do echo "==$u=="; crontab -u $u -l 2>/dev/null; done
ls -la /etc/cron.* /var/spool/cron/

# bash_history 关注内网批量探测命令
grep -E 'ssh\s|scp\s|rsync\s.*192\.168|10\.|172\.|nmap|masscan|fscan' /root/.bash_history /home/*/.bash_history 2>/dev/null
```

### 3.6 WAF / FW 告警（识别工具）

- `CobaltStrike`, `CS Beacon`, `Stager`, `Malleable C2`
- `Sliver`, `Meterpreter`
- `frp`, `nps`, `chisel`, `gost`（隧道工具签名）
- `Impacket`, `PsExec`, `wmiexec`
- `fscan`, `mass scan`, `internal scan`

## 4. 误报排查清单

| # | 误报特征 | 如何排除 |
|---|---|---|
| 1 | 运维批量推送配置 / 部署，使用 ansible / saltstack / 跳板机批量 SSH | 与运维对账日程；源主机是运维跳板机 IP；账户是运维专用账户；时段在工作时段 |
| 2 | 监控系统（zabbix / prometheus node-exporter）对所有主机的轮询连接，呈现「单主机连多主机」特征 | 看源端口和目标端口是否是监控约定端口；UA / 协议指纹是不是 Zabbix/Prometheus agent |
| 3 | 域控正常的 4624 LogonType=3 流量（域内服务账户的 Kerberos 票据获取） | 看账户是不是已知服务账户（krbtgt、各种 svc_*）；目标主机是不是该服务正常访问的资源 |
| 4 | 备份系统从备份主机连接所有主机（NetBackup / Veeam / 自研备份） | 看时段（通常凌晨）+ 源主机 IP（备份服务器）+ 目标端口（备份专用端口） |
| 5 | 域内 SCCM / WSUS 推送补丁，445/SMB 流量 | 看源主机是否是 SCCM / WSUS 服务器 |
| 6 | 红蓝演练或安全工程师在做内网评估 | 与团队对账；工程师 IP 在白名单 |
| 7 | 开发 / 测试人员在内网调试，正常使用 SSH 跳跃 | 看账户是否是个人开发账户；时段是否合理；只跳跃到自己负责的开发机 |
| 8 | 业务集群内部的服务发现 / RPC 流量呈现网状连接 | 看是不是业务约定的 RPC 端口（如 dubbo 20880、grpc 50051）；账户是不是业务服务账户 |

**误报判定原则**：横向移动告警的误报代价低，**宁可误报也要查**。能与运维 / 监控 / 备份正常工作对账的，标 `false_positive_prob >= 0.7`，但需要 audit 模式回看 24h 确认无残留。

## 5. 关联升级规则

### 5.1 严重性升级

- **P2 → P1**：
  - 单主机出现内网横向扫描行为（即使没有成功连接）
  - 主机上出现已知横向工具落地物
- **P1 → P0**：
  - 横向成功（其他主机出现首次未授权登录 / 异常进程）
  - 凭据被窃迹象（`shadow` / `SAM` / `NTDS.dit` 被访问）
  - 域管理员账户在异常主机登录
  - C2 / beacon 流量持续 ≥ 1h
  - 失陷主机数 ≥ 2 → **整网失陷预警**，按重大事件升级

### 5.2 模式升级

- **monitor → audit**：任何横向告警都需要 audit 模式回看相关主机 24-72h 日志
- **audit → ir**：
  - 确认横向成功 → 立即 ir
  - 失陷主机 ≥ 2 → 立即 ir 并启动整网应急

## 6. 止血动作（containment）

> 横向移动的止血核心是「分段隔离」，不是清理单台主机。

### 6.1 网络层（最优先）

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| **VLAN 分段隔离** | 把失陷主机和疑似失陷主机切到隔离 VLAN，仅保留管理通道 | 业务流量需切换到其他主机 | 根除完成后回切 |
| 关闭横向通道 | 防火墙限制内网主机间 22/445/3389/6379 的访问，按白名单允许业务必需 | 影响合法运维和业务的内网通信 | 加白名单逐项放开 |
| 阻断 C2 出口 | 防火墙封 C2 IP / 域名 / 端口 | 攻击者可能切换通道但短期阻断有效 | 持续监控新通道 |
| 切断隧道流量 | 关闭已发现的 frp/nps/chisel 监听端口 | 攻击者隧道失效 | 不需要回退 |

### 6.2 主机层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| **隔离已失陷主机** | 摘负载 / 切管理 VLAN | 业务流量切换 | 根除完成后回切 |
| 快照取证 | 内存 + 磁盘快照 | 占用资源 | 证据保留 |
| kill 横向工具进程 | 杀掉 fscan / beacon / frp 等 | 攻击者会重启，需要持久化也清理 | 同时清持久化 |
| 关闭 SMB / Redis 等服务 | 临时停服 | 业务受影响 | 加固后重启 |
| 卸载隧道工具 | 删除 frp/nps/chisel 二进制 + 配置 | 攻击者重新部署 | 同时改防火墙规则 |

### 6.3 应用层

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| Redis 加 requirepass + 改 bind | 不允许公网 / 内网随便访问 | 应用配置同步更新连接字符串 | 标准流程 |
| Redis / Memcached / ES 加固 | 默认禁用 CONFIG / FLUSHALL 等危险命令 | 影响管理工具 | 加白名单 |
| SMB 关闭 / 限制 | 关闭 SMBv1，限制 IPC$/ADMIN$ 访问 | 部分老应用不可用 | 升级老应用 |
| 关闭 PsExec 类管理通道 | 限制 ADMIN$ 共享只允许特定管理工作站 | 远程管理变化 | 标准流程 |

### 6.4 账号层（这是横向止血的核心）

| 动作 | 操作要点 | 副作用 | 回退路径 |
|---|---|---|---|
| **轮换所有失陷主机上的本地账户口令** | 同时同步给运维并通知用户改密 | 短期登录受影响 | 标准流程 |
| **轮换域管理员凭据** | 重置 `krbtgt` 两次（间隔 10h+），重置所有 DA 账户口令 | 域内 Kerberos 票据失效，全员需重新登录 | 必须做，无回退 |
| 轮换所有 SSH key | 收集旧 key，分发新 key | 全员配置更新 | 标准流程 |
| 回收业务服务账户凭据 | 数据库、API、中间件账户全部轮换 | 应用配置同步更新 | 配合发布 |
| 清理所有主机的 authorized_keys | 比对基线，删除非授权 key | 误删合法 key 需要分发 | 比对基线 |
| 强制全员重置个人密码 | 工作量大但必须做 | 短期 helpdesk 压力 | 通过 SSO 统一推送 |

## 7. 根除与恢复（eradication & recovery）

### 7.1 根除步骤

1. **画清失陷面**（最重要的一步）：
   - 第一台失陷主机：明确入口
   - 通过 bash_history / EventLog / netflow / 连接记录，找出**所有被攻击者访问过**的主机
   - 通过凭据使用记录，找出**所有凭据被复用**的主机
   - 通过工具落地物，找出**所有部署了横向工具**的主机
2. **清理所有失陷主机的落地物**：
   - 二进制文件：`fscan`、`beacon`、`frp`、`nps`、`chisel` 等
   - 配置文件：`frpc.ini`、`npc.conf` 等
   - 临时文件：`/tmp/result.txt`、`/tmp/1.txt`、`/tmp/.*` 隐藏文件
3. **清理所有失陷主机的持久化**（参考 command-exec.md 持久化清单）：
   - crontab、systemd 单元、init 脚本
   - SSH authorized_keys
   - shell rc 文件
   - 启动项
4. **凭据全面轮换**（横向移动的根除核心是凭据轮换）：
   - 所有失陷主机的本地账户
   - 所有可能被窃的 SSH 私钥
   - 所有可能被窃的域账户（特别是 DA）
   - 所有可能被窃的服务账户
   - **krbtgt 重置两次**（间隔 10h+，否则旧黄金票据仍可用）
5. **修补横向通道**：
   - Redis 加 auth、改 bind
   - SMB 加固
   - SSH key only
   - 网络分段（生产 / 办公 / 管理 分网）

### 7.2 恢复步骤

- 失陷面已画清 + 凭据已轮换 + 落地物已清理 → 加固后回切
- 域控失陷 / 关键业务系统失陷 → 整域 / 整业务系统重建，从可信基线恢复
- 不确定彻底清理 → 推荐重装系统 + 还原业务数据（数据需扫描）

### 7.3 验证点

1. **连接层验证**：失陷主机的 outbound 连接 24h 干净，无 C2 / beacon / 隧道流量
2. **进程层验证**：所有失陷主机 24h 无异常进程，无横向工具运行
3. **凭据层验证**：
   - krbtgt 已二次重置（hash 已变）
   - 所有 DA 账户密码已重置
   - 所有 SSH key 已轮换（旧 key 列表已下发废止）
4. **配置层验证**：Redis / SMB / SSH 等所有横向通道已加固，配置与基线一致
5. **网络层验证**：分段策略已生效，跨段访问按白名单
6. **告警验证**：24-72h 监控无新增横向告警

## 8. IOC 提取模板

```json
[
  {
    "type": "ip",
    "value": "192.168.1.xxx",
    "confidence": "high",
    "first_seen": "2026-06-30T15:30:11+08:00",
    "source": "auth.log:line-22318",
    "tag": "lateral,compromised-host,pivot-source",
    "description": "失陷主机，作为横向跳板攻击 192.168.1.51-100"
  },
  {
    "type": "ip",
    "value": "192.168.1.yyy",
    "confidence": "high",
    "first_seen": "2026-06-30T15:32:00+08:00",
    "source": "auth.log:line-22420",
    "tag": "lateral,compromised-host,target"
  },
  {
    "type": "hash:sha256",
    "value": "<fscan-binary-sha256>",
    "confidence": "high",
    "first_seen": "2026-06-30T15:31:22+08:00",
    "source": "host:/tmp/fs",
    "tag": "tool:fscan,lateral-tool"
  },
  {
    "type": "ip",
    "value": "<c2-external-ip>",
    "confidence": "high",
    "first_seen": "2026-06-30T15:00:11+08:00",
    "source": "conntrack:line-1023",
    "tag": "c2,cobaltstrike,beacon"
  },
  {
    "type": "tool",
    "value": "fscan",
    "confidence": "high",
    "first_seen": "2026-06-30T15:31:22+08:00",
    "source": "rule:PLB-LM-001",
    "tag": "lateral-tool"
  },
  {
    "type": "path",
    "value": "/root/.ssh/authorized_keys",
    "confidence": "high",
    "first_seen": "2026-06-30T15:35:00+08:00",
    "source": "host:diff-with-baseline",
    "tag": "persistence:ssh-key,lateral-persistence",
    "description": "authorized_keys 中新增非授权公钥指纹 SHA256:abcd..."
  }
]
```

提取重点：
- 所有失陷主机的 IP / hostname（pivot-source 和 target 都要标）
- C2 / beacon 服务器 IP / 域名 / 端口
- 横向工具的 hash（fscan / cs beacon / frp 等）
- 攻击者公钥指纹（被写入 authorized_keys 的）
- 被窃的账户名 / 凭据
- 横向使用的协议 / 端口（SSH 22 / SMB 445 / Redis 6379 等）

---

## rule_id 命名约定

- 前缀：`PLB-LM-NNN`（PlayBook-LateralMovement）

### 已建议规则一览

| rule_id | 规则名 | 触发条件 |
|---|---|---|
| PLB-LM-001 | 内网横向扫描（fscan / nmap） | 单主机 5min 内对内网 ≥ 20 个 IP 同端口连接 |
| PLB-LM-002 | SSH 横向批量 | 单主机 1h 内 ssh 连接 ≥ 10 个不同内网 IP |
| PLB-LM-003 | SMB / PsExec 横向 | EventID 4624 LogonType=3/5 异常账户 + 5145 IPC$/ADMIN$ 访问 |
| PLB-LM-004 | WMI 横向 | EventID 4688 父进程 WmiPrvSE.exe 拉起 cmd/powershell |
| PLB-LM-005 | Redis 未授权 + 写公钥 | Redis 日志含 `CONFIG SET dir` + `CONFIG SET dbfilename authorized_keys` |
| PLB-LM-006 | CobaltStrike beacon | 进程 / 流量含 CS 默认 named pipe / heartbeat 周期 / 默认端口 |
| PLB-LM-007 | frp / nps 隧道工具 | 进程命令行含 `frpc -c`/`npc -server`/`chisel client` 等 |
| PLB-LM-008 | 凭据复用横向 | 同账户在多主机短时间登录（跨主机日志聚合） |
| PLB-LM-009 | 域管异常使用 | DA 账户在「非管理主机」首次登录 |
| PLB-LM-010 | shadow / SAM / NTDS 访问 | `cat /etc/shadow` / `reg save HKLM\SAM` / `ntdsutil` 痕迹 |
| PLB-LM-011 | authorized_keys 异常新增 | `~/.ssh/authorized_keys` 新增条目（与基线对比） |
| PLB-LM-012 | 内网长连接 C2 | 主机对外/内 IP 的非业务端口长连接 ≥ 1h + 周期心跳 |
| PLB-LM-013 | impacket 工具特征 | 命令行 / Event 中含 `psexec.py`/`wmiexec.py`/`secretsdump.py` |
| PLB-LM-014 | Kerberos 异常（黄金/白银票据） | krbtgt 账户的 4769、PAC 异常、非常规票据生命周期 |
| PLB-LM-015 | 跨段访问异常 | 生产 ↔ 办公 / 生产 ↔ 管理 跨网段的非白名单访问 |
