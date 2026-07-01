# Windows Lateral Traffic Signatures — Windows 横向流量识别

> Windows 环境下横向移动（Lateral Movement）的流量层识别知识库。
> **何时使用**：判断已经攻陷内网某台 Windows 主机后，攻击者是否在向其他主机横向；或事后审计横向路径。
> 仅描述识别特征，不给出可复现的横向 payload。
> 关联运行时规则：`R-TRAF-101` ~ `R-TRAF-199`（Windows lateral 段）；知识库：`SIG-TRAF-101` ~ `SIG-TRAF-199`。

---

## 分类速查表

| 通道 | 端口 | rule_id | severity 上限 | 主要视图 |
|---|---|---|---|---|
| SMB 横向 | 445, 139 | R-TRAF-101~120 | P0 | flow + smb |
| RDP 横向 | 3389 | R-TRAF-121~130 | P0 | tls + flow |
| WMI 远程执行 | 135 + 49152-65535 | R-TRAF-131~140 | P0 | dcerpc + flow |
| WinRM | 5985, 5986 | R-TRAF-141~150 | P0 | http |
| Kerberos 异常 | 88 (tcp/udp) | R-TRAF-151~160 | P0 | kerberos |

---

## 1. SMB 横向（445 端口）

### 1.1 SMBv1 vs SMBv2/v3 识别

- **SMBv1 特征**：Negotiate 请求 dialects 含 `NT LM 0.12` / `PC NETWORK PROGRAM 1.0` 等老 dialect —— 现代 Windows 通常已禁用；**SMBv1 出现即高危**（可能是 EternalBlue MS17-010 相关工具）
- **SMBv2 特征**：dialects `0x0202` / `0x0210`
- **SMBv3 特征**：dialects `0x0300` / `0x0302` / `0x0311`
- **加密标志**：SMBv3 支持加密（`SMB2 encryption`），Impacket 类工具默认不启用加密，是识别特征

### 1.2 命名管道横向识别

Impacket / PsExec 类工具依赖特定命名管道。SMB2 Create Request 中的 File Name 字段是关键。

| 管道名 | 用途 | 命中风险 |
|---|---|---|
| `\PIPE\svcctl` | 服务控制器（创建 / 启动服务） | 高，PsExec / smbexec 依赖 |
| `\PIPE\lsass` | LSASS 命名管道 | 高，凭据 dump |
| `\PIPE\samr` | 用户 / 组管理 | 高，账户枚举 |
| `\PIPE\netlogon` | 域登录服务 | 中，DCSync 攻击依赖 |
| `\PIPE\srvsvc` | 服务器管理 | 中，SharpHound 枚举 |
| `\PIPE\wkssvc` | 工作站服务 | 中，账户会话枚举 |
| `\PIPE\atsvc` | 任务计划服务 | 高，通过任务计划横向 |
| `\PIPE\lsarpc` | LSA 远程调用 | 高，凭据 / 策略操作 |
| `\PIPE\eventlog` | 事件日志 | 中，清日志 |

### 1.3 PsExec 家族识别

- **原版 SysInternals PsExec**：
  - 上传 `PSEXESVC.exe` 到目标 `ADMIN$` 共享 → 命名管道 `\PIPE\PSEXESVC`
  - 三个附加管道：`\PIPE\PSEXESVC-<hostname>-<pid>-stdin` / `-stdout` / `-stderr`
- **Impacket psexec.py**：
  - 默认服务名随机 8 字符（如 `\PIPE\<random8>`）
  - 上传的 exe 名也是随机 8 字符
  - 命令回显通过 SMB Read/Write on named pipe
- **Impacket smbexec.py**：
  - 不上传 exe，直接创建临时服务执行命令
  - 用 `\PIPE\lsass` 或 `\PIPE\svcctl` 触发
  - 输出重定向到 `C:\__output` 文件，通过 SMB read 回收 —— **命名文件 `__output` 是强特征**
- **Impacket dcomexec.py**：走 DCOM，不主要用 SMB，但会在 SMB 上留下认证痕迹
- **Impacket wmiexec.py**：走 DCOM + WMI，见 §3
- **Impacket atexec.py**：走 `\PIPE\atsvc` 创建计划任务

### 1.4 Impacket 家族通用识别

- **NTLM 认证 workstation 字段**：Impacket 默认 workstation 空或固定字符
- **SMB session key**：Impacket 生成的 session key 熵值可辨（有 pattern）
- **文件名 pattern**：随机 8 字符 alphanumeric `[A-Za-z0-9]{8}.exe`
- **服务 DisplayName**：Impacket 常用 `wxyx` `abcd` 等短标识
- **client GUID**：Impacket 默认 GUID pattern 与 Windows 原生工具不同

### 1.5 匿名 SMB 探测

- **NULL session setup**：Session Setup Request 中 Username / Domain / Password 全空
- **用途**：枚举共享（`\\<ip>\IPC$`） / 枚举用户 / 探测系统信息
- **tshark filter**：`smb2.cmd == 1 and ntlmssp.auth.username == ""`

### 1.6 关联 rule_id

- `R-TRAF-101`：SMBv1 dialect 出现
- `R-TRAF-102`：SMB 命名管道 `PSEXESVC` 命中
- `R-TRAF-103`：Impacket 特征命名管道（8 字符随机 + `-stdin/stdout/stderr`）
- `R-TRAF-104`：SMB 共享上传 `.exe` 到 `ADMIN$` / `C$`
- `R-TRAF-105`：`\PIPE\svcctl` 创建服务 + 立即启动
- `R-TRAF-106`：SMB 匿名 session（NULL session setup）
- `R-TRAF-107`：SMB 短时间连接 5+ 台内网主机（横向扫描 pattern）
- `R-TRAF-108`：`__output` / `__<random>` 文件读写（smbexec 特征）

### 1.7 tshark filter 备忘

```bash
# 所有 SMB2 Create Request，看目标文件 / 管道
tshark -r <pcap> -Y "smb2.cmd == 5" -T fields -e smb2.filename

# 查找可疑命名管道
tshark -r <pcap> -Y 'smb2.filename contains "PSEXESVC" or smb2.filename contains "\\PIPE\\"'

# NULL session
tshark -r <pcap> -Y 'ntlmssp.auth.username == "" and smb2.cmd == 1'

# 上传到 ADMIN$
tshark -r <pcap> -Y 'smb2.tree contains "ADMIN$" and smb2.cmd == 5'

# 会话统计（谁访问了谁的 445）
tshark -r <pcap> -q -z conv,tcp -f "port 445"
```

### 1.8 误报排查

- 域内合法的 GPO 应用（`\PIPE\netlogon` 会有大量）—— 但通常源是 DC，目的是所有客户端
- 备份任务（rsync-over-SMB / robocopy 定时任务）—— 走 ADMIN$/C$ 但文件类型固定 + 时间规律
- 域内软件分发（SCCM 类）—— 有固定 IP 分发点
- 域内文件共享服务 —— 走的是命名共享（`\\fileserv\public`），不是 ADMIN$

### 1.9 处置引用

参考 `references/playbooks/lateral-movement.md` §SMB 横向 章节。

---

## 2. RDP 异常（3389 端口）

### 2.1 RDP 暴破识别

- **TLS ClientHello 大量重复**：短时间同 dst_ip 出现大量 RDP TLS 握手（每次尝试都会重建连接）
- **认证失败特征**：TLS 握手后建立时长很短（< 3s）就断开
- **源 IP 特征**：单 src_ip 5 分钟内对同 dst 尝试 > 20 次
- **暴破工具指纹**：
  - `hydra`：无独有 TLS 指纹但认证节奏机械
  - `crowbar`：默认 client hello 使用 mstsc 兼容
  - `RDPScan`：批量扫，先做 TLS 探测再尝试认证

### 2.2 RDP 横向识别

- **画像变化**：一台受控主机 → **新增 RDP 出站**，之前从未见过该 dst_ip
- **认证成功后行为**：TLS 会话时长明显更长（> 60s），有交互式数据传输
- **多跳 RDP 链**：主机 A → RDP → 主机 B → RDP → 主机 C（横向前进特征）
- **RDP hijacking 痕迹**：
  - `bettercap` / `freerdp` / `xfreerdp` 的 UA / client Hello 特征与 mstsc 不同
  - Impacket 的 `rdp_check.py` 只做认证不进入桌面 —— TLS 握手完就断
  - `mstsc.exe` 从异常账户发起（如 domain admin 登录到普通用户主机）

### 2.3 关联 rule_id

- `R-TRAF-121`：RDP 短时高频握手（暴破嫌疑）
- `R-TRAF-122`：内网主机新增 RDP 出站
- `R-TRAF-123`：跨 3 台主机的 RDP 连锁（横向链）
- `R-TRAF-124`：非 mstsc 客户端 RDP 连接（freerdp / bettercap 指纹）

### 2.4 tshark filter 备忘

```bash
# RDP 连接目标统计
tshark -r <pcap> -Y "tcp.port == 3389" -T fields -e ip.src -e ip.dst | sort -u

# RDP 认证握手（Cred SSP）时长过短（可能暴破）
tshark -r <pcap> -Y "tcp.port == 3389 and tls.handshake.type == 1"
```

### 2.5 误报排查

- 运维日常 RDP：通常有固定跳板机 IP + 固定运维时段
- 堡垒机会话：所有 RDP 走同一堡垒机 IP —— 加白
- 屏幕录制 / 远程协助（TeamViewer / AnyDesk）：不是 3389，而是各自服务的端口

### 2.6 处置引用

参考 `references/playbooks/lateral-movement.md` §RDP 章节。

---

## 3. WMI 远程执行（DCOM，135 + 高端口 49152-65535）

### 3.1 DCOM 协议识别

- **135 端口 endpoint mapper**：DCERPC epmap 查询，用于发现动态端口
- **高端口通信**：49152-65535 上的 DCERPC 通信（Windows 默认 RPC 动态端口范围）
- **接口 UUID 关键**：
  - `9556DC99-828C-11CF-A37E-00AA003240C7` = IWbemServices（WMI 主接口）
  - `F309AD18-D86A-11D0-A075-00C04FB68820` = IWbemLevel1Login
  - `423EC01E-2E35-11D2-B604-00104B703EFD` = IWbemContext
  - `4590F812-1D3A-11D0-891F-00AA004B2E24` = IWbemClassObject

### 3.2 MS-DCOM 特征

- **CoCreateInstance 序列**：客户端向 135 端口发起 IRemoteSCMActivator RemoteCreateInstance
- **ORPCTHIS header**：DCE/RPC 上的 DCOM header，含 CID / cbExtension / flags
- **认证阶段**：NTLM SSP 协商，观察 workstation 字段

### 3.3 wmiexec.py 特征

- **命令执行流程**：
  1. 135 端口 IWbemLevel1Login::NTLMLogin
  2. 高端口 IWbemServices::ExecMethod（调用 Win32_Process::Create）
  3. 结果写入 `\\<target>\ADMIN$\<random>.tmp`
  4. 通过 SMB read 该文件回收 stdout
- **强特征**：单 src_ip 短时间内同时出现 DCOM 135 + SMB 445 双通道
- **命令行 pattern**：ExecMethod 参数中含 `cmd.exe /Q /c <cmd> 1> \\127.0.0.1\ADMIN$\__<timestamp> 2>&1`

### 3.4 关联 rule_id

- `R-TRAF-131`：DCOM 到 135 端口 + 高端口 RPC 组合（横向嫌疑）
- `R-TRAF-132`：IWbemLevel1Login::NTLMLogin 调用 + 后续 Win32_Process::Create
- `R-TRAF-133`：ExecMethod 参数含 `cmd.exe /Q /c` 特征
- `R-TRAF-134`：DCOM + SMB 双通道，SMB 上出现 `__<timestamp>` 临时文件

### 3.5 tshark filter 备忘

```bash
# DCOM 相关流量
tshark -r <pcap> -Y "dcerpc.pkt_type == 0 and (ip.dstport == 135 or (ip.dstport >= 49152 and ip.dstport <= 65535))"

# WMI 接口调用
tshark -r <pcap> -Y "dcerpc.iface_uuid == 9556dc99-828c-11cf-a37e-00aa003240c7"
```

### 3.6 误报排查

- SCCM / WSUS：域内合法用 WMI 分发软件，源固定
- Nagios / Zabbix WMI 监控：源是监控服务器，目的是被监控客户端 —— 加白
- PowerShell DSC（Desired State Configuration）：合法运维用 WMI

### 3.7 处置引用

参考 `references/playbooks/lateral-movement.md` §WMI 章节。

---

## 4. WinRM（5985 / 5986）

### 4.1 协议识别

- **端口**：5985（HTTP） / 5986（HTTPS）
- **HTTP POST 到 `/wsman`**：所有 WinRM 请求都 POST 到该路径
- **SOAP envelope**：body 是 XML SOAP，含 `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">` + WS-Management 命名空间
- **Content-Type**：`application/soap+xml;charset=UTF-8`

### 4.2 evil-winrm 特征

- **UA / SOAP 命名空间**：与 Windows 原生 winrm 相同（较难仅凭协议区分）
- **命令执行调用**：`http://schemas.microsoft.com/wbem/wsman/1/wsman/rsp/Command` action
- **shell 建立**：`Create` + `Shell` 组合，随后大量 `Send` / `Receive` 命令
- **短会话密集命令**：evil-winrm 交互式使用时命令频率高

### 4.3 关联 rule_id

- `R-TRAF-141`：WinRM POST /wsman + 短时高频命令
- `R-TRAF-142`：WinRM HTTP（5985）而非 HTTPS —— 明文传输，域环境异常
- `R-TRAF-143`：WinRM 连接来自内网非管理 VLAN

### 4.4 tshark filter 备忘

```bash
# WinRM HTTP
tshark -r <pcap> -Y "http.request.uri contains '/wsman'"

# 命令类调用
tshark -r <pcap> -Y "http.request.uri contains '/wsman' and http contains 'CommandLine'"
```

### 4.5 误报排查

- Ansible over WinRM：合法运维使用，源固定为 Ansible 管理机
- PowerShell Remoting：合法运维，与 Ansible 类似需要白名单管理源

### 4.6 处置引用

参考 `references/playbooks/lateral-movement.md` §WinRM 章节。

---

## 5. Kerberos 异常（88/tcp, 88/udp）

### 5.1 协议基础

- Kerberos 5 主要消息类型：AS-REQ / AS-REP（认证请求 / 响应） / TGS-REQ / TGS-REP（票据请求 / 响应） / AP-REQ / AP-REP
- 加密类型（etype）：
  - 3 = DES-CBC-MD5（老，不安全，罕见）
  - 17 = AES128-CTS-HMAC-SHA1-96
  - 18 = AES256-CTS-HMAC-SHA1-96
  - 23 = RC4-HMAC（较老，Kerberoasting 常使用）
  - 24 = RC4-HMAC-EXP

### 5.2 Kerberoasting 识别

- **TGS-REQ 中 SPN 请求突增**：短时间大量 TGS-REQ 请求不同 SPN（`MSSQL/*` / `HTTP/*` / `HOST/*`）
- **etype = 23 (RC4-HMAC)**：Kerberoasting 依赖弱哈希，攻击者会请求 RC4 加密的 TGS
- **service name pattern**：常见目标 SPN 为 SQL / IIS / HTTP / CIFS
- **发起源**：来自普通用户账户（非管理员）的 TGS-REQ 批量请求

### 5.3 ASREPRoasting 识别

- **AS-REQ 不带 preauth**：AS-REQ 消息中 PA-DATA 字段缺失 PA-ENC-TIMESTAMP
- **前提**：目标账户 UAC 位设置了 `DONT_REQUIRE_PREAUTH`（0x0400000）
- **响应特征**：DC 返回 AS-REP，攻击者拿到可离线破解的密文
- **发起源**：陌生 IP 大量试探不同用户名

### 5.4 S4U2Self / S4U2Proxy 识别

- **S4U2Self**：TGS-REQ 中 additional-tickets 字段存在，for-user 字段指定目标用户
- **S4U2Proxy**：TGS-REQ 使用 S4U2Self 得到的 ticket 作为 additional-tickets，请求代表其他用户
- **合法用途**：Kerberos 约束委派、SharePoint / SQL 委派
- **恶意用途**：Constrained Delegation Abuse 提权 / 横向

### 5.5 Golden / Silver Ticket 识别

- Golden/Silver Ticket 是伪造 ticket，网络流量层不易直接识别
- **可疑信号**：
  - AP-REQ 中 ticket 的 client name 与实际发起源不匹配
  - ticket 生命周期超长（默认 10h，Golden Ticket 常设 10 年）
  - 从未见过认证的用户名突然出现在关键服务的 AP-REQ

### 5.6 关联 rule_id

- `R-TRAF-151`：TGS-REQ 中 etype=23 (RC4) 突增（Kerberoasting）
- `R-TRAF-152`：AS-REQ without preauth（ASREPRoasting）
- `R-TRAF-153`：单账户短时间请求 5+ 个 SPN
- `R-TRAF-154`：S4U2Self 后紧接 S4U2Proxy（可能是委派滥用）
- `R-TRAF-155`：从未认证过的账户突然出现 AP-REQ

### 5.7 tshark filter 备忘

```bash
# 所有 Kerberos
tshark -r <pcap> -Y "kerberos"

# TGS-REQ 请求
tshark -r <pcap> -Y "kerberos.msg_type == 12"

# RC4 加密的 Kerberos 请求（Kerberoasting）
tshark -r <pcap> -Y "kerberos.etype == 23"

# 提取 SPN
tshark -r <pcap> -Y "kerberos.msg_type == 12" -T fields -e kerberos.SNameString
```

### 5.8 误报排查

- Windows 老版本 / 兼容性配置强制 RC4 —— 需要客户环境评估
- SharePoint / SQL 合法委派：S4U 有合法用途，需要与业务对账
- 一次 SPN 密集查询：AD 探测工具（BloodHound）在合法权限测试时也会触发

### 5.9 处置引用

参考 `references/playbooks/lateral-movement.md` §Kerberos 章节。

---

## 附录 A：tshark filter 快速索引

| 场景 | filter |
|---|---|
| SMBv1 出现 | `smb.negprot.dialect contains "NT LM 0.12"` |
| SMB 命名管道 | `smb2.filename contains "\\PIPE\\"` |
| PsExec 特征 | `smb2.filename contains "PSEXESVC"` |
| NULL session | `ntlmssp.auth.username == ""` |
| RDP 会话 | `tcp.port == 3389 and tls.handshake` |
| DCOM 到 135 | `tcp.port == 135 and dcerpc` |
| WMI 接口 | `dcerpc.iface_uuid == 9556dc99-828c-11cf-a37e-00aa003240c7` |
| WinRM | `http.request.uri contains "/wsman"` |
| Kerberoasting | `kerberos.msg_type == 12 and kerberos.etype == 23` |
| ASREPRoasting | `kerberos.msg_type == 10 and !kerberos.padata` |

---

## 附录 B：Windows 事件与流量的对照

流量层线索需要主机侧事件对齐，参考主机侧：

| 流量特征 | 对应 Windows Event ID |
|---|---|
| SMB PsExec | 7045（服务安装） + 4624 type 3（网络登录） |
| RDP 登录 | 4624 type 10（远程交互） |
| WMI 执行 | 4688（进程创建 wmiprvse.exe → 子进程） |
| WinRM | 4624 type 3 + 4103（PowerShell 模块日志） |
| Kerberoasting | 4769（TGS 请求日志） |

---

## 附录 C：与其他文档的交叉索引

- SMB 攻击特征（含 EternalBlue）：`references/attack-patterns/malicious-traffic.md` §6 C2
- Lateral movement 处置：`references/playbooks/lateral-movement.md`
- 主机侧凭据 dump 识别：`references/attack-patterns/c2-signatures.md` §一.2
- 内网穿透（隧道搭建）：`references/attack-patterns/tunnel-tools-traffic.md`
