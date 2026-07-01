# Windows EventLog 关键 EventID 速查

> Windows 事件 ID 速查表，假定 evtx 已通过 `wevtutil` / `Get-WinEvent` / `chainsaw` 导出为 CSV/XML。
> **何时使用**：audit / ir 模式拿到 Windows 主机的 Security / System / Application 导出文件时。

---

## 一、Security 日志（最常用）

### 1.1 登录类

| EventID | 含义 | 关注字段 |
|---|---|---|
| 4624 | 登录成功 | `LogonType` / `TargetUserName` / `IpAddress` / `LogonProcessName` |
| 4625 | 登录失败 | `LogonType` / `TargetUserName` / `IpAddress` / `Status` / `SubStatus` |
| 4634 | 登出 | `LogonId` |
| 4647 | 用户主动登出 | `LogonId` |
| 4648 | 显式凭据登录（runas / Invoke-Command）| `SubjectUserName` / `TargetUserName` / `TargetServerName` |
| 4672 | 特殊权限授予（管理员级登录）| `SubjectUserName` / `PrivilegeList` |
| 4768 | Kerberos TGT 申请 | `TargetUserName` / `IpAddress` / `TicketEncryptionType` |
| 4769 | Kerberos ST 申请 | `ServiceName` / `IpAddress` |
| 4771 | Kerberos 预身份验证失败 | `FailureCode`（0x18 密码错） |
| 4776 | NTLM 凭证验证 | `TargetUserName` / `Workstation` / `Status` |

**LogonType 类型对照（4624 / 4625 必查）**：
- 2 — 交互式（控制台）
- 3 — 网络（SMB / IPC / 远程访问）
- 4 — 批处理（计划任务）
- 5 — 服务
- 7 — 解锁
- 8 — 网络明文凭证
- 9 — NewCredentials（runas /netonly）
- 10 — RemoteInteractive（RDP）
- 11 — CachedInteractive
- 13 — 缓存解锁

> 横向移动核心组合：**4624 LogonType=3（远程 SMB）** + 4672（特权）+ 4688（cmd.exe / powershell.exe） 跨主机出现 → SMB 横向落地。
> **4624 LogonType=10** + 异常源 IP → RDP 横向。

### 1.2 进程 / 命令行

| EventID | 含义 | 关注字段 |
|---|---|---|
| 4688 | 新进程创建 | `NewProcessName` / `ParentProcessName` / `CommandLine`（需启用） / `SubjectUserName` |
| 4689 | 进程退出 | `ProcessName` / `ExitStatus` |
| 5379 | 凭据管理器读取 | `TargetName` |

> **CommandLine 字段默认未启用**！需 GPO 启用 `Audit Process Creation` + `Include command line in process creation events`。
> 父子进程异常组合：`w3wp.exe → cmd.exe / powershell.exe`、`winword.exe → cmd.exe`、`mshta.exe → powershell.exe`。

### 1.3 账户 / 组

| EventID | 含义 |
|---|---|
| 4720 | 新建用户 |
| 4722 | 启用账户 |
| 4724 | 重置他人密码 |
| 4725 | 禁用账户 |
| 4726 | 删除账户 |
| 4738 | 账户属性变更（含 UAC 标志） |
| 4732 | 加入本地组 |
| 4756 | 加入通用组（Domain Admins / Enterprise Admins） |
| 4767 | 解锁账户 |

> **4732 + 目标组 = Administrators / Remote Desktop Users** → 即时 P0。
> **4756 + 目标组 = Domain Admins** → 域内提权信号，P0。

### 1.4 服务 / 计划任务 / 共享 / 防火墙

| EventID | 含义 | 备注 |
|---|---|---|
| 7045 | 服务安装（System 日志） | 关注 ImagePath 含可疑路径 / base64 |
| 4697 | 服务变更 | Security 日志，需启用 |
| 4698 | 计划任务创建 | TaskName / TaskContent |
| 4699 | 计划任务删除 | |
| 4700 / 4701 | 计划任务启用 / 禁用 | |
| 4702 | 计划任务更新 | |
| 5140 | 共享访问 | ShareName / IpAddress |
| 5145 | 共享对象访问详细 | ShareName / RelativeTargetName |
| 4663 | 文件/对象访问 | ObjectName / AccessMask（需 SACL） |

### 1.5 日志清除 / 反取证

| EventID | 含义 |
|---|---|
| 1102 | **Security 日志清空（高危信号）** |
| 104 | System 日志清空（System log） |
| 1100 | 事件服务停止 |

### 1.6 网络连接（Filtering Platform）

| EventID | 含义 |
|---|---|
| 5156 | 连接放行 |
| 5157 | 连接拒绝 |
| 5152 / 5154 | 监听放行 |

> 量大，仅在 ir 排查特定 PID 出网时启用。

---

## 二、System 日志关键 ID

| EventID | 含义 |
|---|---|
| 7045 | 服务安装 |
| 7034 | 服务异常退出 |
| 7036 | 服务状态变化 |
| 7040 | 服务启动类型变更 |
| 104 | 日志清空 |
| 6005 / 6006 | 事件服务启动 / 停止 |

---

## 三、PowerShell 日志（Microsoft-Windows-PowerShell/Operational）

| EventID | 含义 |
|---|---|
| 4103 | 模块日志（含管道执行） |
| 4104 | **脚本块日志（最重要）** —— 含完整命令体 |
| 4105 / 4106 | 脚本启动 / 停止 |

> 4104 启用后即使是 Empire / PowerSploit 这类 obfuscated 脚本也会被记录原文。蓝队优先看 4104。

---

## 四、Sysmon 关键 ID（如已部署）

| EventID | 含义 |
|---|---|
| 1 | 进程创建（含 hash） |
| 3 | 网络连接 |
| 7 | 镜像加载（DLL 注入定位） |
| 8 | CreateRemoteThread |
| 10 | ProcessAccess（dump lsass 信号） |
| 11 | 文件创建 |
| 13 | 注册表写 |
| 17/18 | 命名管道（CS named pipe） |
| 22 | DNS 查询 |
| 23 | 文件删除 |
| 25 | 进程篡改 |

---

## 五、横向移动 / 攻击链识别组合

| 行为 | 事件组合 |
|---|---|
| **SMB 横向（psexec/wmiexec）** | 源主机 4648 + 目标 4624(Type=3) + 目标 7045（远程 svc 安装）+ 目标 4688（cmd.exe by SYSTEM） |
| **RDP 横向** | 4624(Type=10) + 4778（会话重连） |
| **WinRM / WMI 横向** | 4624(Type=3) by Service=WSMAN / WMI + 4688 父进程 wsmprovhost.exe / WmiPrvSE.exe |
| **PtH（哈希传递）** | 4624(Type=3) + LogonProcess=NtLmSsp + AuthPackage=NTLM + 来源主机异常 |
| **Kerberoasting** | 4769 海量 + EncryptionType=0x17(RC4) + 服务账户多 |
| **DCSync** | 4662 + Properties 含 `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| **凭证 dump（mimikatz）** | Sysmon 10 GrantedAccess=0x1010/0x1410 targeting lsass.exe |
| **日志清空** | 1102 / 104 |
| **新增持久化** | 4698 / 4720 / 4732 / 7045 |

---

## 六、导出与解析提示

```powershell
# 导出 Security 最近 7 天
wevtutil epl Security C:\export\Security.evtx /q:"*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]"

# CSV（适合给 Skill 解析）
Get-WinEvent -LogName Security -MaxEvents 10000 | Export-Csv -NoTypeInformation security.csv
```

第三方建议：`chainsaw`、`hayabusa`、`evtx_dump` —— 输出 jsonl 后用 jq 抽字段。
