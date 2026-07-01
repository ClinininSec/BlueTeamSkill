# Windows 主机应急排查清单

> 一张表跑完一台 Windows 主机的“是否被入侵”。蓝队照单跑 PowerShell 命令，逐项核对输出。
> **何时使用**：ir 模式收到 `windows_quick_check.ps1` 采集包后逐项核查；audit 模式快速例行健康检查也适用。

约定：所有命令默认在客户机本地由客户跑，回传输出。本 Skill 不远连客户主机。**如遇 EDR 拦截，用 `windows_quick_check.ps1 -DryRun` 拿到全部命令交给驻场蓝队手工执行**。

> 每项格式：**命令** / **关注点** / **常见误报** / **关联 IOC 类型** / **CHECK-WIN-X.Y 触发条件**

---

## 1. 基础信息

### 检查项 1.1: 主机标识与补丁级
- **命令**：`Get-ComputerInfo -Property OsName,OsVersion,OsBuildNumber,CsDomain,CsDomainRole,BiosSMBIOSBIOSVersion`
- **关注点**：build 号是否低于安全基线（如仍在 1809 / 20H2 且缺 KB）；DomainRole=4/5（DC）→ 提高审计门槛
- **常见误报**：长期未升级但未失陷的存量服务器
- **关联 IOC 类型**：host metadata
- **CHECK-WIN-1.1 触发条件**：build 号有已知未修 LPE（如 PrintNightmare / SeriousSAM 等） → P2

### 检查项 1.2: 时间与时区
- **命令**：`Get-Date; w32tm /query /status`
- **关注点**：主机时间与 CMDB 是否偏差 > 5min；时区异常（如客户机为北京时间但显示 UTC）
- **常见误报**：新装机未同步 NTP
- **关联 IOC 类型**：host metadata
- **CHECK-WIN-1.2 触发条件**：时间偏差 > 30 min 或 NTP 源被改为公网未知服务器 → P3

### 检查项 1.3: 最近安装的补丁
- **命令**：`Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20`
- **关注点**：最近安装的 KB / 时间线；InstalledBy = 陌生账户
- **常见误报**：例行 WSUS 推送
- **关联 IOC 类型**：patch / actor
- **CHECK-WIN-1.3 触发条件**：InstalledBy 非运维/域管账户且非 SYSTEM → P3

---

## 2. 账户审计

### 检查项 2.1: 新增本地账户
- **命令**：`Get-LocalUser | Sort-Object PasswordLastSet -Descending | Select-Object Name,Enabled,LastLogon,PasswordLastSet,Description`
- **关注点**：PasswordLastSet 在事件窗口内、Description 为空 / 疑似占位（"admin"、"test"）
- **常见误报**：新到岗员工被合法创建
- **关联 IOC 类型**：user:new
- **CHECK-WIN-2.1 触发条件**：护网期任何新增本地账户 → **P0** (对齐 R-WIN-004)

### 检查项 2.2: 隐藏账户（`$` 结尾）
- **命令**：`Get-LocalUser | Where-Object { $_.Name -like '*$' }; Get-CimInstance Win32_UserAccount | Where-Object { $_.Name -like '*$' -and $_.LocalAccount } | Select-Object Name,SID,Disabled`
- **关注点**：Windows 用户名以 `$` 结尾在 `net user` 中不显示，但仍可登录 —— 典型后门；正常只有计算机账户（域机器）与部分服务账户带 `$`
- **常见误报**：域计算机账户 (COMPUTERNAME$)
- **关联 IOC 类型**：user:backdoor
- **CHECK-WIN-2.2 触发条件**：出现 `<name>$` 但 name 非当前主机名、非已知服务账户 → **P0**

### 检查项 2.3: RID hijack 检测
- **命令**：`Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Select-Object Name,SID,Disabled`
- **关注点**：Administrator 的 RID 应为 500 (SID 末段 = 500)；如有多个账户 RID = 500，或 RID = 500 被映射到非 Administrator 的账户 → RID Hijack
- **常见误报**：极少（合法场景几乎不存在）
- **关联 IOC 类型**：user:backdoor / persistence
- **CHECK-WIN-2.3 触发条件**：SID 末段 = 500 的账户 name != Administrator → **P0**

### 检查项 2.4: Guest / DefaultAccount 启用
- **命令**：`Get-LocalUser -Name 'Guest','DefaultAccount' -ErrorAction SilentlyContinue | Select-Object Name,Enabled,LastLogon`
- **关注点**：Guest.Enabled=True 且 LastLogon 在事件窗口内 → 后门利用
- **常见误报**：老服务器业务需要 Guest 匿名共享（罕见）
- **关联 IOC 类型**：user:backdoor
- **CHECK-WIN-2.4 触发条件**：Guest 启用 → P1；且 LastLogon 在事件窗口内 → **P0**

### 检查项 2.5: Administrators 组成员
- **命令**：`Get-LocalGroupMember -Group 'Administrators'`
- **关注点**：非域管 / 非运维账户列于此；域机器上出现陌生域账户；出现 `<hostname>\<random_string>`
- **常见误报**：DBA / CI-CD 账户合法在组内
- **关联 IOC 类型**：user:privesc
- **CHECK-WIN-2.5 触发条件**：新增成员且加入时间 = 事件窗口 → **P0** (对齐 R-WIN-005)

---

## 3. 登录历史

### 检查项 3.1: 4624 成功登录（近 7 天）
- **命令**：`Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 5000 | Group-Object {$_.Properties[5].Value} | Sort-Object Count -Descending | Select-Object -First 30 Name,Count`
- **关注点**：陌生账户成功登录、非工作时间登录、来自公网 IP（LogonType=3/10）、深夜运维 IP 之外
- **常见误报**：域内正常横向服务账户
- **关联 IOC 类型**：user / ip
- **CHECK-WIN-3.1 触发条件**：LogonType=10 (RDP) 来源 IP 归属公网 / 非域内段 → **P1** (对齐 R-WIN-003)

### 检查项 3.2: 4625 失败登录（暴破）
- **命令**：`Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 5000 | Group-Object {$_.Properties[19].Value} | Sort-Object Count -Descending | Select-Object -First 30 Name,Count`
- **关注点**：单 IP 短时间失败 ≥ 20 → 暴破 (R-WIN-001)；密码喷洒（多账户单 IP）
- **常见误报**：监控探针错口令
- **关联 IOC 类型**：ip:bruteforce
- **CHECK-WIN-3.2 触发条件**：单 IP 60s ≥ 20 → **P2**；紧接着 4624 成功 → **P0** (R-WIN-002)

### 检查项 3.3: 4634 登出 / 4647 主动登出关联
- **命令**：`Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4634,4647; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 2000 | Select-Object TimeCreated,Id,@{n='LogonId';e={$_.Properties[3].Value}} | Format-Table`
- **关注点**：仅登录没登出（可能被强杀 / 反取证）；登出前有异常特权命令
- **常见误报**：断电 / OS crash
- **关联 IOC 类型**：session:anomaly
- **CHECK-WIN-3.3 触发条件**：4624 成功但从未 4634 且 5min 内出现 1102 → **P0**

### 检查项 3.4: 4672 特权登录
- **命令**：`Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 2000 | Group-Object {$_.Properties[1].Value} | Sort-Object Count -Descending | Select-Object -First 20 Name,Count`
- **关注点**：非域管 / 非本地管理员账户获得特权 → 疑似令牌盗用 / UAC bypass
- **常见误报**：服务账户合法获得特权 (SYSTEM / LocalService / NetworkService 白名单)
- **关联 IOC 类型**：user:privesc
- **CHECK-WIN-3.4 触发条件**：非白名单账户 4672 → **P2** (对齐 R-WIN-006)

---

## 4. 进程审计

### 检查项 4.1: 可疑路径运行的进程
- **命令**：`Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -match 'C:\\Users\\|C:\\Windows\\Temp|C:\\ProgramData\\|C:\\Temp' } | Select-Object ProcessId,Name,ExecutablePath,CommandLine | Format-List`
- **关注点**：`ExecutablePath` 落在 Users\*\AppData\Local\Temp / ProgramData / C:\Temp / Windows\Temp —— 落马常用区
- **常见误报**：一些绿色软件；某些安装包在安装完成前处于 Temp
- **关联 IOC 类型**：process / path
- **CHECK-WIN-4.1 触发条件**：可疑路径 + 无有效签名 → **P1**

### 检查项 4.2: 未签名 / 无效签名的运行进程
- **命令**：`Get-Process | ForEach-Object { $p = $_; try { $s = Get-AuthenticodeSignature -FilePath $p.Path -ErrorAction SilentlyContinue; if ($s -and $s.Status -ne 'Valid') { [PSCustomObject]@{ Pid=$p.Id; Name=$p.ProcessName; Path=$p.Path; Sig=$s.Status; Signer=$s.SignerCertificate.Subject } } } catch {} }`
- **关注点**：`Status` 为 NotSigned / HashMismatch / NotTrusted；关注路径落在 Users / Temp / ProgramData
- **常见误报**：一些内部工具与开源二进制未签名
- **关联 IOC 类型**：process:unsigned
- **CHECK-WIN-4.2 触发条件**：`NotSigned + 可疑路径 + 命令行含 base64 / -enc / IEX` → **P1**

### 检查项 4.3: 父子进程异常（Office / Web / LOLBIN 组合）
- **命令**：`Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ForEach-Object { $p = $_; $pp = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction SilentlyContinue; [PSCustomObject]@{Child=$p.Name; Parent=$pp.Name; CmdLine=$p.CommandLine} }`
- **关注点**：Office (winword/excel/outlook) → cmd/powershell/wscript / mshta；w3wp/nginx → cmd/powershell (webshell RCE)；services.exe → 非系统 exe
- **常见误报**：Office 加载项启动 cmd.exe（少见但合法）
- **关联 IOC 类型**：process:parent-anomaly / webshell
- **CHECK-WIN-4.3 触发条件**：MACRO 父 → SHELL 子 → **P0** (R-WIN-010)；WEB 父 → SHELL 子 → **P0** (R-WIN-011)

### 检查项 4.4: 命令行含编码 / 敏感字符串
- **命令**：`Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match '(?i)(-enc(odedcommand)?|FromBase64String|IEX|Invoke-Expression|DownloadString|Net\.WebClient|certutil.*urlcache|bitsadmin.*transfer|mshta.*http)' } | Select-Object ProcessId,Name,CommandLine`
- **关注点**：编码执行 / cradle / LOLBIN 组合
- **常见误报**：极少数运维脚本；正版软件更新
- **关联 IOC 类型**：process:encoded / cradle
- **CHECK-WIN-4.4 触发条件**：命中 → **P1**（结合 4104 全脚本内容判定 P0）

### 检查项 4.5: lsass.exe 异常访问（需 Sysmon 或 EDR）
- **命令**：`Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'lsass\.exe' } | Select-Object TimeCreated,Message`
- **关注点**：SourceImage 非 svchost/services/lsass 白名单；GrantedAccess 掩码 = 0x1010 / 0x1410 / 0x143a
- **常见误报**：EDR 自身、某些 AV 引擎
- **关联 IOC 类型**：credential-access
- **CHECK-WIN-4.5 触发条件**：非白名单 SourceImage 访问 lsass → **P0** (R-WIN-020)

---

## 5. 网络连接

### 检查项 5.1: 监听非业务端口
- **命令**：`Get-NetTCPConnection -State Listen | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [PSCustomObject]@{ LocalPort=$_.LocalPort; Pid=$_.OwningProcess; Process=$p.ProcessName; Path=$p.Path } } | Sort-Object LocalPort`
- **关注点**：4444 / 1337 / 8888 / 31337 / 7777 / 5555 / 9999 / 6666 (Cobalt / MSF 常用) 监听；非业务进程监听 3389
- **常见误报**：管理员临时映射端口
- **关联 IOC 类型**：ip / port
- **CHECK-WIN-5.1 触发条件**：非业务进程监听已知恶意端口 → **P1**

### 检查项 5.2: 出站到公网陌生地址
- **命令**：`Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80)' } | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [PSCustomObject]@{ RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort; Pid=$_.OwningProcess; Process=$p.ProcessName } }`
- **关注点**：出站到 43 / 22 / 6379 等异常业务组合；出站到威胁情报库标注的 IP
- **常见误报**：合法业务出网 (CDN / DNS-over-HTTPS)
- **关联 IOC 类型**：ip:c2
- **CHECK-WIN-5.2 触发条件**：cmd/powershell/rundll32/mshta 出站到公网 → **P1**

### 检查项 5.3: 系统进程异常出网
- **命令**：`Get-NetTCPConnection -State Established | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p.ProcessName -match '^(cmd|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript)$') { [PSCustomObject]@{ Process=$p.ProcessName; RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort } } }`
- **关注点**：解释器 / LOLBIN 出网基本 = 反连
- **常见误报**：极少
- **关联 IOC 类型**：ip:c2 / rce
- **CHECK-WIN-5.3 触发条件**：命中 → **P0**

### 检查项 5.4: 大量出向 SMB (445)
- **命令**：`Get-NetTCPConnection -RemotePort 445 -State Established | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 20 Name,Count`
- **关注点**：单主机短时间向 ≥ 20 个内网主机 445 → 横向探测；Passex / SMBExec / PsExec 特征
- **常见误报**：合法的文件服务器 / 集群同步
- **关联 IOC 类型**：lateral
- **CHECK-WIN-5.4 触发条件**：非文件服务器角色主机出向 SMB 目标 ≥ 20 → **P1**

---

## 6. 文件系统

### 检查项 6.1: Users 目录下的可执行落地
- **命令**：`Get-ChildItem 'C:\Users' -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.hta -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-7) } | Select-Object LastWriteTime,FullName | Sort-Object LastWriteTime -Descending`
- **关注点**：AppData\Local\Temp / Downloads / Desktop 下的可疑落地；无有效签名
- **常见误报**：浏览器下载合法文件；软件自动更新
- **关联 IOC 类型**：path / file
- **CHECK-WIN-6.1 触发条件**：LastWriteTime 命中事件窗口 + 未签名 → **P1**

### 检查项 6.2: ProgramData / C:\Temp 下的落地
- **命令**：`Get-ChildItem 'C:\ProgramData','C:\Temp','C:\Windows\Temp','C:\Windows\Tasks' -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.hta -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-7) } | Sort-Object LastWriteTime -Descending`
- **关注点**：ProgramData 是标准落马路径（无 AV 白名单敏感度）；C:\Windows\Temp 二进制
- **常见误报**：软件安装临时文件（多数会自清理）
- **关联 IOC 类型**：path / file
- **CHECK-WIN-6.2 触发条件**：文件仍存在 + 无签名 + 落地时间在事件窗口 → **P1**

### 检查项 6.3: Prefetch 分析（执行历史）
- **命令**：`Get-ChildItem 'C:\Windows\Prefetch\*.pf' | Sort-Object LastWriteTime -Descending | Select-Object -First 50 Name,LastWriteTime`
- **关注点**：文件名 `XXX.EXE-<hash>.pf` 揭示曾运行过什么 exe；关注非业务软件的 Prefetch
- **常见误报**：合法软件 Prefetch
- **关联 IOC 类型**：execution-history
- **CHECK-WIN-6.3 触发条件**：`.pf` 名字对应可疑工具 (mimikatz / rubeus / procdump / psexec / adfind) → **P0**

### 检查项 6.4: Alternate Data Stream (ADS)
- **命令**：`Get-Item -Path 'C:\Users\*\AppData\Local\Temp\*' -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } | Select-Object PSPath,Stream,Length`
- **关注点**：非 Zone.Identifier 的备用数据流 —— 攻击者藏 payload 的经典位置
- **常见误报**：Zone.Identifier 是合法的 MOTW 标记
- **关联 IOC 类型**：file:ads
- **CHECK-WIN-6.4 触发条件**：出现非 Zone.Identifier ADS → **P1**

### 检查项 6.5: 系统文件被替换
- **命令**：`Get-FileHash 'C:\Windows\System32\{sethc,utilman,osk,narrator,magnify,DisplaySwitch}.exe' -ErrorAction SilentlyContinue`
- **关注点**：辅助功能程序被替换成 cmd.exe (粘滞键后门经典手法)
- **常见误报**：极少
- **关联 IOC 类型**：persistence:accessibility
- **CHECK-WIN-6.5 触发条件**：哈希与官方基线不符 → **P0**

---

## 7. 持久化 - Registry Run keys

### 检查项 7.1: HKLM Run / RunOnce / RunOnceEx
- **命令**：`'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run' | ForEach-Object { if (Test-Path $_) { "== $_ =="; Get-ItemProperty $_ | Select-Object * -ExcludeProperty PS* } }`
- **关注点**：新增 value 名（非软件名）；value data 含 base64 / -enc / 可疑路径
- **常见误报**：合法软件安装
- **关联 IOC 类型**：persistence:run
- **CHECK-WIN-7.1 触发条件**：value data 落在 Users/Temp/ProgramData 或含 powershell -enc → **P1** (对齐 SIG-WIN-001)

### 检查项 7.2: HKCU Run（当前用户）
- **命令**：`Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue`
- **关注点**：无需管理员权限即可写入 → 攻击者偏爱；名字看起来像正常软件但 path 可疑
- **常见误报**：Chrome / Steam / Skype 等
- **关联 IOC 类型**：persistence:run
- **CHECK-WIN-7.2 触发条件**：value data 未签名或路径可疑 → **P1** (SIG-WIN-005)

### 检查项 7.3: BootExecute / Session Manager
- **命令**：`Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute,PendingFileRenameOperations,SetupExecute -ErrorAction SilentlyContinue`
- **关注点**：BootExecute 期望仅 `autocheck autochk *`；出现其它二进制 → 高危
- **常见误报**：极少
- **关联 IOC 类型**：persistence:boot
- **CHECK-WIN-7.3 触发条件**：BootExecute 含额外条目 → **P0** (SIG-WIN-034)

---

## 8. 持久化 - Services

### 检查项 8.1: 新增服务
- **命令**：`Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message | Format-List`
- **关注点**：ServiceName / ImagePath 含 cmd/powershell/rundll32；ImagePath 含 base64；ServiceType = user mode + StartType = auto
- **常见误报**：软件安装注册服务
- **关联 IOC 类型**：persistence:service
- **CHECK-WIN-8.1 触发条件**：ImagePath 含 shell 或编码 → **P1** (R-WIN-009, SIG-WIN-009/012)

### 检查项 8.2: 服务 PathName 异常
- **命令**：`Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'cmd\.exe|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript' -or $_.PathName -match 'C:\\Users\\|C:\\ProgramData\\|C:\\Temp\\|C:\\Windows\\Temp' } | Select-Object Name,DisplayName,State,StartName,PathName | Format-List`
- **关注点**：PathName 落在非 Program Files；PathName 使用 UNC (`\\host\share\..`)；PathName 引号包裹缺陷 (未加引号的空格路径)
- **常见误报**：极少数管理工具
- **关联 IOC 类型**：persistence:service
- **CHECK-WIN-8.2 触发条件**：命中 → **P1** (SIG-WIN-009/010/048)

### 检查项 8.3: 未签名服务二进制
- **命令**：`Get-CimInstance Win32_Service | ForEach-Object { $path = ($_.PathName -replace '^"([^"]+)".*','$1') -replace '^(\S+).*','$1'; if ($path -and (Test-Path $path)) { $s = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue; if ($s.Status -ne 'Valid') { [PSCustomObject]@{ Name=$_.Name; Path=$path; SigStatus=$s.Status } } } }`
- **关注点**：Status = NotSigned / HashMismatch；Signer 是异常/自签名主体
- **常见误报**：一些内部脚本/工具
- **关联 IOC 类型**：persistence:service
- **CHECK-WIN-8.3 触发条件**：未签名 + State=Running + StartName=SYSTEM → **P1**

---

## 9. 持久化 - Scheduled Tasks

### 检查项 9.1: 非 Microsoft 作者的任务
- **命令**：`Get-ScheduledTask | Where-Object { $_.Author -and $_.Author -notmatch 'Microsoft' -and $_.Author -notmatch 'Windows' } | Select-Object TaskPath,TaskName,Author,State`
- **关注点**：Author 为空 / 陌生字符串 / DOMAIN\ 攻击者账户；TaskPath = `\` (根路径无子目录 = 攻击者常用)
- **常见误报**：第三方软件计划任务（Chrome / Adobe / OneDrive 均非 Microsoft Author）
- **关联 IOC 类型**：persistence:task
- **CHECK-WIN-9.1 触发条件**：Author 陌生 + Action 含 shell/编码 → **P1** (R-WIN-008)

### 检查项 9.2: RunAs SYSTEM 且 Action 含 shell
- **命令**：`Get-ScheduledTask | ForEach-Object { $x = Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue; if ($x -match 'S-1-5-18|SYSTEM' -and $x -match 'cmd\.exe|powershell|rundll32|regsvr32|mshta') { [PSCustomObject]@{ Path=$_.TaskPath; Name=$_.TaskName; State=$_.State } } }`
- **关注点**：SYSTEM 权限 + shell 执行 = 高价值持久化
- **常见误报**：合法运维任务（结合 Author 判定）
- **关联 IOC 类型**：persistence:task
- **CHECK-WIN-9.2 触发条件**：命中 → **P0** (SIG-WIN-015)

### 检查项 9.3: 高频触发任务（beacon）
- **命令**：`Get-ScheduledTask | ForEach-Object { $x = Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue; if ($x -match '<Interval>PT[1-5]M</Interval>' -or $x -match '<Interval>PT[0-9]{1,2}S</Interval>') { [PSCustomObject]@{ Path=$_.TaskPath; Name=$_.TaskName } } }`
- **关注点**：Trigger repetition < 5min → beacon 持久化
- **常见误报**：一些监控工具
- **关联 IOC 类型**：persistence:task:beacon
- **CHECK-WIN-9.3 触发条件**：≤ 5min 触发 + Author 陌生 → **P1** (SIG-WIN-016)

---

## 10. 持久化 - WMI Subscriptions

### 检查项 10.1: EventFilter / EventConsumer 三元组
- **命令**：`Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue; Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue; Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue`
- **关注点**：非 SCCM/OpsMgr 的 EventFilter；CommandLineTemplate 含 powershell / cmd；ActiveScriptEventConsumer 含 inline VBScript/JScript
- **常见误报**：SCCM / OpsMgr / Nagios agent
- **关联 IOC 类型**：persistence:wmi
- **CHECK-WIN-10.1 触发条件**：出现非白名单三元组 → **P0** (R-WIN-022, SIG-WIN-017/018/019)

### 检查项 10.2: 非标准命名空间 (`root\default` 等)
- **命令**：`Get-CimInstance -Namespace 'root\default' -ClassName '__EventFilter' -ErrorAction SilentlyContinue`
- **关注点**：EventFilter 在 root\default / root\aspnet 等非 root\subscription 命名空间 → 刻意规避扫描
- **常见误报**：极少
- **关联 IOC 类型**：persistence:wmi:evasive
- **CHECK-WIN-10.2 触发条件**：任何命中 → **P0** (SIG-WIN-020)

---

## 11. 持久化 - AppInit_DLLs / IFEO / COM 劫持

### 检查项 11.1: AppInit_DLLs / AppCertDlls
- **命令**：`Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs,LoadAppInit_DLLs -ErrorAction SilentlyContinue; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue`
- **关注点**：AppInit_DLLs 非空且 LoadAppInit_DLLs=1；AppCertDlls 任何 value = 高危
- **常见误报**：极少（Win8+ 默认关闭 AppInit）
- **关联 IOC 类型**：persistence:appinit
- **CHECK-WIN-11.1 触发条件**：AppInit_DLLs 非空 或 AppCertDlls 有条目 → **P0** (SIG-WIN-026/027)

### 检查项 11.2: IFEO Debugger 劫持
- **命令**：`Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object { $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue; if ($props.Debugger -or $props.GlobalFlag) { [PSCustomObject]@{ Key=$_.PSChildName; Debugger=$props.Debugger; GlobalFlag=$props.GlobalFlag } } }`
- **关注点**：Debugger 设置在 sethc/utilman/notepad/mspaint 等常用 exe；GlobalFlag=0x200 → Silent Process Exit hook
- **常见误报**：一些调试工具会临时设 Debugger
- **关联 IOC 类型**：persistence:ifeo
- **CHECK-WIN-11.2 触发条件**：Debugger 指向 cmd/powershell/自定义 exe → **P0** (SIG-WIN-024/025)

### 检查项 11.3: COM 劫持 (HKCU\Software\Classes\CLSID)
- **命令**：`Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object { $inproc = Join-Path $_.PSPath 'InprocServer32'; if (Test-Path $inproc) { [PSCustomObject]@{ CLSID=$_.PSChildName; DLL=(Get-ItemProperty $inproc -ErrorAction SilentlyContinue).'(default)' } } }`
- **关注点**：HKCU 优先于 HKCR，攻击者利用此覆盖系统 CLSID；DLL 路径在 Users\* / Temp\*
- **常见误报**：Chrome / Office 某些组件合法写 HKCU\Classes
- **关联 IOC 类型**：persistence:com
- **CHECK-WIN-11.3 触发条件**：DLL 未签名且路径可疑 → **P0** (SIG-WIN-021/022)

---

## 12. 持久化 - Startup Folder

### 检查项 12.1: 全局 Startup 目录
- **命令**：`Get-ChildItem 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp' -Force -ErrorAction SilentlyContinue | Select-Object Name,LastWriteTime,Length`
- **关注点**：新增 .lnk / .exe / .vbs / .bat / .ps1；LNK 目标为 powershell / cmd / rundll32
- **常见误报**：软件安装写入
- **关联 IOC 类型**：persistence:startup
- **CHECK-WIN-12.1 触发条件**：新增文件在事件窗口 + 目标为 shell → **P1** (SIG-WIN-030/032)

### 检查项 12.2: 每用户 Startup 目录
- **命令**：`Get-ChildItem 'C:\Users' -Directory | ForEach-Object { $p = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'; if (Test-Path $p) { Get-ChildItem $p -Force } }`
- **关注点**：无需管理员权限；攻击者偏爱；关注最近修改时间
- **常见误报**：个别软件在此写入
- **关联 IOC 类型**：persistence:startup
- **CHECK-WIN-12.2 触发条件**：新增文件在事件窗口 → **P1** (SIG-WIN-031)

---

## 13. PowerShell 与 Sysmon

### 检查项 13.1: PSReadLine 历史
- **命令**：`Get-ChildItem 'C:\Users' -Directory | ForEach-Object { $p = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'; if (Test-Path $p) { "== $($_.Name) =="; Get-Content -Tail 200 $p } }`
- **关注点**：mimikatz / rubeus / adfind / net user / net group / whoami /all；下载 cradle；Invoke-Mimikatz / Invoke-Kerberoast 等 PS 攻击命令
- **常见误报**：合法运维脚本
- **关联 IOC 类型**：process:cmd
- **CHECK-WIN-13.1 触发条件**：出现攻击关键字 → **P1**

### 检查项 13.2: 4104 script-block（编码 / cradle / AMSI bypass）
- **命令**：`Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 1000 | Where-Object { $_.Message -match '(?i)FromBase64String|IEX|Invoke-Expression|Net\.WebClient|DownloadString|AmsiUtils|amsiInitFailed|Reflection\.Assembly' } | Select-Object TimeCreated,@{n='Script';e={$_.Message.Substring(0,[Math]::Min($_.Message.Length,600))}}`
- **关注点**：base64 + IEX = 编码执行；AMSI bypass；反射加载 .NET assembly
- **常见误报**：极少
- **关联 IOC 类型**：rce:encoded
- **CHECK-WIN-13.2 触发条件**：命中 → **P0/P1** (R-WIN-017/018/019)

### 检查项 13.3: Sysmon 配置是否被篡改
- **命令**：`Get-Service Sysmon,SysmonDrv -ErrorAction SilentlyContinue | Select-Object Name,Status; Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=16} -MaxEvents 20 -ErrorAction SilentlyContinue`
- **关注点**：Sysmon 服务被停 → 攻击者规避；Event 16 = 配置更改
- **常见误报**：运维正常更新 config
- **关联 IOC 类型**：evasion
- **CHECK-WIN-13.3 触发条件**：Event 16 在事件窗口 且 变更者非运维账户 → **P0**

---

## 14. Rootkit / Kernel

### 检查项 14.1: 未签名驱动
- **命令**：`Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | ForEach-Object { $path = $_.PathName -replace '\\??\\',''; if ($path -and (Test-Path $path)) { $s = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue; if ($s -and $s.Status -ne 'Valid') { [PSCustomObject]@{ Name=$_.Name; Path=$path; SigStatus=$s.Status } } } }`
- **关注点**：Running 状态 + 未签名 → 强 rootkit 信号；关注 Signer 是否是攻击者自签
- **常见误报**：极少（Win10+ 强制签名）
- **关联 IOC 类型**：rootkit
- **CHECK-WIN-14.1 触发条件**：未签名 running 驱动 → **P0**

### 检查项 14.2: 隐藏进程 / 内核对象
- **命令**：`Get-Process | Sort-Object Id; Get-CimInstance Win32_Process | Sort-Object ProcessId` (对比两个列表)
- **关注点**：`Get-Process` 与 `Win32_Process` 不一致 → 进程隐藏；Handle 数异常高的 lsass；PID 不连续跳变
- **常见误报**：极短生命周期进程
- **关联 IOC 类型**：rootkit
- **CHECK-WIN-14.2 触发条件**：两个列表差异 > 3 且非瞬时进程 → **P1**

### 检查项 14.3: MBR / VBR 篡改（磁盘引导）
- **命令**：`Get-Disk | Select-Object Number,FriendlyName,PartitionStyle; # MBR 完整性需要离线工具（如 chainsaw / bootrec）验证`
- **关注点**：PartitionStyle 从 GPT 变为 MBR（异常）；出现未知磁盘签名；使用 `bootrec /scanos` 检出异常 OS 引导
- **常见误报**：极少
- **关联 IOC 类型**：rootkit:bootkit
- **CHECK-WIN-14.3 触发条件**：需专用工具确认；如有异常 → **P0**

---

## 附录: 常用 rule_id / SIG-WIN 映射

- **R-WIN-XXX**：由 `scripts/evtx_hunt.py` 自动 emit（离线 evtx 解析）
- **CHECK-WIN-X.Y**：本清单人工核查项（由蓝队照单跑）
- **SIG-WIN-XXX**：`data/windows-persistence-patterns.json` 里的持久化特征
- **SIG-SYSMON-XXX**：`data/sysmon-detection-rules.json` 里的 Sysmon 事件规则

三者互为补充：evtx_hunt.py 走机器判定，本清单走人工核查，data/*.json 走 SIEM / EDR 侧规则订阅。

## 红线（复述）

- 只读命令；本清单**不给出任何删除 / 修改 / 断服务的操作**
- 输出前必须过 `scripts/desensitize.py` 脱敏（IP / 用户名 / 域名 / 路径）
- 不出 PoC / 不动客户主机文件（即使疑似落马也只给路径与哈希）
- 不通过 SSH/WinRM 远连客户主机；命令由客户或驻场蓝队本地跑
