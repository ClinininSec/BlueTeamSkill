# Windows Sysmon EventID 字段速查

> Sysmon (System Monitor) 是 Sysinternals 的免费高价值遥测组件，配置合理时可覆盖进程创建、网络、DLL 加载、注册表、命名管道、WMI 等关键攻击面。
> **何时使用**：ir / audit 模式；`windows_quick_check.ps1` 已导出 `Microsoft-Windows-Sysmon/Operational`，本速查用于 `evtx_hunt.py` 命中 R-WIN-020/021/022 及 SIG-SYSMON-* 后的字段判读。
> **前提**：假设主机已部署 Sysmon（推荐 SwiftOnSecurity 或 Olaf Hartong 的社区 config）。未部署时 4104 / 4688 / 7045 仍可提供部分覆盖但精度较低。

---

## Event 1: Process Create（进程创建）

- **关键字段**：`Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `LogonId`, `IntegrityLevel`, `Hashes` (MD5/SHA1/SHA256/IMPHASH), `ProcessId`, `ParentProcessId`, `CurrentDirectory`, `OriginalFileName`
- **常见调优**：过滤 svchost.exe / MsMpEng.exe / Sysinternals sysmon.exe / 编译过程的 conhost.exe 噪声
- **检测机会**：cradle 命令 (`FromBase64String`, `IEX`)；whoami / net user / ipconfig / nltest recon；命令行 base64；powershell -enc / -w hidden；LOLBIN (certutil / bitsadmin / mshta / regsvr32 / rundll32) 与远程 URL 共现
- **关联 rule_id**：R-WIN-010, R-WIN-011, R-WIN-017（配合 4104），SIG-SYSMON-001..019

## Event 2: File Creation Time Changed（时间戳篡改）

- **关键字段**：`Image`, `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime`
- **常见调优**：合法的备份 / 同步工具会大量触发（如 rsync、robocopy）
- **检测机会**：timestomping —— 攻击者把落地文件的 mtime 改到过去；PreviousCreationUtcTime > CreationUtcTime 是强信号
- **关联 rule_id**：无 R-WIN-* 直接映射（人工侧关注），关联 CHECK-WIN-6.1

## Event 3: Network Connection（网络连接建立）

- **关键字段**：`Image`, `ProcessId`, `User`, `Protocol`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, `DestinationHostname`, `Initiated`
- **常见调优**：过滤 svchost.exe (DNS/DHCP)、chrome / edge / firefox 大量正常连接
- **检测机会**：解释器 (powershell / cmd / rundll32 / mshta / wscript / cscript) 出网；出向到已知恶意端口 (4444/1337/8888/31337) 或异常 TLD (.top / .xyz / .tk)；DNS-over-HTTPS 到非白名单
- **关联 rule_id**：SIG-SYSMON-020, SIG-SYSMON-021

## Event 5: Process Terminate（进程退出）

- **关键字段**：`Image`, `ProcessId`, `UtcTime`
- **常见调优**：正常场景大量触发；仅在关联链条中使用
- **检测机会**：与 Event 1 配对做进程存活时长分析；短生命周期 (< 1s) 的 powershell / cmd 可能是一次性执行 payload
- **关联 rule_id**：无直接映射（人工侧关联）

## Event 7: Image Loaded（DLL 加载）

- **关键字段**：`Image` (加载主体), `ImageLoaded` (被加载的 DLL), `Signed`, `Signature`, `SignatureStatus`, `Hashes`
- **常见调优**：Sysmon 默认不 log Event 7；启用后噪声极大，需要精细过滤
- **检测机会**：DLL 侧加载（`Image` 是合法签名 exe 但 `ImageLoaded` 是可疑 DLL 且路径异常）；未签名 DLL 加载到 lsass / winlogon / services；phantom DLL (从 cwd 加载未签名 DLL)
- **关联 rule_id**：SIG-SYSMON-022, SIG-SYSMON-023, SIG-WIN-028/029/043

## Event 8: CreateRemoteThread（远程线程注入）

- **关键字段**：`SourceImage`, `SourceProcessId`, `TargetImage`, `TargetProcessId`, `NewThreadId`, `StartAddress`
- **常见调优**：Chrome/Edge 内部大量合法注入；应白名单浏览器进程
- **检测机会**：SourceImage 是 powershell / rundll32 / regsvr32 / mshta → 强注入信号；TargetImage 是 lsass / explorer / winlogon 且 Source 非系统 = P0
- **关联 rule_id**：SIG-SYSMON-024

## Event 10: Process Access（进程访问，含 LSASS）

- **关键字段**：`SourceImage`, `SourceProcessId`, `TargetImage`, `TargetProcessId`, `GrantedAccess`, `CallTrace`
- **常见调优**：EDR / AV 会大量访问 lsass，需按签名白名单
- **检测机会**：TargetImage = lsass.exe 且 SourceImage 非白名单 → 凭据窃取 (mimikatz / procdump / comsvcs.dll)；GrantedAccess 掩码 0x1010 / 0x1410 / 0x143a 是 dump 能力标志；CallTrace 含 dbgcore.dll / dbghelp.dll 强信号
- **关联 rule_id**：R-WIN-020, SIG-SYSMON-025, SIG-SYSMON-026

## Event 11: File Create（文件创建）

- **关键字段**：`Image`, `TargetFilename`, `CreationUtcTime`, `User`
- **常见调优**：浏览器 / 编译器噪声大；应过滤
- **检测机会**：TargetFilename 在 Startup / AppData\Local\Temp / ProgramData 且后缀 .exe/.dll/.ps1/.bat/.vbs/.hta；System32 / SysWOW64 下由非 MSI 进程写入的 .exe/.dll
- **关联 rule_id**：R-WIN-021, SIG-SYSMON-027, SIG-SYSMON-028, SIG-SYSMON-029, SIG-WIN-030/031

## Event 12: Registry Object Create/Delete（键创建 / 删除）

- **关键字段**：`EventType` (CreateKey / DeleteKey), `TargetObject`, `Image`
- **常见调优**：Windows Update / 软件安装大量触发
- **检测机会**：Run keys / IFEO / Winlogon / Session Manager\BootExecute 下的 CreateKey；Task Scheduler 下的 CreateKey（补充 4698）
- **关联 rule_id**：SIG-SYSMON-030

## Event 13: Registry Value Set（键值写入）

- **关键字段**：`EventType` (SetValue), `TargetObject`, `Details`, `Image`
- **常见调优**：软件配置大量触发
- **检测机会**：`\Run\`, `\RunOnce\`, `Winlogon\Shell`, `Winlogon\Userinit`, `Image File Execution Options\<exe>\Debugger`, `Session Manager\BootExecute`, `Services\<svc>\ImagePath` 的 SetValue；Details 含 base64 / -enc / 可疑路径
- **关联 rule_id**：SIG-SYSMON-031, SIG-SYSMON-032, SIG-WIN-024/025

## Event 15: File Create Stream Hash（ADS 落地）

- **关键字段**：`Image`, `TargetFilename`, `Hash`, `Contents` (仅 Zone.Identifier)
- **常见调优**：Zone.Identifier 是标准 MOTW 机制，需过滤
- **检测机会**：非 Zone.Identifier 的 stream —— 攻击者藏 payload 的经典手法（如 `file.exe:evil.dll`）
- **关联 rule_id**：SIG-SYSMON-033

## Event 17: PipeEvent (Pipe Created)（命名管道创建）

- **关键字段**：`EventType` (CreatePipe), `PipeName`, `Image`
- **常见调优**：大量合法管道（RPC / 打印 spool 等）
- **检测机会**：PipeName 匹配已知红队工具指纹（`\mimikatz`, `\paexec`, `\cobaltstrike`, `\msagent`, `\status_[0-9]+`）
- **关联 rule_id**：SIG-SYSMON-034

## Event 18: PipeEvent (Pipe Connected)

- **关键字段**：`PipeName`, `Image`
- **常见调优**：与 17 类似
- **检测机会**：追踪进程如何跨会话通过管道通信 —— 结合 SharpHound / Rubeus 等工具
- **关联 rule_id**：无直接映射（关联 SIG-SYSMON-034）

## Event 19: WmiEvent (WmiEventFilter activity)

- **关键字段**：`Operation` (Created / Modified / Deleted), `User`, `EventNamespace`, `Name`, `Query`
- **常见调优**：SCCM / OpsMgr 使用 WMI subs
- **检测机会**：Operation=Created + Query 非白名单模式 → WMI 持久化第一环
- **关联 rule_id**：R-WIN-022, SIG-SYSMON-035, SIG-WIN-017

## Event 20: WmiEvent (WmiEventConsumer activity)

- **关键字段**：`Operation`, `User`, `Name`, `Type`, `Destination` (CommandLineTemplate for CommandLineEventConsumer)
- **常见调优**：SCCM 白名单
- **检测机会**：CommandLineEventConsumer + Destination 含 shell / powershell / cmd → P0；ActiveScriptEventConsumer 含 inline VBS/JScript → P0
- **关联 rule_id**：R-WIN-022, SIG-SYSMON-036, SIG-WIN-018/038

## Event 21: WmiEvent (WmiEventConsumerToFilter activity)

- **关键字段**：`Operation`, `Consumer`, `Filter`
- **常见调优**：SCCM 白名单
- **检测机会**：Operation=Created + Consumer 与 Filter 组合 → 三元组闭环，WMI 持久化就绪
- **关联 rule_id**：R-WIN-022, SIG-SYSMON-037, SIG-WIN-019

## Event 22: DNSEvent (DNS query)

- **关键字段**：`QueryName`, `QueryStatus`, `QueryResults`, `Image`
- **常见调优**：极大量正常 DNS，需重点过滤 chrome/edge/svchost
- **检测机会**：QueryName 匹配 duckdns.org / no-ip.com / ngrok.io / paste.ee / transfer.sh 等 dynamic DNS / paste / tunnel；QueryStatus 大量 NXDOMAIN 且 Image 是 powershell / cmd → DGA C2 探测
- **关联 rule_id**：SIG-SYSMON-038

## Event 23: FileDelete (File Delete archived)

- **关键字段**：`Image`, `TargetFilename`, `Archived`, `Hashes`
- **常见调优**：日志噪声较大，通常仅关注特定路径（Startup / Sched Tasks / System32 driver）
- **检测机会**：攻击者销毁落地文件 = 反取证；关注 evtx 日志文件被删除的场景（补充 1102）
- **关联 rule_id**：无直接映射（人工关联 R-WIN-007）

## Event 25: ProcessTampering (Image Change)

- **关键字段**：`Image`, `Type` (Image is replaced / Process Hollowing / Process Herpaderping)
- **常见调优**：极少误报
- **检测机会**：Type=Image is replaced / Process Hollowing → 极强的进程伪装信号；配合 lsass / winlogon 等目标即 P0
- **关联 rule_id**：无 R-WIN-* 直接映射（属于 P0 兜底信号）

---

## 附录：字段命名细节

- **Sysmon 15.x** 用 `Image` / `TargetImage` / `ParentImage`；`Image` = 主体进程的可执行路径，绝对路径含 `.exe`。
- **Get-WinEvent 导出到 CSV** 时字段会展开成 `Properties[N].Value`，`evtx_hunt.py --csv` 会把 `EventData.*` 或 `Properties[N]` 都折叠进 `data` dict，检测规则里用 field name 即可。
- **Sysmon config 差异**：SwiftOnSecurity vs Olaf Hartong 的过滤规则不同，检测覆盖率也不同。ir 现场先跑一次 `sysmon -c` 打印当前 config，避免误判"没告警 = 没入侵"。
- **CommandLine 字段** 在 4688 与 Sysmon Event 1 都存在；Sysmon 的 CommandLine 更完整（默认启用），4688 需 GPO 打开 "Include command line" 才有。

## 与 evtx_hunt.py 的对接

- `evtx_hunt.py --csv <exp.csv>`: 直接读 `Get-WinEvent | Export-Csv` 输出（推荐路径，无外部依赖）
- `evtx_hunt.py --evtx <file.evtx>`: 需 `pip install python-evtx`，适合分析师后台批量分析
- `--sysmon-data data/sysmon-detection-rules.json`: 加载 38 条 SIG-SYSMON-* 规则做补充匹配

## 典型 Sysmon 攻击链关联样例

### 样例 A：钓鱼落地 + 编码执行 + 反连

1. **Event 11** — `TargetFilename` = `C:\Users\<u>\AppData\Local\Temp\report.docm`，`Image` = outlook.exe → 附件落地
2. **Event 1** — `Image` = winword.exe，`ParentImage` = outlook.exe → 用户打开文档
3. **Event 1** — `Image` = powershell.exe，`ParentImage` = winword.exe，`CommandLine` 含 `-enc <base64>` → 命中 R-WIN-010、SIG-SYSMON-018
4. **Event 3** — `Image` = powershell.exe，`DestinationIp` 出向公网 → 命中 SIG-SYSMON-020/021
5. **Event 10** — `TargetImage` = lsass.exe，`SourceImage` = powershell.exe → 命中 R-WIN-020

### 样例 B：Webshell 命令执行

1. **Event 1** — `Image` = cmd.exe，`ParentImage` = w3wp.exe，`CommandLine` = whoami / net user / ipconfig → 命中 R-WIN-011、SIG-SYSMON-019
2. **Event 11** — `TargetFilename` 落在 IIS wwwroot 且新增 .aspx → 网页 shell 上传痕迹
3. **Event 3** — `Image` = w3wp.exe，`DestinationIp` 出向公网 → 数据外传或反弹 shell

### 样例 C：WMI 持久化三元组

1. **Event 19** — `Operation` = Created，`Name` 陌生 EventFilter → 命中 SIG-SYSMON-035
2. **Event 20** — `Operation` = Created，`Type` = CommandLineEventConsumer，`Destination` 含 powershell → 命中 SIG-SYSMON-036 + SIG-WIN-018
3. **Event 21** — `Operation` = Created，Consumer 与 Filter 组合 → 三元组闭环，命中 SIG-SYSMON-037 + R-WIN-022

## 常见误报白名单模板（现场按需要调整）

| Image / SourceImage | 事件 | 场景 | 应加白 |
|---|---|---|---|
| `MsMpEng.exe` | 10 | Defender 扫 lsass | 是 |
| `SearchIndexer.exe` | 10 | 索引服务访问进程 | 是 |
| `svchost.exe` (rpcss) | 10 | RPC 调用 | 是 |
| `chrome.exe` / `msedge.exe` | 3, 8 | 浏览器正常网络与内部注入 | 是 |
| `ccmexec.exe` | 19/20/21 | SCCM 使用 WMI subs | 是 |
| `MonitoringHost.exe` | 19/20/21 | SCOM/OpsMgr | 是 |
| `RUNDLL32.EXE shell32.dll,Control_RunDLL` | 1 | 控制面板打开 | 是 |
| `python.exe` / `node.exe` | 8 | 部分开发调试 | 视场景 |

## 采集侧对接（windows_quick_check.ps1）

`windows_quick_check.ps1` 的第 14 类"关键 evtx 导出"会调用 `wevtutil epl "Microsoft-Windows-Sysmon/Operational" ...`（未指定 -SkipHeavy 时）。分析师拿到导出后：

```bash
# 若已装 python-evtx
python3.11 evtx_hunt.py --evtx 14-evtx-export/Microsoft-Windows-Sysmon_Operational.evtx \
                     --output findings.jsonl \
                     --sysmon-data ../data/sysmon-detection-rules.json

# 或者驻场机纯 stdlib（客户 Windows 侧先转 CSV）
# powershell> Get-WinEvent -Path 'X.evtx' | Export-Csv X.csv -NoTypeInformation -Encoding UTF8
python3.11 evtx_hunt.py --csv X.csv --output findings.jsonl \
                     --sysmon-data ../data/sysmon-detection-rules.json
```

输出为 JSONL，每行一条 8 字段告警（对齐 SKILL.md 输出契约），可继续送到 `desensitize.py` 脱敏。

## 关键 EventID 与 CHECK-WIN-*.* 交叉参照

| Sysmon Event | 现象 | 对应 CHECK-WIN 项 | 对应 R-WIN 规则 |
|---|---|---|---|
| 1 | 进程创建 | 4.1, 4.2, 4.3, 4.4 | R-WIN-010, R-WIN-011 |
| 3 | 网络连接 | 5.1, 5.2, 5.3 | — |
| 7 | DLL 加载 | 11.1 | — |
| 8 | 远程线程注入 | — | (P0 兜底) |
| 10 | 进程访问 | 4.5 | R-WIN-020 |
| 11 | 文件创建 | 6.1, 6.2, 12.1, 12.2 | R-WIN-021 |
| 12/13 | 注册表 | 7.1, 7.2, 11.1, 11.2 | — (由 Security 4657 + Sysmon 13 联合) |
| 15 | ADS 落地 | 6.4 | — |
| 17/18 | 命名管道 | — | (工具指纹兜底) |
| 19/20/21 | WMI subs | 10.1, 10.2 | R-WIN-022 |
| 22 | DNS 查询 | 5.2 | — |
| 23 | 文件删除 | — | (与 R-WIN-007 关联) |
| 25 | 进程篡改 | — | (P0 兜底) |

## 红线

- 本速查只描述**如何识别**攻击行为，不提供任何 PoC / 复现代码
- 现场分析前先脱敏（IP / 用户名 / 域名 / 路径）
- Sysmon 服务被停 / config 被改 = 攻击行为本身（对应 CHECK-WIN-13.3）
- 若客户未部署 Sysmon，本速查仍可作为 IOC 语义参考；采集侧退回到 Security 4688 / PowerShell 4104 / System 7045，覆盖率会下降但仍能命中大部分 P0 场景

