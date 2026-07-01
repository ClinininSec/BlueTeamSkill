# hvv-defender · 护网蓝队作战 Skill

<p align="center">
  <a href="https://github.com/ClinininSec/BlueTeamSkill"><img alt="version" src="https://img.shields.io/badge/version-v0.4--M0-blue"></a>
  <a href="https://github.com/ClinininSec/BlueTeamSkill/blob/main/LICENSE"><img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-green"></a>
  <img alt="platform" src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20WSL-lightgrey">
  <img alt="python" src="https://img.shields.io/badge/python-3.8%2B-blue">
  <img alt="tshark" src="https://img.shields.io/badge/tshark-required%20for%20traffic-orange">
  <img alt="claude-code" src="https://img.shields.io/badge/Claude%20Code-Skill-purple">
</p>

> 面向**蓝队人员**的 Claude Code Skill — 把 SIEM 分诊、日志审计、pcap 流量分析、应急响应、授权 SSH 远程采集五件事合并成一个「Coding Agent 副驾驶」。
>
> **五模式**（monitor / audit / traffic / ir / remote）· **69 条流量规则** · **22 条 Windows evtx 规则** · **59 条 3-tier 远程命令白名单** · **每条结论必附证据**

---

## 目录

- [是什么 / 为什么](#是什么--为什么)
- [五模式一览](#五模式一览)
- [设计原则](#设计原则)
- [快速开始](#快速开始)
- [使用示例](#使用示例)
- [项目结构](#项目结构)
- [Rule ID 命名分层](#rule-id-命名分层)
- [输出契约](#输出契约)
- [合规与红线](#合规与红线)
- [路线图](#路线图)
- [贡献指南](#贡献指南)
- [License](#license)
- [免责声明](#免责声明)

---

## 是什么 / 为什么

**护网期间蓝队人员的日常工作**可以拆成五类：值守告警分诊、日志审计、流量抓包分析、应急响应取证、远程主机采集。每类都有一套**重复的手工流程 + 一些工具脚本 + 一堆经验规则**，蓝队人员在项目现场往往需要在这五类之间不停切换、记忆规则、复制命令。

**`hvv-defender`** 是一个 **Claude Code Skill**（可以理解为一个「有工具、有剧本、有记忆的 AI 副驾驶」），把这五类工作整合到一个统一的**自然语言接口**下：

- 你说「帮我分诊这批 NGSOC 告警」→ 进 monitor 模式
- 你说「审计 nginx 日志排查 webshell」→ 进 audit 模式
- 你说「分析这个 pcap 里有没有 fscan」→ 进 traffic 模式（跑 69 条规则）
- 你说「这台机器怀疑被入侵」→ 进 ir 模式，还原攻击链
- 你说「远程 SSH 拉客户机的进程和网络」→ 进 remote 模式（授权+白名单+审计+录制）

每个模式背后都是**知识库 + 规则脚本 + 输出模板**的组合，蓝队人员不用记 tshark 语法、不用记 evtx 通道号、不用手写脱敏正则，只管说结果、看证据。

**它解决了什么问题**：

| 蓝队人员的痛点 | 传统做法 | 本 Skill 的做法 |
|---|---|---|
| 4 家国产厂商告警字段不一致 | 手写 mapping 或人肉看 | `vendor_field_mapper.py` 一键归一化，支持 NGSOC / SIP / SafeLine / 明御 |
| pcap 打开 wireshark 手动过滤 | tshark 命令记不全 | `traffic_anomaly.py` 六视图 × 69 条规则，直接输出异常清单 |
| evtx 事件日志分析靠 EventID 硬记 | 反复 grep | `evtx_hunt.py` 22 条规则覆盖 Security/Kerberos/PowerShell/Sysmon 四组 |
| 主机取证核查项容易漏 | 靠个人经验 | Linux 14 章 + Windows 14 章 48 项标准化清单 |
| 远程 SSH 命令没审计留痕 | 直接开 ssh，无记录 | 授权 + 白名单 + 审计 + 会话录制四要素强制 |
| 告警报告脱敏靠手工 | 每次都要 sed | 输出前自动过 `desensitize.py`，6 类脱敏规则内建 |

---

## 五模式一览

| 模式 | 中文 | 触发场景 | 输入 | 输出 |
|---|---|---|---|---|
| **monitor** | 值守监管 | 日常值守、告警批次分诊、值守日报 | 告警 JSON/CSV、SIEM 导出 | P0-P3 分级清单 + 值守日报 |
| **audit** | 日志审计 | 主动审计、时段排查、专项排查（webshell / 暴破 / SQLi）| 原始日志（nginx / auth / evtx-csv 等） | 异常清单（带证据行号）+ 标准 IOC 列表 |
| **traffic** | 流量审计 | pcap/pcapng 离线审计、C2 识别、隧道工具识别 | tcpdump / wireshark 抓取的 pcap 文件 | 异常清单 + tshark 定位 + 六视图证据 |
| **ir** | 应急响应 | 主机失陷、入侵取证、事件复盘 | 主机采集包（Linux tar.gz / Windows PS 输出）| 攻击链还原 + 12 节事件报告 |
| **remote** | 远程分析 | 授权 SSH 直连客户机采集或止血 | SSH 凭据 + 客户书面授权 + 白名单命令 ID | 远程命令 stdout（脱敏）+ session 录制 + 审计条目 |

**升级链**：
```
monitor 命中 P0/P1 → 转 audit 或 traffic 深挖证据 → 确认入侵 → 转 ir 取证 → 输出 incident-report
                                                                                ↕
                                              （远程分析）remote ←→ ir 协作
                                              - remote 拉数据 → ir 分析
                                              - ir 定性入侵 → remote 触发 Tier 3 处置（需二次授权）
```

---

## 设计原则

1. **授权优先** — 所有远程动作四要素强制：书面授权 + 白名单命令 + 每命令审计 + 会话录制。堡垒机场景降级到 H-I-L（Skill 只生成命令清单，蓝队人员在堡垒机 web 端粘贴执行）
2. **厂商无关** — 日志字段走最大公约数；具体厂商扩展放 `references/log-fields/vendor-*.md`（已覆盖奇安信 NGSOC / 深信服 SIP / 长亭雷池 SafeLine / 安恒明御 WAF 四家）
3. **可解释** — 每个判定必须附证据（日志原文 + 行号 + 命中规则 ID）；结论不下"感觉像"、"可能是"的模糊定性
4. **脱敏内建** — 所有面向用户的回显默认过 `scripts/desensitize.py`（IP 保留 /24 段、用户名首字符+长度、内部域名替换为 `<internal>`、客户名 `<customer>`、敏感路径 `/data/<app>/`）
5. **红线三条** — 不出可复现的 PoC payload（防反向滥用）· 不做破坏性 / 不可逆操作（`rm` / `chmod` / `useradd` / `reboot` / `iptables -F` 命令族全禁）· 不做横移（即便取得会话也不允许再 SSH / SCP 到第二跳）

---

## 快速开始

### 1. 环境要求

- **操作系统**：macOS / Linux / WSL（Windows 会打印手工安装指引后退出）
- **Claude Code**：需要已安装并可用（`claude --version` 有输出）
- **依赖**：`python3` (≥3.8) + `tshark`（traffic 模式必需）+ `sshpass` / `expect`（remote 模式密码认证可选）

### 2. 克隆 & 安装

```bash
# 克隆到本地
git clone https://github.com/ClinininSec/BlueTeamSkill.git
cd BlueTeamSkill

# 软链到 Claude Code skills 目录（Claude Code 自动扫描 ~/.claude/skills/）
ln -sfn "$(pwd)" ~/.claude/skills/hvv-defender

# 一键装依赖：tshark + python3 + sshpass + expect
bash scripts/hvv_init.sh
```

`hvv_init.sh` 会：
- 探测系统 + 包管理器（macOS brew / Debian apt / RHEL dnf/yum / Alpine apk / Arch pacman / openSUSE zypper）
- 装硬依赖 `tshark` + `python3`
- 装 remote 密码认证依赖 `sshpass`（主）+ `expect`（备）
- 二次确认所有依赖已入 PATH

**退出码**：`0` 硬依赖就绪；非 0 有硬依赖装不上需手动排查。`sshpass` / `expect` 都未装成功只 WARN，remote 模式将强制改用 SSH 公钥登录。

### 3. 触发方式

方式 A — **自然语言**（推荐）：直接说人话，Skill 会根据触发词自动进入对应模式。

```
你: 帮我分诊一下今天这批 NGSOC 告警，文件在 ./alerts-20260630.json，昨晚 22:00-24:00 的
你: 审计一下 /var/log/nginx/access.log 最近 24 小时，重点看 webshell 迹象
你: 这个 pcap 是 tcpdump 抓的，我怀疑里面有 fscan，帮我识别工具指纹
你: 192.168.1.50 root 密码被撞了，需要应急，还原攻击链出份报告
你: 用户答应我 SSH 直连他那台 CentOS 拉 top / netstat / auth.log 出来
```

方式 B — **显式命令**：

```bash
/hvv-defender monitor --input ./alerts.json --window 8h
/hvv-defender audit --target /var/log/nginx/access.log --since 2026-06-30T08:00
/hvv-defender traffic --pcap ./capture.pcap
/hvv-defender ir --host 192.168.1.50
/hvv-defender remote --target user@host --command list-processes --authorized-by TICKET-123
```

---

## 使用示例

### 示例 1：值守期间分诊一批告警

```
You: 帮我看一下今天这批告警，./alerts-2026-06-30.json，2000 条左右
Skill:
  [1] scripts/log_parser.py 解析告警 → 归一化字段
  [2] scripts/ioc_match.py 内置 IOC + 工具特征匹配
  [3] agents/alert-triage 子 agent 分诊
  [4] 输出：
      P0  3 条（fastjson 反序列化 RCE 真实命中）
      P1 12 条（sqlmap 扫描，部分疑似命中）
      P2 87 条（一般扫描器低 payload）
      P3 1898 条（误报或低风险）
  [5] scripts/desensitize.py 脱敏
  [6] 渲染 assets/daily-report.md 值守日报 + 待跟进列表（3 条 P0 + 4 条 P1）
```

### 示例 2：审计 nginx 排查 webshell

```
You: 审计 /var/log/nginx/access.log，2026-06-30 8 点到 18 点，重点看 webshell
Skill:
  [1] scripts/log_parser.py 切窗口、字段标准化
  [2] scripts/nginx_anomaly.py 跑：
      - UA 工具指纹（sqlmap / nuclei / xray / fscan / dirsearch / feroxbuster ...）
      - 4xx 突增 IP
      - 敏感路径（.git/ / .env / wp-admin 等）
      - 异常 payload（${jndi:、Runtime.getRuntime、phpinfo()、ImportNode）
      - 长 URL / 编码套娃 / 路径穿越
  [3] scripts/webshell_scan.py 扫 web 目录（配合 data/webshell-patterns.json 36 条规则）
  [4] 同 IP 跨规则关联升级
  [5] 输出异常清单 + IOC（IP / UA / 路径）
```

### 示例 3：pcap 流量审计（识别 C2 / 隧道 / DNS 隐蔽通道）

```
You: 分析这个 pcap，是从客户防火墙镜像口抓的，30 分钟数据
Skill:
  [1] scripts/pcap_parser.py 六视图归一化：http / dns / tls / flow / creds / conn
  [2] scripts/traffic_anomaly.py 跑 69 条规则：
      - 基础 12 条（扫描器 / SQLi / RCE / DNS 隧道 / DGA / 反弹 shell / C2 心跳 / webshell 通信）
      - Windows 横向 4 条（SMB 命名管道 / PsExec / RDP 异常 / WMI DCOM）
      - 内网穿透 3 条（frp / nps / chisel + gost / stowaway）
      - TLS 深化 20 条（JA3/JA3S 指纹 / 异常 SNI / 短周期证书）
      - DNS 深化 15 条（DNS-over-HTTPS 泄露 / TXT 隐蔽通道 / 长子域 exfil）
      - 国内红队工具 14 条（xray / rad / crawlergo / sunny / pupy / suo5 ...）
      - R-TRAF-999 关联簇（同 src_ip 跨 ≥3 规则升级）
  [3] 输出异常清单 + tshark 定位命令 + 六视图证据
```

### 示例 4：应急响应还原攻击链

```
You: 192.168.1.50 怀疑被入侵，怎么办
Skill:
  [1] 引导：请在客户主机上跑 scripts/linux_quick_check.sh，回传 tar.gz
  [2] 收到回传 → 按 references/ioc-checklist/linux-host-check.md 14 章核查：
      进程 / 隐藏进程 / 网络连接 / 新增账户 / SUID / cron / systemd / authorized_keys
      / bash_history / 最近 7 天修改文件 / tunnel 相关进程
  [3] scripts/webshell_scan.py 扫 web 目录
  [4] scripts/timeline_build.py 合并 auth + web + syslog + cron 时间线
  [5] agents/ir-investigator 子 agent 还原攻击链
  [6] 输出 assets/incident-report.md：
      入口点：8080 端口 OA 系统的 fastjson 反序列化（CVE-2022-25845）
      立足点：/tmp/.X11-lock 持久化后门
      提权：未发现（已是 root 服务进程）
      横向：发现对 192.168.1.x 段的 22 端口探测
      持久化：/etc/cron.d/.update 计划任务
      数据动作：未发现批量外传
      止血：封 IP / kill PID / 清 cron / 改密码
      根除：审计同版本 OA / 补丁 / 轮换密钥
      恢复：保留快照 / 回滚到清洁基线
```

### 示例 5：授权 SSH 远程采集

```
You: 用户答应我 SSH 直连他那台 CentOS 172.16.1.10，工单号 HVV-2026-0630-001，
     拉一下当前进程 / 网络连接 / auth.log
Skill:
  [1] 入场对齐 5 问：授权 / 连通性 / 跳板机 / 密钥 / Tier 3 需求
  [2] scripts/remote/ssh_probe.py --dry-run 预演，打印 ssh_argv + 审计条目
  [3] 正式执行三条 Tier 1 只读命令：
      ssh_probe.py --target root@172.16.1.10 --command list-processes --authorized-by HVV-2026-0630-001
      ssh_probe.py --target root@172.16.1.10 --command list-connections --authorized-by HVV-2026-0630-001
      ssh_probe.py --target root@172.16.1.10 --command tail-auth-log --authorized-by HVV-2026-0630-001
  [4] 三份产物同时落地：
      stdout（脱敏后）
      ~/.hvv-defender/sessions/172.16.1.10-<ts>.log（会话录制）
      ~/.hvv-defender/audit.jsonl（追加式审计）
  [5] 结果送入 audit / ir 分析
```

---

## 项目结构

```
BlueTeamSkill/
├── SKILL.md                       ← Claude Code Skill 入口（160 行）
├── README.md                      ← 本文件
├── LICENSE                        ← Apache-2.0
│
├── agents/                        ← 子 agent prompts
│   ├── alert-triage.md            ← monitor 模式的 P0-P3 分诊 agent
│   ├── log-analyzer.md            ← audit 模式跨源关联分析 agent
│   └── ir-investigator.md         ← ir 模式攻击链还原 agent
│
├── assets/                        ← 输出模板
│   ├── daily-report.md            ← 值守日报（monitor）
│   ├── handover.md                ← 值守交接班模板
│   ├── incident-report.md         ← 事件报告 12 节（ir）
│   └── ioc-extract.md             ← 标准 IOC 输出格式
│
├── data/                          ← 运行时特征库（JSON）
│   ├── ioc-builtin.json           ← 51 条基线 IOC
│   ├── remote-command-whitelist.json  ← 59 条 3-tier 远程命令白名单
│   ├── traffic-signatures.json    ← 126 条流量特征（SIG-TRAF-*）
│   ├── sysmon-detection-rules.json    ← 38 条 Sysmon 规则
│   ├── windows-persistence-patterns.json  ← 48 条 Windows 持久化模式
│   ├── tool-signatures.json       ← 60 条攻击工具特征
│   └── webshell-patterns.json     ← 36 条 webshell 特征
│
├── references/                    ← 知识库（Claude 按需读取）
│   ├── CHANGELOG.md               ← v0.1 → v0.4-M0 版本历史
│   ├── rule-id-namespaces.md      ← 规则 ID 命名分层总表
│   ├── modes/
│   │   ├── monitor.md             ← monitor 详细流程
│   │   ├── audit.md               ← audit 详细流程
│   │   ├── traffic.md             ← traffic 详细流程（此模式 playbook 在 playbooks/traffic-audit.md）
│   │   ├── ir.md                  ← ir 详细流程
│   │   └── remote.md              ← remote 详细流程 + 合规四要素
│   ├── playbooks/                 ← 6 类攻击处置剧本
│   │   ├── webshell.md
│   │   ├── brute-force.md
│   │   ├── sql-injection.md
│   │   ├── command-exec.md
│   │   ├── lateral-movement.md
│   │   └── traffic-audit.md
│   ├── log-fields/                ← 日志字段速查
│   │   ├── web-access.md          ← Apache / Nginx access
│   │   ├── linux-auth.md          ← auth.log / secure
│   │   ├── windows-evtx.md        ← Windows 事件日志
│   │   ├── windows-sysmon.md      ← Sysmon 19 类字段
│   │   ├── waf-fw-generic.md      ← WAF / 防火墙通用
│   │   ├── audit-session.md       ← remote 模式审计字段（v0.4-M0）
│   │   ├── vendor-qax-ngsoc.md    ← 奇安信 NGSOC
│   │   ├── vendor-sangfor-sip.md  ← 深信服 SIP
│   │   ├── vendor-changting-safeline.md ← 长亭雷池 SafeLine
│   │   └── vendor-dbappsec-mingyu.md    ← 安恒明御 WAF
│   ├── attack-patterns/           ← 特征知识库
│   │   ├── webshell-signatures.md
│   │   ├── c2-signatures.md
│   │   ├── tool-fingerprints.md
│   │   ├── living-off-land.md
│   │   ├── malicious-traffic.md
│   │   ├── windows-lateral-traffic.md
│   │   ├── tunnel-tools-traffic.md
│   │   ├── tls-fingerprints.md
│   │   └── dns-covert-channels.md
│   ├── ioc-checklist/
│   │   ├── linux-host-check.md    ← Linux 应急核查 14 章
│   │   └── windows-host-check.md  ← Windows 应急核查 14 章 48 项
│   ├── remote-command-whitelist.md    ← 3-tier 白名单详细知识库
│   ├── grading.md                 ← P0-P3 分级 + SLA
│   ├── compliance.md              ← 脱敏规则、红线细则、数据保留销毁
│   └── glossary.md                ← 蓝 / 红 / 监管侧术语映射
│
├── scripts/                       ← 可执行脚本
│   ├── hvv_init.sh                ← 一键装依赖
│   ├── log_parser.py              ← 通用日志解析
│   ├── ioc_match.py               ← 本地 IOC 匹配（--builtin 加载 data/ioc-builtin.json）
│   ├── nginx_anomaly.py           ← nginx 异常聚合
│   ├── auth_log_audit.py          ← ssh 登录 / 暴破审计
│   ├── webshell_scan.py           ← webshell 静态扫描
│   ├── timeline_build.py          ← 多源日志合并时间线
│   ├── pcap_parser.py             ← pcap 六视图归一化（依赖 tshark）
│   ├── traffic_anomaly.py         ← 69 条流量规则引擎
│   ├── evtx_hunt.py               ← Windows evtx 22 条 R-WIN 规则
│   ├── vendor_field_mapper.py     ← 4 家国产厂商字段归一化
│   ├── desensitize.py             ← 输出脱敏
│   ├── linux_quick_check.sh       ← Linux 主机一键采集
│   ├── windows_quick_check.ps1    ← Windows 主机一键采集
│   └── remote/                    ← v0.4-M0 remote 模式
│       ├── ssh_probe.py           ← 单命令远程执行（白名单校验）
│       ├── remote_collect.py      ← 组合采集（上传 → 执行 → 回传 → 清理）
│       └── session_recorder.sh    ← 交互式会话全程录制（script 命令）
```

---

## Rule ID 命名分层

Skill 里的每条规则都有前缀标识，方便审计和溯源。完整表见 [`references/rule-id-namespaces.md`](references/rule-id-namespaces.md)。

| 前缀 | 含义 | 落地位置 | 由脚本 emit |
|---|---|---|---|
| `PLB-<XX>-NNN` | Playbook 指引规则 | `references/playbooks/*.md` | ❌（供蓝队照此写客户 SIEM 规则）|
| `SIG-<XX>-NNN` | 攻击特征 | `references/attack-patterns/*.md` + `data/*.json` | ✅ 308 条落地（36+60+126+48+38）|
| `R-<AUTH/NGX>-NNN` | 日志运行时规则 | `scripts/{auth_log_audit,nginx_anomaly}.py` | ✅ |
| `R-TRAF-NNN` | 流量运行时规则 | `scripts/traffic_anomaly.py` | ✅ 69 条 |
| `R-WIN-NNN` | Windows evtx 运行时规则 | `scripts/evtx_hunt.py` | ✅ 22 条 |
| `R-REM-NNN` | Remote 只读 / 采集运行时 | `scripts/remote/{ssh_probe,remote_collect}.py` | ✅ 每次成功执行 emit |
| `R-REM-DISP-NNN` | Remote Tier 3 处置类 | 同上，`--allow-mutating` 时 emit | ✅ 独立命名空间便于告警审计 |
| `CHECK-LIN-N.N` | Linux 主机核查项 | `references/ioc-checklist/linux-host-check.md` | ❌ 人工核，14 章 |
| `CHECK-WIN-N.N` | Windows 主机核查项 | `references/ioc-checklist/windows-host-check.md` | ❌ 人工核，14 章 48 项 |
| `IOC-<type>` | IOC 匹配命中分类 | `scripts/ioc_match.py` | ✅ |
| `VENDOR-<name>` | 厂商归一化标签 | `scripts/vendor_field_mapper.py` | ✅ 4 家厂商 |
| `SESSION-AUDIT-<action>` | Remote 会话审计 | `~/.hvv-defender/audit.jsonl` | ✅ 每次调用一条 |

---

## 输出契约

所有 `R-*` / `PLB-*` 命中都输出**统一 8 字段告警条目**（跨模式一致）：

| 字段 | 取值 | 必填 |
|---|---|---|
| `id` | 本次会话唯一（`MON-001` / `AUD-001` / `IR-001` / `TRAF-001` / `REM-001`）| ✅ |
| `severity` | `P0` / `P1` / `P2` / `P3` | ✅ |
| `category` | webshell / brute-force / sqli / rce / lateral / recon / data-exfil / 其他 | ✅ |
| `evidence` | 日志原文（脱敏后）+ 行号 / 文件路径 | ✅ |
| `rule_id` | 命中规则 ID | ✅ |
| `false_positive_prob` | 0.0 - 1.0 | ✅ |
| `recommended_action` | 处置建议 | ✅ |
| `iocs` | 提取的 IOC 列表（按 IOC schema）| ⛔ 可空 |

**IOC schema**：`type` / `value`（脱敏）/ `confidence` / `first_seen` / `source` / `tag`

字段完整定义 + 样例见 [`references/rule-id-namespaces.md`](references/rule-id-namespaces.md) 与 [`references/modes/monitor.md`](references/modes/monitor.md) §七。

---

## 合规与红线

### 硬红线三条

- ❌ **不输出可复现的攻击 PoC payload**（防反向滥用）— 识别特征只写到"触发字段 + 关键词"层级，不给完整 exploit chain
- ❌ **不做破坏性 / 不可逆操作** — `rm` / `mv` / `chmod` / `chown` / `useradd` / `userdel` / `reboot` / `dd` / `mkfs` / `iptables -F` / `DROP TABLE` 等命令族全禁；即便 remote 模式 Tier 3 打开，命令拼接前仍会二次自检命中禁区拒绝
- ❌ **不做横移（lateral pivot）** — 即便 remote 已取得会话，也不允许从客户机再 SSH / SCP / SFTP / nc / curl / wget 到第二跳（防止 Skill 变成攻击链跳板）

### 远程连接四要素（remote 模式强制）

1. **书面授权** — `ssh_probe.py --authorized-by` 必填工单号或邮件 ID
2. **白名单命令** — 必须匹配 `data/remote-command-whitelist.json` 的 `cmd_id`
3. **每命令审计** — `~/.hvv-defender/audit.jsonl` 追加式，每次调用一条
4. **会话录制** — Python 层 tee-fork 自动录制到 `~/.hvv-defender/sessions/<host>-<ts>.log`

**Tier 分级**：
- **Tier 1**（40 条只读，默认开）— `ps` / `ss` / `last` / `tail auth.log` 等
- **Tier 2**（8 条采集脚本，默认开+审计）— 组合采集类
- **Tier 3**（11 条处置类，**默认关**）— `kill` / `passwd -l` / `block-ip` 等；需 `--allow-mutating` + 客户口头二次确认

**堡垒机场景**：客户走 JumpServer / 齐治 / Coco 等堡垒机时，Skill **不接堡垒机 API**，只生成命令清单让蓝队人员在堡垒机 web 端粘贴（H-I-L 降级）。

### 脱敏规则（默认开启）

- **私网 IP** → 保留 /24 段末段：`192.168.1.100` → `192.168.1.xxx`
- **公网攻击者 / C2 IP** → 不脱敏（IOC 价值高）
- **用户名** → 首字符 + 长度：`zhangsan` → `z*******`
- **内部域名** → `<internal>`
- **客户名 / 项目代号** → `<customer>` / `<project>`
- **敏感文件路径** → `/data/app/` → `/data/<app>/`
- **Hash（MD5/SHA1/SHA256）** → 不脱敏（已不可逆）

完整规则见 [`references/compliance.md`](references/compliance.md)。

---

## 路线图

- ✅ **v0.1** — MVP 三模式（monitor / audit / ir）+ 5 playbook + 8 脚本 + 内置 IOC 51 条
- ✅ **v0.2** — traffic 模式（pcap 离线审计）+ 86 条流量特征
- ✅ **v0.2.1** — `hvv_init.sh` 一键环境初始化
- ✅ **v0.3-M1** — 三大能力包：4 家国产厂商告警研判 + Windows 主机 IR 全套 + 流量深化到 126 条
- ✅ **v0.4-M0（当前）** — remote 第 5 模式（授权 SSH 分析）+ 59 条 3-tier 白名单
- 🔜 **v0.3-M2** — phishing / ransomware / data-exfil / 0day-emerge / AD 攻击检测 playbook
- 🔜 **v0.5** — MCP 工具化封装 · 情报 API 接入（VirusTotal / 微步 / ThreatBook）· 客户 SIEM/EDR API 对接
- 🔜 **v0.6+** — AI 辅助规则挖掘 · 告警根因分析 · 多主机集群模式

详细版本历史见 [`references/CHANGELOG.md`](references/CHANGELOG.md)。

---

## 贡献指南

欢迎蓝队人员反馈误报 / 漏报 / 缺失的攻击类型、共享厂商日志字段、贡献 playbook。

### 如何贡献

1. **Bug / 误报**：开 issue，附上（脱敏后）样本 + 命中的规则 ID + 期望行为
2. **新增规则**：
   - 流量规则加到 `data/traffic-signatures.json`（走 `SIG-TRAF-*` 命名空间）
   - webshell 特征加到 `data/webshell-patterns.json`
   - Windows 持久化加到 `data/windows-persistence-patterns.json`
   - 附上 pcap / 日志样本（脱敏）与规则命中的 false-positive rate 评估
3. **新增 playbook**：在 `references/playbooks/` 下新建 `<attack-type>.md`，遵循已有格式（特征 / 查询 / 止血 / 根除 / IOC 五节）
4. **新增厂商日志字段**：在 `references/log-fields/vendor-<name>.md` 下新建；如需字段归一化，扩展 `scripts/vendor_field_mapper.py`

### PR 规范

- 每个 PR 只做一件事（新规则 / 新 playbook / bug 修复 / 文档更新）
- 变更规则数量时，同步更新 `SKILL.md` 与 `README.md` 里的计数（否则会被"数字漂移"审计打回）
- 涉及远程命令的 PR **必须**说明 tier 分级 + 关联 CHECK-* 检查项 + 二次冒烟验证
- Python 脚本变更需保持向后兼容的 CLI（既有 `--flag` 不动）

### 报告安全问题

如果你发现本 Skill **自身**有安全问题（比如脱敏被绕过、白名单校验漏洞、命令注入），**不要开 public issue**，请邮件到项目维护者（在 GitHub profile 上）。

---

## License

[Apache License 2.0](LICENSE) © ClinininSec

商业使用友好，需保留版权与协议声明。特征库中的 IOC / 规则来自公开威胁情报报告与研究，遵循原引用协议。

---

## 免责声明

**本工具用于合法授权范围内的蓝队防守作业。**

- 使用者必须在**获得客户书面授权**的前提下使用本工具，尤其是 remote 模式的远程连接与命令执行
- 工具不输出可复现的攻击 PoC；识别特征仅用于防御检测
- 使用者需自行承担因**未授权使用**、**误操作**、**违反客户合规要求**导致的一切后果
- 本工具不构成对任何具体入侵事件的法律定性建议；结论仅供技术分析参考

如果你不是**获得客户授权的蓝队人员**，或不确定手上是否有足够授权，**请停止使用**并咨询客户安全合规部门。

---

<p align="center">
  <sub>Built for blue team engineers, by blue team engineers. · <a href="https://github.com/ClinininSec/BlueTeamSkill/issues">Issues</a> · <a href="https://github.com/ClinininSec/BlueTeamSkill/pulls">PRs welcome</a></sub>
</p>
