---
name: hvv-defender
description: |
  护网蓝队驻场作战 skill。覆盖 monitor（告警分诊）/ audit（日志审计）/ traffic（pcap 流量审计）/ ir（应急响应）/ remote（授权 SSH 远程分析）五模式一体化作业，面向乙方驻场。

  当用户说 "帮我看这批告警 / 分诊 SIEM 告警 / 值守日报 / 审计 nginx / auth.log / 排查 SSH 暴破 / webshell 扫描 / 分析 pcap / wireshark 抓包 / tcpdump / 识别 C2 / JA3 指纹 / DNS 隧道 / 主机怀疑被入侵 / 应急响应 / 还原攻击链 / 出事件报告 / evtx 分析 / Windows 主机排查 / NGSOC / 深信服 SIP / 长亭雷池 / 明御 WAF / 远程 SSH 采集 / 远程执行命令 / 提取 IOC / 这个 IP 是不是 C2 / 这个 hash 有没有见过 / log4j 检测规则怎么写" 中的任一类时，优先激活本 skill。

  设计原则：离线优先 + 授权远程；脱敏内建；每条告警必附证据；红线三条：不出 PoC / 不做破坏动作 / 不做横移。首次使用先跑 `bash scripts/hvv_init.sh` 装依赖（tshark + python3 + sshpass/expect）。当前版本 v0.4-M1，历史版本见 `references/CHANGELOG.md`。
allowed-tools:
  - Read
  - Write
  - Grep
  - Glob
  - Bash
  - Task
model: sonnet
---

# hvv-defender — 护网蓝队驻场作战 Skill

> 乙方驻场护网 · 授权+审计+录制下的**五模式**（monitor / audit / traffic / ir / remote）一体化作业台

## When to Use This Skill

命中以下任一意图，激活本 Skill：

- **值守 / 监管类**："帮我看一下今天这批告警"、"分诊一下这些 SIEM 告警"、"值守日报"、"哪些是误报"
- **初始化 / 环境准备**："初始化 hvv-defender / 装依赖 / 环境自检" → `bash scripts/hvv_init.sh`
- **审计 / 排查类**："审计一下最近一周的 nginx 日志"、"看看有没有 webshell"、"排查 ssh 暴破"、"查一下昨天 8 点到 12 点的访问异常"
- **流量审计类**："分析这个 pcap"、"看一下 wireshark 抓包"、"tcpdump 抓的流量"、"识别 C2 通信"、"pcap 里有没有横向移动"、"隧道工具流量"、"JA3/JA3S 指纹"、"DNS 隧道"、"国内红队工具流量"
- **应急 / 取证类**："这台机器怀疑被入侵了"、"应急响应"、"还原攻击链"、"主机失陷取证"、"出一份事件报告"
- **Windows 事件日志分析**："分析 evtx"、"Windows 事件日志"、"Sysmon 分析" → audit 模式 + `scripts/evtx_hunt.py`
- **Windows 主机取证**："Windows 主机排查"、"windows-host-check" → ir 模式 + `scripts/windows_quick_check.ps1`
- **国产厂商告警类**："NGSOC 告警"、"奇安信 SIP 告警"、"深信服态势感知"、"长亭雷池 SafeLine"、"明御 WAF" → `scripts/vendor_field_mapper.py --vendor <name>`
- **远程连接类**："远程 SSH 采集"、"远程执行命令"、"从客户机拉一下进程/网络/日志"、"远程止血 kill / block-ip"（需授权+白名单+审计+录制四要素）
- **单点情报查询类**："这个 IP 是不是 C2 / 有没有见过"、"这个域名有没有威胁"、"这个 hash 是不是恶意"、"这个 UA 是什么工具" → 任意模式的 ioc_match / 特征匹配
- **规则学习 / 检测经验类**："给我 fastjson 的 SIEM 规则"、"log4j 检测特征怎么写"、"webshell 怎么防" → 检索 playbook 与 attack-patterns
- **IOC 提取（结构化输出阶段）**："提取 IOC"、"生成 IOC 列表" → 任意模式尾端必跑
- **明确触发词**：`/hvv-defender`、`/hvv-defender init`、"护网防守"、"蓝队"

**同一 query 命中多类怎么办**：按 monitor < audit < traffic ≈ ir < remote 的**处置深度**升序，选深度更深者。例："pcap 里的 IOC"命中 traffic + IOC 提取，走 traffic；"Windows 主机被入侵怎么排查"命中 ir + Windows 主机取证，走 ir + `windows_quick_check.ps1`。

## 关键参考文件

进入 skill 后细节在这里查，不用把 SKILL.md 撑到 500 行。

| 类别 | 位置 | 用途 |
|---|---|---|
| 模式流程 | `references/modes/{monitor,audit,traffic,ir,remote}.md` | 五模式的详细步骤与决策树 |
| 处置剧本 | `references/playbooks/*.md` | 6 类攻击的端到端处置（含特征 / 查询 / 止血 / 根除 / IOC） |
| 流量审计剧本 | `references/playbooks/traffic-audit.md` | pcap 六步审计 + TLS / DNS 深化 |
| 日志字段 | `references/log-fields/*.md` | 主流日志字段速查 + 4 家国产厂商抽屉 + audit-session（remote 审计字段） |
| 攻击特征 | `references/attack-patterns/*.md` | webshell / C2 / 工具指纹 / LOLBins / 恶意流量 / Windows 横向 / 内网穿透 / TLS 指纹 / DNS 隐蔽通道 |
| Linux 主机核查 | `references/ioc-checklist/linux-host-check.md` | 14 章应急取证核查清单 |
| Windows 主机核查 | `references/ioc-checklist/windows-host-check.md` | 14 章 48 项应急取证核查清单（`CHECK-WIN-*`） |
| 远程白名单 | `references/remote-command-whitelist.md` | 3 tier 命令白名单知识库（40 只读 + 8 采集 + 11 处置） |
| 分级标准 | `references/grading.md` | P0-P3 定义 + SLA，跨客户语义一致 |
| 合规边界 | `references/compliance.md` | 脱敏规则、数据外发禁止项、操作红线、远程连接四要素 |
| 规则命名分层 | `references/rule-id-namespaces.md` | 所有 `R-*` / `PLB-*` / `SIG-*` / `CHECK-*` 前缀的命名空间总表 |
| 版本历史 | `references/CHANGELOG.md` | v0.1 → v0.4-M1 的能力演化 |
| 术语表 | `references/glossary.md` | 蓝队 / 红队 / 监管侧术语映射 |
| 跨规则关联 agent | `agents/log-analyzer.md` | audit 模式跨源关联分析 |
| 告警分诊 agent | `agents/alert-triage.md` | monitor 模式 P0-P3 分级 + 误报判定 |
| IR 调查 agent | `agents/ir-investigator.md` | ir 模式攻击链还原 |
| 值守日报模板 | `assets/daily-report.md` | monitor 输出格式 |
| 事件报告模板 | `assets/incident-report.md` | ir 输出格式（12 节） |
| 值守交接模板 | `assets/handover.md` | 白班 / 夜班交接、周班交接 |
| IOC 提取模板 | `assets/ioc-extract.md` | 标准 IOC schema 输出 |
| 内置 IOC 库 | `data/ioc-builtin.json` | 51 条基线 IOC，`ioc_match.py --builtin` 自动加载 |
| 统一终报模板 | `assets/final-report.md` | 跨 5 模式收尾结论报告（攻击路径骨架，10 节 spine + 模式激活表） |
| findings.json schema | `assets/findings-schema.md` | 终报机器可读伴生文件 schema（8 字段契约 + attack_paths + ioc_ref） |

## 首次使用：装依赖

首次在客户驻场机器上使用本 Skill 前，跑一次依赖装设脚本：

```bash
bash scripts/hvv_init.sh
```

**它做什么**：
1. 探测系统 + 包管理器（macOS brew / Debian & Ubuntu apt / RHEL & Fedora dnf/yum / Alpine apk / Arch pacman / openSUSE zypper）
2. 装硬依赖：`tshark`（traffic 模式必需）+ `python3`（所有脚本必需）
3. 装 remote 模式密码认证可选依赖：`sshpass`（主）+ `expect`（备）；二者至少一个可用即达标，都装最稳
4. 二次确认所有依赖已入 PATH，输出每个工具的绝对路径
5. Windows 系统会打印手工安装指引后退出（不自动装）

**退出码**：`0` 硬依赖就绪；非 0 有硬依赖装不上需手动排查。`sshpass` / `expect` 都未装成功只 WARN，remote 模式将强制改用 SSH 公钥登录。

当用户说"初始化 hvv-defender / 装依赖 / 环境自检 / `/hvv-defender init`"时，执行 `bash scripts/hvv_init.sh`。

## 五模式简述

每个模式的完整流程见 `references/modes/*.md`。SKILL.md 里只保留一句话概览与相互关系。

- **monitor（值守监管）** —— SIEM/告警批次分诊、误报研判、值守日报；支持 4 家国产厂商字段归一化（NGSOC / SIP / SafeLine / 明御 WAF）；输入告警 JSON/CSV，输出 P0-P3 分级清单 + 待跟进列表。详见 `references/modes/monitor.md`。
- **audit（日志审计）** —— 主动审计指定时段 / 系统日志（nginx access、auth.log、windows evtx 导出），输出异常清单（带证据行号）+ 标准 IOC 列表。详见 `references/modes/audit.md`。
- **traffic（流量审计）** —— 对 wireshark/tcpdump 抓取的 pcap/pcapng 做离线审计；六大视图（http / dns / tls / flow / creds / conn）× 69 条规则（基础 12 + Windows 横向 4 + 内网穿透 3 + TLS 深化 20 + DNS 深化 15 + 国内红队工具 14 + `R-TRAF-999` 关联簇），输出异常清单 + IOC。**需要本机预装 tshark**。详见 `references/playbooks/traffic-audit.md`。
- **ir（应急响应）** —— 怀疑或确认入侵后的取证排查，覆盖 Linux（`linux_quick_check.sh` + 14 章核查清单）与 Windows（`windows_quick_check.ps1` + `evtx_hunt.py` 22 条 `R-WIN-*` + 14 章 48 项核查），还原攻击链，输出 `incident-report`。详见 `references/modes/ir.md`。
- **remote（远程 SSH 分析）** —— 授权+白名单+审计+录制四要素约束下的 SSH 远程执行；59 条命令白名单 3 tier（40 只读 / 8 采集 / 11 处置）；Tier 3 默认关，需二次授权；堡垒机场景降级到 H-I-L（只生成命令清单让驻场人员在堡垒机 web 端粘贴）。详见 `references/modes/remote.md`；合规四要素见该文件 §二；命令白名单见 `references/remote-command-whitelist.md`。

**升级链**：
```
monitor 命中 P0/P1  →  转 audit 或 traffic 深挖证据  →  确认入侵  →  转 ir 取证  →  输出 incident-report
                                                                                       ↕
                                                    （远程分析）remote  ←→  ir 协作
                                                    - remote 拉数据 → ir 分析
                                                    - ir 定性入侵 → remote 触发 Tier 3 处置（需二次授权）
```

`remote` 与 `ir` 互补：`remote` 负责"从客户机拉数据 / 发命令"，`ir` 负责"分析数据 + 攻击链还原"。两者可独立跑，也可组合。

## 输出契约（跨模式一致）

所有 `R-*` / `PLB-*` 命中都输出统一 **8 字段告警条目**：`id` / `severity` (P0-P3) / `category` / `evidence`（脱敏后原文+行号）/ `rule_id` / `false_positive_prob` (0.0-1.0) / `recommended_action` / `iocs`（可空）。

IOC 输出走 **标准 schema**：`type` / `value`（脱敏）/ `confidence` / `first_seen` / `source` / `tag`。

**收尾统一报告**：任意模式得出结论后，输出跨模式一致的 markdown 终报 `assets/final-report.md`（按攻击路径组织，10 节 spine + 模式激活表，5 模式各有变体），并同生机器可读伴生文件 `findings.json`（schema 见 `assets/findings-schema.md`；`findings[]` 严格遵循上述 8 字段契约，`attack_paths[]` 消费 `agents/ir-investigator` 的 `kill_chain`）。现有 4 个模板（`incident-report` / `daily-report` / `ioc-extract` / `handover`）降为终报的模式专属附件。

字段完整定义、样例、Rule ID 命名分层（`PLB-*` / `SIG-*` / `R-*` / `CHECK-*` / `IOC-*` / `VENDOR-*` / `SESSION-AUDIT-*` 各前缀落地位置与 emit 规则）均在 `references/rule-id-namespaces.md`；`monitor.md §七` 有完整样例。

## 合规与脱敏（摘要）

**默认工作流规范**（不列为红线，但需常态执行）：

1. **脱敏内建**：所有面向用户的回显必须先过 `scripts/desensitize.py`。私网 IP 保留 /24 段末段（`192.168.1.100` → `192.168.1.xxx`）；用户名首字符 + 长度（`zhangsan` → `z*******`）；内部域名 → `<internal>`；客户名 → `<customer>`；敏感文件路径按 `/data/<app>/` 模式脱。
2. **离线优先**：默认不接客户 SIEM / EDR API，也不调第三方威胁情报 API（VirusTotal / 微步 / ThreatBook）；只用本地 `data/ioc-builtin.json`。远程调用必须走 §红线 4 的四要素。
3. **每次操作留审计**：`~/.hvv-defender/audit.jsonl` 追加式，remote 模式每命令一条。
4. **临时关闭脱敏**（`--no-desensitize`）需现场总指挥书面 / 群消息授权，仅单命令生效。

完整规则（脱敏 6 大类、数据保留销毁、客户授权要点、审计字段、违规处置）见 `references/compliance.md §二/§三/§四/§五/§六`。

## 操作红线

> 只限制"不可逆 / 破坏性 / 攻击复用"三类硬操作。脱敏、远程连接、白名单管理等日常规范见 `references/compliance.md`，不在此列。

- ❌ **不输出可复现的攻击 PoC payload**（防反向滥用）—— 识别特征只写到"触发字段 + 关键词"层级；不给完整 exploit chain
- ❌ **不擅自对客户主机执行破坏性 / 不可逆操作**（`rm` / `mv` / `chmod` / `useradd` / `reboot` / `dd` / `iptables -F` / `DROP TABLE` 等命令族全部禁用；命令族清单与例外见 `references/compliance.md §红线 6`）
- ❌ **不擅自删除或修改客户主机上的疑似恶意文件**（webshell / 后门 / 可疑 binary / 异常 cron / systemd unit）—— 只给路径让客户处理，保留取证链
- ❌ **不做横移（lateral pivot）**：即便 remote 已取会话，也不允许从客户机再 SSH / SCP / SFTP / nc / curl / wget 到第二跳
- ❌ **不发起对外攻击 / 反向探测**：不主动扫描客户网络以外的资产；不对攻击者源 IP 做反向连接、端口探测、漏扫

违反上述任一项即视为违规。详细违规处置流程见 `references/compliance.md §六`。

## Quick Reference

| 用户说 | 应进入 |
|---|---|
| "初始化 hvv-defender" / "装依赖" / `/hvv-defender init` | `bash scripts/hvv_init.sh` |
| "看一下告警" / "分诊一下" | monitor |
| "NGSOC 告警" / "深信服 SIP" / "雷池 SafeLine" / "明御 WAF" | monitor + `scripts/vendor_field_mapper.py --vendor <name>` |
| "审计 nginx" / "排查 ssh 暴破" | audit |
| "排查 webshell" | audit + `playbooks/webshell.md` |
| "分析 pcap" / "wireshark 抓包" / "tcpdump" / "识别 C2 通信" / "JA3 指纹" / "DNS 隧道" | traffic（需 tshark） |
| "分析 evtx" / "Windows 事件日志" | audit + `scripts/evtx_hunt.py` |
| "怀疑被入侵" / "应急响应" / "出事件报告" | ir |
| "Windows 主机排查" | ir + `scripts/windows_quick_check.ps1` |
| "远程 SSH 采集" / "拉一下客户机的进程 / 网络 / 日志" | remote + `scripts/remote/ssh_probe.py` |
| "远程 kill / 封 IP" | remote Tier 3（`--allow-mutating` + 二次授权） |
| "这个 IP / 域名 / hash / UA 是不是恶意" | 任意模式 + `scripts/ioc_match.py --builtin` |
| "给我 log4j / fastjson 的 SIEM 规则" | 检索 `references/playbooks/*.md` |
| "提取 IOC" / "生成 IOC 列表" | 任意模式尾端 + `assets/ioc-extract.md` |
| "出终报" / "生成报告" / "收尾出报告" | 任意模式收尾 + `assets/final-report.md` + `findings.json` |
| "值守日报" / "交接班" | monitor + `assets/daily-report.md` / `assets/handover.md` |
