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
> **五模式**（monitor / audit / traffic / ir / remote）· **316 条规则落地脚本运行时** · **每条结论必附证据** · **远程命令四要素护栏**

---

## 目录

- [是什么 / 为什么](#是什么--为什么)
- [五模式一览](#五模式一览)
- [快速开始](#快速开始)
- [使用示例](#使用示例)
- [项目结构](#项目结构)
- [输出契约](#输出契约)
- [合规与红线](#合规与红线)
- [Credits & Prior Art](#credits--prior-art)
- [路线图](#路线图)
- [贡献指南](#贡献指南)
- [License & 免责声明](#license--免责声明)

---

## 是什么 / 为什么

**护网期间蓝队人员的日常工作**可以拆成五类：告警分诊、日志审计、流量抓包分析、应急响应取证、远程主机采集。每类都有一套**手工流程 + 工具脚本 + 经验规则**，蓝队人员在项目现场需要在这五类之间不停切换、记忆规则、复制命令。

**`hvv-defender`** 是一个 **Claude Code Skill**（可理解为「有工具、有剧本、有运行时规则库的 AI 副驾驶」），把这五类整合到统一的**自然语言接口**下：

- 你说「帮我分诊这批告警」→ 进 monitor 模式
- 你说「审计 nginx 排查 webshell」→ 进 audit 模式（跑 36 条 webshell 特征）
- 你说「分析这个 pcap 里有没有 fscan」→ 进 traffic 模式（跑 69 条规则）
- 你说「这台机器怀疑被入侵」→ 进 ir 模式，还原攻击链
- 你说「远程 SSH 拉客户机」→ 进 remote 模式（授权+白名单+审计+录制）

每个模式背后是**知识库 + 规则脚本 + 输出模板**的组合。

---

## 五模式一览

| 模式 | 中文 | 触发场景 | 输入 | 输出 |
|---|---|---|---|---|
| **monitor** | 值守监管 | 告警批次分诊、值守日报 | 告警 JSON/CSV、SIEM 导出 | P0-P3 分级清单 + 值守日报 |
| **audit** | 日志审计 | 时段排查、专项排查（webshell / 暴破 / SQLi）| 原始日志（nginx / auth / evtx-csv 等） | 异常清单（带证据行号）+ IOC 列表 |
| **traffic** | 流量审计 | pcap 离线审计、C2 识别、隧道工具识别 | tcpdump / wireshark 抓取的 pcap | 异常清单 + tshark 定位 + 六视图证据 |
| **ir** | 应急响应 | 主机失陷、入侵取证、事件复盘 | 主机采集包（Linux tar.gz / Windows PS 输出）| 攻击链还原 + 12 节事件报告 |
| **remote** | 远程分析 | 授权 SSH 直连采集或止血 | SSH 凭据 + 客户书面授权 + 白名单 cmd_id | 远程 stdout（脱敏）+ session 录制 + 审计条目 |

**升级链**：`monitor 命中 P0/P1 → 转 audit / traffic 深挖 → 确认入侵 → 转 ir 取证 → 输出 incident-report`；ir ↔ remote 双向协作（remote 拉数据 → ir 分析；ir 定性 → remote 触发 Tier 3 处置）。

---

## 快速开始

### 环境要求

- macOS / Linux / WSL（Windows 会打印手工安装指引后退出）
- Claude Code（`claude --version` 有输出）
- 依赖：`python3` (≥3.8) + `tshark`（traffic 必需）+ `sshpass` / `expect`（remote 密码认证可选）

### 克隆 & 安装

```bash
git clone https://github.com/ClinininSec/BlueTeamSkill.git
cd BlueTeamSkill
ln -sfn "$(pwd)" ~/.claude/skills/hvv-defender   # Claude Code 自动扫描此目录
bash scripts/hvv_init.sh                          # 一键装依赖
```

`hvv_init.sh` 会探测系统 + 包管理器（brew / apt / dnf / apk / pacman / zypper），装硬依赖并二次确认 PATH。**退出码**：`0` 就绪 / 非 0 硬依赖装失败。

### 触发方式

**自然语言**（推荐）：
```
你: 帮我分诊今天这批告警,./alerts-20260630.json,昨晚 22:00-24:00 的
你: 审计一下 /var/log/nginx/access.log 最近 24 小时,重点看 webshell
你: 这个 pcap 是 tcpdump 抓的,识别工具指纹
你: 192.168.1.50 root 密码被撞了,应急,还原攻击链
你: 用户答应我 SSH 直连他那台 CentOS 拉 top / netstat / auth.log
```

**显式命令**：
```bash
/hvv-defender monitor --input ./alerts.json --window 8h
/hvv-defender audit --target /var/log/nginx/access.log --since 2026-06-30T08:00
/hvv-defender traffic --pcap ./capture.pcap
/hvv-defender ir --host 192.168.1.50
/hvv-defender remote --target user@host --command list-processes --authorized-by TICKET-123
```

---

## 使用示例

### 示例 1：告警分诊

```
You: 帮我看这批告警 ./alerts-2026-06-30.json,2000 条
Skill:
  [1] log_parser 归一化 → [2] ioc_match 匹配内置 IOC + 工具特征
  [3] agents/alert-triage 子 agent 分诊
  [4] 输出: P0 3 条(fastjson RCE) / P1 12 条 / P2 87 条 / P3 1898 条
  [5] desensitize 脱敏 → [6] 渲染 assets/daily-report.md
```

### 示例 2：pcap 流量审计（识别 C2 / 隧道）

```
You: 分析这个 pcap,防火墙镜像口抓的 30 分钟数据
Skill:
  [1] pcap_parser 六视图归一化: http / dns / tls / flow / creds / conn
  [2] traffic_anomaly 跑 69 条规则:
      基础 12 + Win 横向 4 + 穿透 3 + TLS 深化 20 + DNS 深化 15 + 国内红队 14 + R-TRAF-999 关联簇
  [3] 关联簇触发: 同 src_ip 命中 ≥3 条规则自动升级严重度
  [4] 输出异常清单 + tshark 定位命令 + 六视图证据
```

### 示例 3：应急响应还原攻击链

```
You: 192.168.1.50 怀疑被入侵
Skill:
  [1] 引导: 客户主机跑 linux_quick_check.sh,回传 tar.gz
  [2] 按 linux-host-check 14 章核查(进程/账户/网络/cron/authorized_keys/bash_history/近期修改文件...)
  [3] webshell_scan 扫 web 目录(36 条特征)
  [4] timeline_build 合并 auth + web + syslog + cron 时间线
  [5] agents/ir-investigator 还原攻击链
  [6] 输出 incident-report.md: 入口 / 立足点 / 提权 / 横向 / 持久化 / 数据动作 / 止血 / 根除 / 恢复
```

---

## 项目结构

```
BlueTeamSkill/
├── SKILL.md                       ← Claude Code Skill 入口（160 行）
├── README.md / LICENSE / .gitignore
├── agents/                        ← 3 个子 agent prompt（alert-triage / log-analyzer / ir-investigator）
├── assets/                        ← 4 个输出模板（daily-report / handover / incident-report / ioc-extract）
├── data/                          ← 7 个 JSON 特征库（316 条规则运行时数据）
│   ├── ioc-builtin.json                 ← 51 条基线 IOC
│   ├── remote-command-whitelist.json    ← 59 条 3-tier 远程白名单
│   ├── traffic-signatures.json          ← 126 条流量特征（SIG-TRAF-*）
│   ├── sysmon-detection-rules.json      ← 38 条 Sysmon 规则
│   ├── windows-persistence-patterns.json ← 48 条 Windows 持久化
│   ├── tool-signatures.json             ← 60 条攻击工具特征
│   └── webshell-patterns.json           ← 36 条 webshell 特征
├── references/                    ← 知识库（Claude 按需读取）
│   ├── CHANGELOG.md / rule-id-namespaces.md / compliance.md / grading.md / glossary.md
│   ├── modes/                     ← 5 模式详细流程
│   ├── playbooks/                 ← 6 类攻击处置剧本
│   ├── attack-patterns/           ← 9 份特征知识库
│   ├── log-fields/                ← 10 份日志字段速查（含 4 家国产厂商抽屉）
│   ├── ioc-checklist/             ← Linux 14 章 / Windows 14 章 48 项应急核查清单
│   └── remote-command-whitelist.md ← 3-tier 白名单详细知识库
└── scripts/                       ← 15 个可执行脚本
    ├── hvv_init.sh                ← 一键装依赖
    ├── log_parser / ioc_match / nginx_anomaly / auth_log_audit / webshell_scan / timeline_build
    ├── pcap_parser / traffic_anomaly    ← traffic 模式（依赖 tshark）
    ├── evtx_hunt                        ← Windows evtx 22 条 R-WIN 规则
    ├── vendor_field_mapper              ← 4 家厂商字段归一化
    ├── desensitize                      ← 输出脱敏（所有 stdout 强制过）
    ├── linux_quick_check.sh / windows_quick_check.ps1  ← 主机一键采集
    └── remote/                    ← v0.4-M0 remote 模式
        ├── ssh_probe.py           ← 单命令远程执行（白名单校验 + audit + 录制）
        ├── remote_collect.py      ← 组合采集（上传 → 执行 → 回传 → 清理）
        └── session_recorder.sh    ← 交互式会话全程录制（script 命令）
```

---

## 输出契约

所有 `R-*` / `PLB-*` 命中都输出**统一 8 字段告警条目**（跨模式一致）：

`id` / `severity` (P0-P3) / `category` / `evidence`（脱敏后原文 + 行号）/ `rule_id` / `false_positive_prob` (0.0-1.0) / `recommended_action` / `iocs`（可空）

IOC schema：`type` / `value`（脱敏）/ `confidence` / `first_seen` / `source` / `tag`

**规则 ID 前缀**（详见 [`references/rule-id-namespaces.md`](references/rule-id-namespaces.md)）：`R-*` 脚本运行时规则 emit · `PLB-*` playbook 建议规则 · `SIG-*` 攻击特征 · `CHECK-*` 主机核查清单 · `IOC-*` / `VENDOR-*` / `SESSION-AUDIT-*` 分类 tag

---

## 合规与红线

### 硬红线三条

- ❌ **不输出可复现的攻击 PoC payload** — 识别特征只写到"触发字段 + 关键词"层级
- ❌ **不做破坏性 / 不可逆操作** — `rm` / `mv` / `chmod` / `useradd` / `reboot` / `dd` / `iptables -F` / `DROP TABLE` 等命令族全禁
- ❌ **不做横移（lateral pivot）** — 即便取得会话也不允许再 SSH / SCP / SFTP / nc / curl / wget 到第二跳

### 远程连接四要素（remote 模式强制）

书面授权（`--authorized-by` 必填）· 白名单命令（匹配 `remote-command-whitelist.json` cmd_id）· 每命令审计（`~/.hvv-defender/audit.jsonl` 追加）· 会话录制（tee-fork 自动到 `~/.hvv-defender/sessions/<host>-<ts>.log`）

**Tier 分级**：Tier 1（40 条只读，默认开）/ Tier 2（8 条采集，默认开+审计）/ Tier 3（11 条处置，**默认关**，需 `--allow-mutating` + 客户口头二次确认）。堡垒机场景降级到 H-I-L（Skill 不接堡垒机 API，只生成命令清单让人工粘贴）。

### 脱敏（默认开启）

私网 IP 保留 /24 段 · 用户名首字符+长度 · 内部域名 `<internal>` · 客户名 `<customer>` · 敏感路径 `/data/<app>/` · 公网攻击者 IP / hash 不脱敏（IOC 价值高）

完整规则见 [`references/compliance.md`](references/compliance.md)。

---

## Credits & Prior Art

本项目在设计上**参考了社区蓝队 skill 生态**，特别是 [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)（817 skill 通用库，遵循 [agentskills.io](https://agentskills.io) 标准，映射 MITRE ATT&CK / NIST CSF / D3FEND / MITRE ATLAS / NIST AI RMF / MITRE F3 六大框架）中以下同类型 skill：

| 参考 skill | 覆盖场景 | hvv-defender 对应 |
|---|---|---|
| `triaging-security-alerts-in-splunk` · `performing-alert-triage-with-elastic-siem` | SIEM 告警分诊 | monitor 模式 |
| `hunting-for-webshell-activity` | webshell 检索 | audit + `webshell_scan.py` |
| `hunting-evtx-with-chainsaw` | Windows evtx 分析 | audit + `evtx_hunt.py` |
| `analyzing-linux-audit-logs-for-intrusion` | Linux auth 审计 | audit + `auth_log_audit.py` |
| `analyzing-dns-logs-for-exfiltration` · `analyzing-network-traffic-with-wireshark` | 流量 / DNS 隐蔽通道 | traffic 模式 |
| `building-incident-response-playbook` · `triaging-security-incident-with-ir-playbook` | IR 剧本与响应 | ir 模式 + `references/playbooks/` |
| `implementing-velociraptor-for-ir-collection` | 远程 IR 采集 | remote 模式 |

### 运行时行为优化（相对上述通用 skill）

以下是 hvv-defender 在**运行时行为**层面做的差异化优化（不涉及内容组织、语言等表层差异）：

1. **多 skill 合并为单会话工作流** — 上述参考项大多是**原子 skill**（一次做一件事）。hvv-defender 把「告警分诊 → 日志审计 → 流量分析 → 应急响应 → 远程采集」串成 monitor → audit → traffic → ir → remote **五模式升级链**，Claude 在**单个会话**里跨模式路由，无需重新加载 skill 上下文。

2. **规则库脚本化 + 冷启动零外部依赖** — 参考 skill 里 `chainsaw` / `velociraptor` 是**外部工具**（要 subprocess 调用、要单独装、要处理版本兼容）。hvv-defender 把 **316 条规则**（68 traffic + 22 evtx + 36 webshell + 48 persistence + 38 sysmon + 60 tool + 51 IOC）打包成 JSON，一次性 Python 加载。运行时只需一个 `python3` 进程，不 subprocess、不联网。

3. **强制统一 8 字段输出契约** — 参考 skill 的告警输出格式**散在 markdown 里**，字段依赖 LLM 自由格式化。hvv-defender 在**脚本层**强制输出 `id / severity / category / evidence+行号 / rule_id / false_positive_prob / recommended_action / iocs` 8 字段，可直接管道到下游 SOAR / SIEM。

4. **脱敏内置到运行时管道** — 参考 skill 一般提示 "handle PII carefully"，但脱敏靠 LLM 自觉。hvv-defender 所有 stdout 强制过 `desensitize.py`（IP /24 保留 + 用户名首字符 + 内部域名占位符 + Hash 直通），是**运行时行为**而非文档建议。

5. **CLI 层的合规护栏** — remote 模式的 `ssh_probe.py` 在**每次调用**都强制 `--authorized-by` 必填 + 白名单 cmd_id 校验 + `audit.jsonl` 追加 + tee-fork 会话录制。参考 skill 讲授权流程但**没有落到 CLI 层强制**——用户可以跳过；hvv-defender 跳不过（脚本会拒绝启动）。

6. **三层白名单 Tier 分级 + 默认关处置类** — 参考的 IR 采集 skill（`velociraptor` 类）没有分级授权模型。hvv-defender 的 59 条远程命令分 Tier 1 只读（40 条默认开）/ Tier 2 采集（8 条默认开+审计）/ Tier 3 处置（11 条**默认关**，需 `--allow-mutating` + 客户口头二次确认），在**运行时**用一个 `allow_mutating` 布尔位控制处置命令的可用性。

7. **跨规则关联升级（R-TRAF-999 关联簇）** — 参考 skill 是原子的，一条规则命中就 emit 一条告警。hvv-defender 的 `traffic_anomaly.py` 在运行时追踪 `src_ip → [rule_ids]`，同一 src_ip 命中 ≥3 条不同 R-TRAF 规则时**自动升级严重度**并 emit `R-TRAF-999` 关联簇告警。

8. **规则 ID 命名空间 + 反查索引** — 参考 skill 告警没有统一 emit 编号，事后追溯只能靠 grep 关键词。hvv-defender 所有 emit 都带前缀（`R-TRAF-xxx` / `R-WIN-xxx` / `PLB-xxx` / `SIG-xxx` / `CHECK-*` / `IOC-*` / `VENDOR-*` / `SESSION-AUDIT-*`），可通过 [`references/rule-id-namespaces.md`](references/rule-id-namespaces.md) 反查规则定义位置。

9. **一键采集 + 多源时间线合并** — 参考 skill 采集 / 时间线是**分散的独立 skill**（要跨 skill 组合）。hvv-defender 的 `linux_quick_check.sh` + `windows_quick_check.ps1` 一键采集所有 14 章清单需要的 artifact，`timeline_build.py` 一次合并 auth + web + syslog + cron 四源到统一时间轴。

10. **一致的错误码与退出语义** — 参考 skill 大多是纯 markdown 指引，没有可编排的退出码。hvv-defender 每个脚本约定退出码（`0` 干净 / `1` 数据缺失 / `2` 授权失败 / `3` 白名单校验拒绝），便于外部编排。

**致谢**：mukul975/Anthropic-Cybersecurity-Skills 的框架映射方法（每个 skill 挂 MITRE ATT&CK ID）值得借鉴。**未来的版本 v0.5+ 计划在**每条 `R-*` / `PLB-*` 规则**上补充 MITRE ATT&CK Technique ID + NIST CSF 引用**，与该生态互通。

---

## 路线图

- ✅ v0.1 — MVP 三模式（monitor / audit / ir）+ 5 playbook + 8 脚本 + 51 IOC
- ✅ v0.2 — traffic 模式（pcap）+ 86 条流量特征
- ✅ v0.2.1 — `hvv_init.sh` 一键环境初始化
- ✅ v0.3-M1 — 4 家厂商告警研判 + Windows 主机 IR 全套 + 流量规则深化到 126 条
- ✅ **v0.4-M0（当前）** — remote 第 5 模式 + 59 条 3-tier 白名单 + 会话审计
- 🔜 v0.3-M2 — phishing / ransomware / data-exfil / 0day-emerge / AD 攻击 playbook
- 🔜 v0.5 — 规则映射 MITRE ATT&CK Technique ID · MCP 工具化 · 情报 API 接入
- 🔜 v0.6+ — AI 辅助规则挖掘 · 告警根因分析 · 多主机集群模式

详细版本历史见 [`references/CHANGELOG.md`](references/CHANGELOG.md)。

---

## 贡献指南

欢迎反馈误报 / 漏报 / 缺失的攻击类型、贡献新规则和 playbook。

- **Bug / 误报**：开 issue，附（脱敏后）样本 + 规则 ID + 期望行为
- **新增规则**：流量规则加到 `data/traffic-signatures.json`（走 `SIG-TRAF-*`）· webshell 加到 `data/webshell-patterns.json` · Windows 持久化加到 `data/windows-persistence-patterns.json`，附样本 + false-positive rate 评估
- **新增 playbook**：在 `references/playbooks/` 下新建 `<attack-type>.md`，遵循已有格式（特征 / 查询 / 止血 / 根除 / IOC 五节）
- **PR 规范**：单一目的 · 变更规则数量时同步更新 SKILL.md / README 计数 · 涉及远程命令必须说明 Tier 分级 + 关联 CHECK-* + 二次冒烟

**安全漏洞不要开 public issue**（脱敏被绕过 / 白名单校验漏洞 / 命令注入等），邮件到维护者。

---

## License & 免责声明

[Apache License 2.0](LICENSE) © ClinininSec。特征库中的 IOC / 规则来自公开威胁情报报告与研究。

**本工具用于合法授权范围内的蓝队防守作业。** 使用者必须在获得客户书面授权的前提下使用，尤其 remote 模式的远程连接与命令执行。工具不输出可复现的攻击 PoC。使用者需自行承担因未授权使用 / 误操作 / 违反客户合规导致的一切后果。

<p align="center">
  <sub>Built for blue team engineers, by blue team engineers. · <a href="https://github.com/ClinininSec/BlueTeamSkill/issues">Issues</a> · <a href="https://github.com/ClinininSec/BlueTeamSkill/pulls">PRs welcome</a></sub>
</p>
