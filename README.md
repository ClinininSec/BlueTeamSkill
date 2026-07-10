# hvv-defender · 护网蓝队作战 Skill

<p align="center">
  <a href="https://github.com/ClinininSec/BlueTeamSkill/blob/main/LICENSE"><img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-green"></a>
  <img alt="platform" src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20WSL-lightgrey">
  <img alt="python" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="tshark" src="https://img.shields.io/badge/tshark-required%20for%20traffic-orange">
  <img alt="claude-code" src="https://img.shields.io/badge/Claude%20Code-Skill-purple">
</p>

> 面向**蓝队人员**的 Claude Code Skill — 把 SIEM 分诊、日志审计、pcap 流量分析、应急响应、授权 SSH 远程采集五件事合并成一个「Coding Agent 副驾驶」。
>
> **五模式**（monitor / audit / traffic / ir / remote）· **2400+ 条规则运行时** · **6 个 LLM 子 agent 三角色检查点闭环** · **每条结论必附证据** · **远程命令四要素护栏**

---

## 目录

- [是什么 / 为什么](#是什么--为什么)
- [五模式一览](#五模式一览)
- [LLM 三角色检查点](#llm-三角色检查点)
- [快速开始](#快速开始)
- [使用示例](#使用示例)
- [项目结构](#项目结构)
- [输出契约](#输出契约)
- [合规与红线](#合规与红线)
- [规则源同步](#规则源同步)
- [Credits & Prior Art](#credits--prior-art)
- [贡献指南](#贡献指南)
- [License & 免责声明](#license--免责声明)

---

## 是什么 / 为什么

**护网期间蓝队人员的日常工作**可以拆成五类：告警分诊、日志审计、流量抓包分析、应急响应取证、远程主机采集。每类都有一套**手工流程 + 工具脚本 + 经验规则**，蓝队人员在项目现场需要在这五类之间不停切换、记忆规则、复制命令。

**`hvv-defender`** 是一个 **Claude Code Skill**（可理解为「有工具、有剧本、有运行时规则库的 AI 副驾驶」），把这五类整合到统一的**自然语言接口**下：

- 你说「帮我分诊这批告警」→ 进 monitor 模式
- 你说「审计 nginx 排查 webshell」→ 进 audit 模式
- 你说「分析这个 pcap 里有没有 fscan」→ 进 traffic 模式
- 你说「这台机器怀疑被入侵」→ 进 ir 模式，还原攻击链
- 你说「远程 SSH 拉客户机」→ 进 remote 模式（授权+白名单+审计+录制）

每个模式背后是**知识库 + 规则脚本 + LLM 检查点 + 输出模板**的组合。脚本负责确定性检测，LLM 负责审核/决策/验证——两者在每个关键节点交替，不是纯规则流水线，也不是纯 LLM 空谈。

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

## LLM 三角色检查点

五模式工作流不是"纯脚本流水线 + LLM 可选研判"，而是**关键节点强制 LLM 介入**的三角色闭环：

| 检查点 | 角色 | 承载 agent | 做什么 |
|---|---|---|---|
| **A 审核** | Audit | `checkpoint-reviewer` | 脚本输出后审核命中合理性、剔除误报、识别盲区 |
| **B 决策** | Decision | 模式专属 agent（alert-triage / log-analyzer / traffic-analyst / ir-investigator）| 分级、关联、攻击链还原、verdict |
| **C 验证** | Verify | `verdict-validator` | 出终报前验证证据闭环、报告自洽 |

**确定性步骤放行**：归一化、脱敏、tshark 抠取这类确定性操作正常不调 LLM，仅异常（0 记录/字段全空/非 0 退出）触发审核。**大流量策略**：P2/P3 看聚合统计，P0/P1 抽样 ≤20 条逐条研判，避免逐条调 LLM 击穿预算。闭环：A→B→C，C rejected 打回 B 重做。

详见 [`SKILL.md`](SKILL.md) "LLM 检查点协议"段与各模式文档。

---

## 快速开始

### 环境要求

- macOS / Linux / WSL（Windows 会打印手工安装指引后退出）
- Claude Code（`claude --version` 有输出）
- 依赖：`python3.11` + `tshark`（traffic 必需）+ `sshpass` / `expect`（remote 密码认证可选）+ `pyyaml`（vendor_field_mapper 必需）

### 克隆 & 安装

```bash
git clone https://github.com/ClinininSec/BlueTeamSkill.git
cd BlueTeamSkill
ln -sfn "$(pwd)" ~/.claude/skills/hvv-defender   # Claude Code 自动扫描此目录
bash scripts/hvv_init.sh                          # 一键装依赖
```

`hvv_init.sh` 会探测系统 + 包管理器（brew / apt / dnf / apk / pacman / zypper），装硬依赖（含 `pip install pyyaml`）并二次确认 PATH。**退出码**：`0` 就绪 / 非 0 硬依赖装失败。

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

### 示例 1：告警分诊（monitor）

```
You: 帮我看这批告警 ./alerts-2026-06-30.json,2000 条
Skill:
  [1] log_parser 归一化 → [2] ioc_match 匹配内置 IOC + 工具特征
  [3] 🔍 检查点 A: checkpoint-reviewer 审核命中合理性（P0/P1 抽样逐条）
  [4] 🧭 检查点 B: alert-triage 分诊（必跑）→ P0 3 条 / P1 12 条 / P2 87 条 / P3 1898 条
  [5] desensitize 脱敏 → [6] ✅ 检查点 C: verdict-validator 验证待跟进无漏标
  [7] 渲染 assets/daily-report.md
```

### 示例 2：pcap 流量审计（traffic）

```
You: 分析这个 pcap,防火墙镜像口抓的 30 分钟数据
Skill:
  [1] pcap_parser 六视图归一化: http / dns / tls / flow / creds / conn
  [2] traffic_anomaly 跑 1787 条签名（项目自维护 + OWASP CRS / ET Open 通用规则）
  [3] 🔍 检查点 A: checkpoint-reviewer 审核命中 + 剔除误报（如业务查询触发的 SQLi）
  [4] 🧭 检查点 B: traffic-analyst 跨视图关联攻击链（recon→exploit→C2→tunnel）+ 盲区发现
  [5] ✅ 检查点 C: verdict-validator 验证攻击链时间线自洽
  [6] 输出异常清单 + tshark 定位命令 + 六视图证据
```

### 示例 3：应急响应还原攻击链（ir）

```
You: 192.168.1.50 怀疑被入侵
Skill:
  [1] 引导: 客户主机跑 linux_quick_check.sh,回传 tar.gz
  [2] 按 linux-host-check 14 章核查(进程/账户/网络/cron/authorized_keys/bash_history...)
  [3] webshell_scan 扫 web 目录(40 条特征)
  [4] timeline_build 合并 auth + web + syslog + cron 时间线
  [5] 🔍 检查点 A → 🧭 检查点 B: ir-investigator 还原攻击链（ATT&CK 13 战术）
  [6] ✅ 检查点 C: verdict-validator 验证 verdict 证据闭环
  [7] 输出 incident-report.md: 入口 / 立足点 / 提权 / 横向 / 持久化 / 数据动作 / 止血 / 根除 / 恢复
```

---

## 项目结构

```
BlueTeamSkill/
├── SKILL.md                       ← Claude Code Skill 入口（五模式 + 检查点协议）
├── README.md / LICENSE / requirements.txt / .gitignore
├── agents/                        ← 6 个 LLM 子 agent prompt
│   ├── alert-triage.md            ← monitor 决策（检查点 B）
│   ├── log-analyzer.md            ← audit 决策（检查点 B）
│   ├── traffic-analyst.md         ← traffic 决策（检查点 B）
│   ├── ir-investigator.md         ← ir 决策（检查点 B）
│   ├── checkpoint-reviewer.md     ← 横向审核（检查点 A）
│   └── verdict-validator.md       ← 横向验证（检查点 C）
├── assets/                        ← 6 个输出模板 / schema
│   ├── final-report.md            ← 跨 5 模式统一终报（10 节 spine）
│   ├── findings-schema.md         ← 终报机器可读伴生文件 schema
│   ├── incident-report.md / daily-report.md / handover.md / ioc-extract.md
├── data/                          ← 7 个 JSON 特征库（运行时数据）
│   ├── traffic-signatures.json         ← 1787 条流量签名（含 CRS/ET 同步）
│   ├── sysmon-detection-rules.json     ← 475 条 Sysmon 规则（含 Sigma 同步）
│   ├── tool-signatures.json            ← 60 条攻击工具 UA 特征
│   ├── windows-persistence-patterns.json ← 48 条 Windows 持久化
│   ├── webshell-patterns.json          ← 40 条 webshell 特征（含 YARA 同步）
│   ├── ioc-builtin.json                ← 51 条基线 IOC
│   └── remote-command-whitelist.json   ← 59 条 3-tier 远程白名单
├── references/                    ← 知识库（Claude 按需读取，36 份 md）
│   ├── rule-id-namespaces.md / compliance.md / grading.md / glossary.md
│   ├── modes/                     ← 5 模式详细流程（含检查点落位）
│   ├── playbooks/                 ← 6 类攻击处置剧本 + traffic-audit
│   ├── attack-patterns/           ← 9 份特征知识库
│   ├── log-fields/                ← 10 份日志字段速查（含 4 家国产厂商抽屉）
│   ├── ioc-checklist/             ← Linux 14 章 / Windows 14 章 48 项应急核查清单
│   └── remote-command-whitelist.md ← 3-tier 白名单详细知识库
└── scripts/                       ← 18 个可执行脚本 + feeds/ 同步器
    ├── hvv_init.sh                ← 一键装依赖
    ├── log_parser / ioc_match / nginx_anomaly / auth_log_audit / webshell_scan / timeline_build
    ├── pcap_parser / traffic_anomaly    ← traffic 模式（依赖 tshark）
    ├── evtx_hunt                        ← Windows evtx 22 条 R-WIN 规则
    ├── vendor_field_mapper              ← 4 家厂商字段归一化（依赖 pyyaml）
    ├── desensitize                      ← 输出脱敏（所有 stdout 强制过）
    ├── linux_quick_check.sh / windows_quick_check.ps1  ← 主机一键采集
    ├── remote/                    ← remote 模式（SSH 远程执行）
    │   ├── ssh_probe.py           ← 单命令远程执行（白名单校验 + audit + 录制）
    │   ├── remote_collect.py      ← 组合采集（上传 → 执行 → 回传 → 清理）
    │   └── session_recorder.sh    ← 交互式会话全程录制
    └── feeds/                     ← 规则源同步器（构建期离线拉取）
        ├── sync_owasp_crs.py      ← OWASP CRS → traffic-signatures
        ├── sync_yara.py           ← YARA → webshell-patterns
        ├── sync_et_open.py        ← ET Open → traffic-signatures
        └── sync_sigma.py          ← Sigma → sysmon-detection-rules
```

---

## 输出契约

所有 `R-*` / `PLB-*` 命中都输出**统一 8 字段告警条目**（跨模式一致）：

`id` / `severity` (P0-P3) / `category` / `evidence`（脱敏后原文 + 行号）/ `rule_id` / `false_positive_prob` (0.0-1.0) / `recommended_action` / `iocs`（可空）

IOC schema：`type` / `value`（脱敏）/ `confidence` / `first_seen` / `source` / `tag`

**收尾统一报告**：任意模式得出结论后，输出跨模式一致的 markdown 终报 `assets/final-report.md`（按攻击路径组织，10 节 spine + 模式激活表）+ 机器可读伴生文件 `findings.json`（schema 见 `assets/findings-schema.md`）。

**规则 ID 前缀**（详见 [`references/rule-id-namespaces.md`](references/rule-id-namespaces.md)）：`R-*` 脚本运行时规则 emit · `PLB-*` playbook 建议规则 · `SIG-*` 攻击特征 · `CHECK-*` 主机核查清单 · `IOC-*` / `VENDOR-*` / `SESSION-AUDIT-*` 分类 tag

---

## 合规与红线

### 硬红线

- ❌ **不输出可复现的攻击 PoC payload** — 识别特征只写到"触发字段 + 关键词"层级
- ❌ **不做破坏性 / 不可逆操作** — `rm` / `mv` / `chmod` / `useradd` / `reboot` / `dd` / `iptables -F` / `DROP TABLE` 等命令族全禁
- ❌ **不擅自删除客户主机上的疑似恶意文件** — 只给路径让客户处理，保留取证链
- ❌ **不做横移（lateral pivot）** — 即便取得会话也不允许再 SSH / SCP / SFTP / nc / curl / wget 到第二跳
- ❌ **不发起对外攻击 / 反向探测** — 不扫描客户网络以外资产，不对攻击者源 IP 反向连接

### 远程连接四要素（remote 模式强制）

书面授权（`--authorized-by` 必填）· 白名单命令（匹配 `remote-command-whitelist.json` cmd_id）· 每命令审计（`~/.hvv-defender/audit.jsonl` 追加）· 会话录制（tee-fork 自动到 `~/.hvv-defender/sessions/<host>-<ts>.log`）

**Tier 分级**：Tier 1（40 条只读，默认开）/ Tier 2（8 条采集，默认开+审计）/ Tier 3（11 条处置，**默认关**，需 `--allow-mutating` + 客户口头二次确认）。堡垒机场景降级到 H-I-L（只生成命令清单让人工粘贴）。

### 脱敏（默认开启）

私网 IP 保留 /24 段 · 用户名首字符+长度 · 内部域名 `<internal>` · 客户名 `<customer>` · 敏感路径 `/data/<app>/` · 公网攻击者 IP / hash 不脱敏（IOC 价值高）

完整规则见 [`references/compliance.md`](references/compliance.md)。

---

## 规则源同步

`scripts/feeds/` 下的同步器在**构建期**离线拉取外部通用规则源，转换为项目 `data/*.json` 格式，**运行时零外发**（兼容离线优先）：

| 同步器 | 源 | 目标 | 条数 |
|---|---|---|---|
| `sync_owasp_crs.py` | OWASP CRS | traffic-signatures | +149 |
| `sync_et_open.py` | ET Open (Proofpoint) | traffic-signatures | +1512 |
| `sync_sigma.py` | SigmaHQ | sysmon-detection-rules | +437 |
| `sync_yara.py` | bartblaze YARA | webshell-patterns | +4 |

所有同步器支持 `--local`（指定本地已下载源，跳过克隆）+ `--dry-run`。只提取"触发字段+关键词"层级检测特征，不输出可复现 PoC。详见 [`scripts/feeds/README.md`](scripts/feeds/README.md)。

---

## Credits & Prior Art

本项目在设计上参考了社区蓝队 skill 生态，特别是 [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)（遵循 [agentskills.io](https://agentskills.io) 标准，映射 MITRE ATT&CK / NIST CSF 等框架）。hvv-defender 在运行时行为层面的差异化：

- **五模式单会话升级链** — 把告警分诊→日志审计→流量分析→应急响应→远程采集串成 monitor→audit→traffic→ir→remote 升级链，Claude 单会话跨模式路由
- **LLM 三角色检查点闭环** — 脚本检测后强制 LLM 审核(A)→决策(B)→验证(C)，补齐纯规则流水线缺的误报研判与结论验证；确定性步骤放行 + 大流量批量抽样控制成本
- **规则库脚本化 + 离线优先** — 2400+ 条规则打包成 JSON 一次性加载，运行时只读本地不联网；外部通用源（OWASP CRS / ET Open / Sigma / YARA）构建期同步
- **强制统一 8 字段输出契约** — 脚本层强制输出 8 字段告警，可直接管道到下游 SOAR / SIEM
- **脱敏内置到运行时管道** — 所有 stdout 强制过 `desensitize.py`，是运行时行为而非文档建议
- **CLI 层合规护栏** — remote 模式每次调用强制 `--authorized-by` + 白名单 cmd_id + 审计 + 录制，脚本拒绝跳过
- **三层白名单 Tier 分级** — 59 条远程命令分 Tier 1 只读 / Tier 2 采集 / Tier 3 处置（默认关 + 二次授权）
- **规则 ID 命名空间 + 反查索引** — 所有 emit 带前缀（`R-TRAF-xxx` / `R-WIN-xxx` / `SIG-xxx` 等），可反查规则定义位置

**致谢**：mukul975/Anthropic-Cybersecurity-Skills 的框架映射方法（每个 skill 挂 MITRE ATT&CK ID）值得借鉴。后续可在每条 `R-*` / `PLB-*` 规则上补充 MITRE ATT&CK Technique ID + NIST CSF 引用，与该生态互通。

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
