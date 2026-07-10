# IR 模式 —— 应急响应详细流程

> 应用场景：怀疑或确认主机失陷后的取证、攻击链还原、事件报告。
> 关联：分级 `../grading.md`、脱敏与红线 `../compliance.md`、主机核查清单 `../ioc-checklist/linux-host-check.md`。

---

## 一、何时进入 ir

用户措辞匹配：
- 名词类：「应急」「失陷」「入侵」「事件报告」「攻击链」「取证」「IR」
- 动词类：「排查这台机器」「怀疑被打了」「机器中招」「出一份报告」
- 上游触发：monitor 命中 P0（webshell drop / 暴破成功 / fastjson RCE 成功）
- 显式：`/hvv-defender ir --host <ip>`

反例：
- 用户只是想审计日志看看 → audit
- 用户只是想看告警分诊 → monitor
- 用户没确认主机失陷只是「最近异常多」→ 先 audit

---

## 二、入场前对齐（强制 3 问）

进入 ir 后必须先与用户对齐以下三项，**未对齐不开始任何采集动作**：

### Q1：客户是否已书面授权采集？

- 必须有客户工单 / 邮件 / 群消息授权
- Skill 不会替用户登录客户主机，但跑采集脚本仍是「主机本地写操作」，必须授权
- 如未授权 → Skill 直接拒绝执行，提示用户先取得授权

### Q2：主机当前状态？

- **在线 + 业务运行中**：优先内存取证，慎做断网 / 断电
- **已断网隔离**：可放心做磁盘级采集
- **已下线**：磁盘镜像，离线分析

### Q3：是否需要保留快照 / 内存镜像？

- 业务可中断：建议先做 `vmware snapshot` 或 KVM 内存 dump
- 业务不可中断：跳过内存取证，只做轻量采集（`linux_quick_check.sh` 已避免高 IO 操作）

**话术示例**：

> 在跑采集之前确认三件事：
> 1. 是否已取得客户对该主机的取证授权（工单号 / 邮件均可）？
> 2. 主机当前是在线运行、已隔离、还是已下线？
> 3. 是否需要先做主机快照保留现场？跑采集脚本会读 `/proc` 和 `/var/log`，不会写客户业务目录。

---

## 三、采集阶段

### 3.1 Linux 主机一键采集

引导用户在客户主机本地执行：

```bash
bash scripts/linux_quick_check.sh -o /tmp/hvv-collect-<host>.tar.gz
```

**采集内容**（详见脚本本身）：
- 系统基本信息（uname / uptime / cpuinfo / meminfo / df）
- 当前进程 + 网络连接（ps auxf / ss -anptu / netstat）
- 用户账号（/etc/passwd / /etc/shadow 仅 hash 列 / lastlog / w / last -50）
- 计划任务（crontab -l for each user / /etc/cron.* / /etc/at.spool）
- systemd 服务（systemctl list-units --type=service）
- SSH 状态（/etc/ssh/sshd_config / authorized_keys for each user）
- bash_history（每个用户最近 500 行）
- 最近修改文件（find / -mtime -7 -type f，排除 /proc /sys /tmp 的某些子目录）
- SUID 文件（find / -perm -4000 -type f）
- web 目录文件清单（用户自填路径，默认 `/var/www` / `/usr/share/nginx/html`）
- 关键日志副本（/var/log/auth.log* / messages* / secure* / nginx/* / cron*）

**回传方式**：用户把 tar.gz 拷到本地 Skill 工作目录，告知 Skill 路径。

### 3.2 Windows 主机

不内置自动化脚本，引导用户手动采集：

- `Get-WinEvent -LogName Security`（导出 evtx-csv）
- `Get-Process | Export-Csv`
- `Get-NetTCPConnection`
- `Get-LocalUser`
- `schtasks /query /v /fo CSV`
- `Get-Service`
- `Get-ChildItem C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent`
- 浏览器历史 / Powershell history

回传 ZIP 即可。

---

## 四、核查阶段

收到回传压缩包后，主会话解压到 `/tmp/hvv-ir-<host>/`，逐项核查。

**核查清单**：见 `references/ioc-checklist/linux-host-check.md`（含 30+ 项），本节不重复内容。

**核查方式**：
- 主会话用 Grep / Read 直接看文件，不需要再连主机
- 命中可疑项 → 抽到 `findings.jsonl`
- 不确定项 → 标 `need_human_review`，让用户人工确认

**子 agent 介入**：核查项 ≥ 15 项 或 单项需深度对比 → 调用 `agents/ir-investigator` 子 agent 处理，主会话只接收结论。

---

## 五、时间线构建

把多源时间戳合并为统一时间线：

```bash
python3.11 scripts/timeline_build.py \
  --auth /tmp/hvv-ir-<host>/var/log/auth.log \
  --nginx /tmp/hvv-ir-<host>/var/log/nginx/access.log \
  --syslog /tmp/hvv-ir-<host>/var/log/messages \
  --cron /tmp/hvv-ir-<host>/cron-snapshot.txt \
  --bash-history /tmp/hvv-ir-<host>/bash_history/* \
  --output /tmp/hvv-ir-<host>/timeline.csv
```

**输出字段**：`ts / source / actor / action / target / evidence_line`

### 时间线关注点

1. **入口点附近**（已知或疑似入口时间前后 30 分钟）：
   - nginx access 的异常请求
   - 同时段 auth.log 的登录
   - syslog 的服务异常

2. **持久化时间点**：
   - cron / systemd / authorized_keys 修改时间
   - 新增账户时间

3. **横向时间点**：
   - 出站连接首次出现的时间
   - bash_history 中 `ssh` / `scp` / `curl` 内网地址的时间

4. **数据动作时间点**：
   - 大文件读 / 写
   - 出站流量峰值

---

## 六、攻击链还原（MITRE ATT&CK 映射）

将时间线条目映射到 ATT&CK 战术，给出完整画像。每条 finding 至少打一个战术标签。

### ATT&CK 战术枚举（按攻击发展顺序）

| 战术 | 英文 | 典型证据（在驻场场景） |
|---|---|---|
| 侦察 | Reconnaissance | 资产扫描器 UA 在 nginx 出现 / 端口扫描 |
| 资源开发 | Resource Development | 攻击者 C2 域名注册（多来自外部情报，不直接判定） |
| 初始访问 | Initial Access | 漏洞利用成功（fastjson/log4j RCE 触发） / 弱口令登录 / phishing 落地 |
| 执行 | Execution | webshell 命令执行 / cmd.exe / powershell / bash 异常调用 |
| 持久化 | Persistence | cron / systemd 服务 / authorized_keys / 启动项 / WMI 订阅 |
| 提权 | Privilege Escalation | sudo 滥用 / SUID 程序 / 内核漏洞 / token 盗用 |
| 防御绕过 | Defense Evasion | 清日志 / 改时间戳 / 加密 webshell / 文件名伪装 |
| 凭据访问 | Credential Access | mimikatz / SAM dump / shadow 读取 / browser credential 提取 |
| 发现 | Discovery | `whoami` `id` `ifconfig` `arp -a` / 内网段扫描 |
| 横向移动 | Lateral Movement | SSH / RDP / WMI / psexec / cobaltstrike pivot |
| 收集 | Collection | tar 打包 / 数据库导出 / 文件搜索 |
| 命令与控制 | Command and Control | 反向 shell / beacon / DNS 隧道 / 加密外联 |
| 外泄 | Exfiltration | 出站大流量 / 上传到外部存储 / 隧道传输 |
| 影响 | Impact | 加密勒索 / 数据破坏 / 拒绝服务 |

### 还原方式

- 主会话或 `ir-investigator` 子 agent 把 findings 逐条贴 ATT&CK 战术 + 技术 ID（如 T1059.004 Unix Shell）
- 缺哪一战术的证据，主动提示用户：「缺凭据访问环节证据，建议追加查 `/var/log/secure` 是否有 sudo 异常」
- 拼出完整或近似完整的攻击链后输出最终 `incident-report.md`

---

## 七、止血 / 根除 / 恢复 三阶段

参考 SANS IH 流程，但本 Skill 仅出建议清单，**所有动作由客户自己执行**（红线 6）。

### 7.1 止血（Containment）—— 阻止攻击者继续行动

| 动作 | 命令 / 操作（建议） | 风险评估 |
|---|---|---|
| 网络隔离 | iptables DROP 攻击者 IP / vlan 隔离主机 | 业务连接断开，需先确认 |
| kill 恶意进程 | `kill -9 <PID>`（用户在客户主机执行） | 若是业务进程，慎杀 |
| 禁用沦陷账号 | `passwd -l <user>` / `usermod -L <user>` | 检查是否有合法业务依赖 |
| 删除 / 移走 webshell | 先 `cp` 到隔离目录再 `mv` 原文件到 `.quarantine`，**不直接删** | 保留取证 |
| 切断 C2 | iptables 封 dst IP 段 | 注意误封正常出站 |
| 撤销可疑 token / cookie | 业务侧操作 | 客户运维配合 |

### 7.2 根除（Eradication）—— 清除攻击者残留

- 清除 cron / systemd / authorized_keys 中的所有恶意条目（逐条列给客户）
- 修复入口漏洞（升级 OA / 关闭未授权端口 / 补丁 fastjson 等组件）
- 轮换所有可能泄露的凭据：
  - 该主机及关联主机的 root / admin 密码
  - SSH 私钥（包括 authorized_keys 中其他主机的 key）
  - 数据库密码
  - API token
  - 应用 session secret
- 全盘扫 webshell（playbook/webshell）确认无遗漏
- 同版本同组件的兄弟主机一并审计（横向影响面）

### 7.3 恢复（Recovery）—— 业务恢复到清洁基线

- 优先：从备份 / 镜像回滚到清洁状态
- 次选：在隔离环境重建主机后切流
- 最后选项：原机清理（残留风险高，仅在不可重建时）
- 恢复后监控 7 天：
  - 同 IP / UA / hash 是否再次出现
  - 关联主机是否出现类似异常
  - 出站连接是否复现 C2

---

## 八、沟通话术

### 8.1 通报时机

| 通报对象 | 时机 |
|---|---|
| 现场带队 | 任何 P0 立即口头 + 5 分钟内文字 |
| 客户安全负责人 | P0 确认后 ≤ 30 分钟 |
| 客户业务侧 | 涉及业务中断时同步告知 |
| 监管单位 | 按客户 / 演习规则触发（演习中通常带队统一通报） |

### 8.2 通报内容 do / don't

**do**：
- 时间线（什么时间发现 / 什么时间确认）
- 影响面（受影响主机数 / 业务模块）
- 当前状态（已隔离 / 处置中 / 待客户决策）
- 下一步动作（明确谁做什么）
- 证据可用性（脱敏证据已就绪可供监管单位调取）

**don't**：
- 不未脱敏发原始日志到工作群
- 不发未确认的攻击者画像（误导监管）
- 不在公开渠道（朋友圈 / 微博）讨论事件
- 不替客户做决策（隔离 / 断网由客户决定，Skill 只出建议）
- 不口头透露给非授权人员（包括同事中未参与本项目的人）
- 不在通报里包含 PoC（红线 3）

---

## 九、incident-report 大纲（≥ 12 节）

最终输出 `assets/incident-report.md` 渲染，建议结构：

1. **执行摘要**（一段话，给到最高领导看）
2. **事件信息**：时间线起止 / 受影响主机 / 业务影响 / 当前状态
3. **入口点**：利用的漏洞 / 弱口令 / phishing 路径
4. **立足点**：webshell / 持久化机制 / 后门账号
5. **提权路径**（如有）
6. **横向移动**（如有）：跨主机/账号画像
7. **数据动作**：是否有数据收集 / 外发，量级估算
8. **C2 与外联**：通信通道 / 域名 / IP
9. **攻击链 ATT&CK 映射**：表格按战术列出 finding
10. **IOC 清单**：标准 schema 全量 IOC（脱敏后）
11. **处置过程**：止血 / 根除 / 恢复 三阶段实际动作 + 时间戳
12. **改进建议**：长期加固项（架构 / 流程 / 监控）
13. **附录**：原始证据索引（行号引用，便于审计回溯）

每节都必须基于 findings 而非"经验感觉"；缺证据的小节明确写「证据不足，待进一步取证」。

---

## 十、6 步流程总览

1. **入场对齐**（3 问 + 授权确认）
2. **采集**（用户跑 `linux_quick_check.sh` 回传 tar.gz）—— 采集包完整性异常（14文件缺失/关键字段全空）触发检查点 A
3. **核查**（按 `linux-host-check.md` 逐项，可拆给 `ir-investigator` 子 agent）

   > **🔍 检查点 A（审核）**：本步完成后**必跑** `agents/checkpoint-reviewer`（确定性步骤仅异常时触发）。审核核查结果合理性 + 采集包完整性 + 异常信号。审核通过进检查点 B。

4. **时间线**（`scripts/timeline_build.py`）—— 确定性步骤，异常时触发检查点 A
5. **攻击链还原**（ATT&CK 映射，`ir-investigator`）—— **必跑**（检查点 B 决策）

   > **✅ 检查点 C（验证）**：出 incident-report 前**必跑** `agents/verdict-validator` 验证 verdict 证据闭环 + 攻击链时间线自洽。rejected 打回检查点 B 重做。

6. **脱敏 + 渲染 incident-report**

子 agent 介入：
- 核查项多、时间线行数大（> 50k）→ 调 `ir-investigator`（核查 / 时间线阶段）
- 攻击链还原（步骤 5）`ir-investigator` **必跑**（检查点 B 决策），不再按事件复杂度可选

---

## 十一、与 monitor / audit 的衔接

- monitor 命中 P0 → 直接升级进 ir，复用已有 IOC
- audit 找到 webshell 行为证据 → 升级进 ir，复用关联 IP 列表
- ir 完成后：把新 IOC 反哺回 IOC 库，供后续 monitor / audit 使用

---

## 十二、收尾：统一终报 + findings.json

ir 攻击链还原 + 三阶段处置完成后，**必须**输出跨模式统一终报与机器可读伴生文件（见 `SKILL.md §输出契约`）。ir 形态是终报最厚变体：

- **`final-report.md`（ir 形态，最厚）**：按 `assets/final-report.md` 渲染，所有节必填——
  - §2 判定与影响：verdict = `confirmed_intrusion` / `high_suspicion` / `inconclusive`，全字段（dwell time / compromised_count / data_exfil / persistence_status）
  - §3 攻击路径地图：渲染为**完整 MITRE kill chain**（最多 13 节点），直接取 `agents/ir-investigator` 的 `kill_chain`
  - §4 分层发现详情：P0/P1 全文 8 字段卡 + 攻击路径评分
  - §5 证据与时间线：T+0:00 时间线模拟 + 检测空窗分析
  - §7 处置建议与优先级：完整 止血/根除/恢复 三阶段表 + MRS + 验证清单
  - §10 附件：`incident-report.md`（ir 完整 12 节详尽报告，作终报的详尽附件）/ `ioc-extract.md` / `timeline-merged.ndjson` / 采集包
- **`findings.json`**：按 `assets/findings-schema.md` 生成，`mode=ir`，`findings[]` 含 8 字段 + blast_radius + confidence，`attack_paths[]` 必填（消费 ir-investigator 的 kill_chain），`dwell_time_hours` 必填

> ir 形态终报是"事件结论封面"；`incident-report.md`（§九大纲）是详尽 12 节正文，作为终报附件。两者字段对应：终报 §3 = incident-report §4，终报 §4 = incident-report §2/§8，终报 §7 = incident-report §6。

---

## 相关引用

- 主机核查清单：`../ioc-checklist/linux-host-check.md`
- 攻击特征库：`../attack-patterns/`
- 处置剧本：`../playbooks/`
- 统一终报：`../../assets/final-report.md`（ir 形态）+ `../../assets/findings-schema.md`
- 详尽附件：`../../assets/incident-report.md`（ir 12 节正文）
- 分级 SLA：`../grading.md`
