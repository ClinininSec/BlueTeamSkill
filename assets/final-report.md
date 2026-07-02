# 统一终报 · {{case_id}}

> **模式**：`{{mode}}` | **案件**：`{{case_id}}` | **客户**：`<customer>` | **报告日期**：{{report_date}} | **版本**：v{{report_version}} | **机密等级**：仅限项目组 + 客户授权人
>
> 起草：`<analyst>` | 复核：`<reviewer>` | 客户对接人：`<customer_pm>`

> 本报告是 `hvv-defender` 在**任意模式收尾阶段**产出的跨模式统一结论报告，按**攻击路径**组织（而非按日志源 / 告警类型），从防御者视角回答四个问题：**被入侵了吗 → 从哪进的 → 影响多大 → 怎么处置**。机器可读伴生文件 `findings.json`（schema 见 `assets/findings-schema.md`）与本报告同生，二者字段一一对应。
>
> 模式专属的详尽输出作为**附件**挂在本报告末尾（见 §10）：`incident-report.md`（ir 完整 12 节）/ `daily-report.md`（monitor 运营日报）/ `ioc-extract.md`（IOC JSON）/ `handover.md`（交接备忘）。

---

## 0. 模式激活表

每节在 5 模式下的形态。✅ 必填 · 🔁 变体（按模式填写不同内容）· ⚪ 可选 · ➖ 不适用。

| 节 | monitor | audit | traffic | ir | remote |
|---|---|---|---|---|---|
| §1 执行摘要 | ✅ | ✅ | ✅ | ✅ | ✅ |
| §2 判定与影响 | 🔁 批次判定 | 🔁 异常判定 | 🔁 异常判定 | 🔁 入侵判定 | 🔁 采集判定 |
| §3 攻击路径地图 | 🔁 关联簇 | 🔁 跨源异常链 | 🔁 flow+C2 通道 | 🔁 完整 kill chain | 🔁 采集→发现链 |
| §4 分层发现详情 | ✅ | ✅ | ✅ | ✅ | ✅ |
| §5 证据与时间线 | ⚪ | ✅ | ✅ | ✅ | ⚪ |
| §6 IOC 清单 | ✅ | ✅ | ✅ | ✅ | ⚪ |
| §7 处置建议与优先级 | 🔁 待跟进 | 🔁 修复建议 | 🔁 封堵建议 | 🔁 止血/根除/恢复 | 🔁 Tier 处置(需授权) |
| §8 检测改进 | ✅ | ✅ | ✅ | ✅ | ⚪ |
| §9 元数据与签字 | ✅ | ✅ | ✅ | ✅ | ✅ |
| §10 附件 | ✅ | ✅ | ✅ | ✅ | ✅ |

> **填表原则**：ir 形态最厚（所有节填满）；monitor / remote 形态最薄（§3/§5/§7 取变体轻量形态）。任何模式下 §1/§4/§6/§9/§10 必填。

---

## 1. 执行摘要（Executive Summary）

`{{executive_summary}}`

> 示例（ir 形态）：「2026-06-30 08:31，客户 `<customer>` 对外 OA 系统（`192.168.1.xxx`:8080）经 fastjson 反序列化被获取 web 容器权限，建立 2 处持久化并尝试横向探测同段主机。蓝队 1h12min 后介入，完成封堵 / 清除 / 取证。未发现批量数据外发。dwell time 18.7h。」
>
> 示例（monitor 形态）：「本班次累计告警 1832 条，3 条 P0（fastjson 真实命中 + ssh 暴破成功 + actuator 信息泄露）均已通知客户并临时封堵；12 条 P1 待客户复核；其余 P2/P3 已归档。」

### 关键发现分层计数

| 级别 | 数量 | 处置完成率 | 说明 |
|---|---|---|---|
| 🔴 **P0**（紧急 / 立即可利用） | {{p0_count}} | {{p0_done_rate}} | 立即响应，≤15min 介入 |
| 🟠 **P1**（高危 / 疑似命中） | {{p1_count}} | {{p1_done_rate}} | <1h 响应 |
| 🟡 **P2**（中危 / 待关联） | {{p2_count}} | {{p2_done_rate}} | <4h 跟进 |
| ⚪ **P3**（低危 / 噪音） | {{p3_count}} | — | 归档 |
| **合计** | {{total_findings}} | {{overall_done_rate}} | |

**一句话结论**：`{{verdict_one_liner}}`（例：「存在 {{public_attack_surface}} 个公开攻击面，攻击者无需凭证即可入侵」/「本批次无确认入侵，{{n}} 条 P1 待深挖」）

---

## 2. 判定与影响（Verdict & Impact）

| 项 | 值 |
|---|---|
| **判定 verdict** | {{verdict}} |
| **置信度 confidence** | {{confidence}} |
| **首次入侵 / 异常时间** | {{first_evidence_ts}} |
| **末次活动时间** | {{last_evidence_ts}} |
| **dwell time（小时）** | {{dwell_time_hours}} |
| **影响主机数** | {{compromised_count}} |
| **数据外发** | {{data_exfil}} |
| **持久化清除状态** | {{persistence_status}} |
| **time-to-detect（MTTD）** | {{mean_time_to_detect}} |
| **检测空窗** | {{detection_gap}} |

**verdict 取值**（跨模式统一枚举）：

| verdict | 含义 | 典型模式 |
|---|---|---|
| `confirmed_intrusion` | 已确认入侵 | ir |
| `high_suspicion` | 高度疑似，证据待补 | ir / audit / traffic |
| `inconclusive` | 证据不足，列出还需采集什么 | 任意 |
| `no_intrusion` | 未发现入侵（批次正常 / 异常为误报） | monitor / audit / traffic / remote |

**模式变体**：
- **monitor**：verdict = 批次判定；额外填「误报率 {{fp_rate}}」「待跟进 P1 数 {{pending_p1}}」
- **audit / traffic**：verdict = 异常判定；额外填「异常源数 {{anomaly_source_count}}」「是否升级 ir {{escalate_to_ir}}」
- **ir**：verdict = 入侵判定；§2 全字段填满
- **remote**：verdict = 采集判定；额外填「采集命令数 {{remote_cmd_count}}」「Tier 3 处置数 {{tier3_count}}」

---

## 3. 攻击路径地图（Attack Path Map）

> **整份报告的视觉骨干**。把分散的告警 / 日志 / 证据串成一条（或多条）可读的攻击链。每个节点标 **TTP / 证据来源 / 时间戳**。蓝队用它一眼看穿"最短利用链"；与 `findings.json` 的 `attack_paths[]` 一一对应。

{{attack_path_map}}

### 模式变体

**ir 形态** — 完整 MITRE ATT&CK kill chain（最厚）：

```
攻击者 (外部)
  ↓
[1] T1592 Reconnaissance        nginx-access.log:14201  08:23  扫描 /actuator/* /swagger/*
  ↓
[2] T1190 Initial Access        nginx-access.log:14523  08:31  POST /api/login fastjson 反序列化（PLB-CE-006）
  ↓
[3] T1059.004 Execution         04-processes.txt        08:33  tomcat → bash → curl … | sh
  ↓
[4] TA0003 Persistence          09-persistence.txt      08:35  /etc/cron.d/.update + authorized_keys 新公钥
  ↓
[5] T1070.002 Defense Evasion   auth.log 断档           08:35~09:12  日志清除
  ↓
[6] T1018 Discovery             /tmp/scan_ports.txt     09:11  fscan 探测 192.168.1.0/24
  ↓
[7] TA0011 C2                   05-network.txt          09:30~03:12  <external-ip>:443 长连接 7h
  ↓
路径终点: web 容器权限 + 持久化 + 横向探测（未遂）
```

- **攻击复杂度**：⭐☆☆☆☆（极低，公开 PoC）
- **所需时间**：< 5 分钟到 RCE
- **检测难度**：低（单次请求即可触发告警）

**monitor 形态** — 告警关联簇（CLU-*）：

```
CLU-001 关联簇（同源 src_ip=192.168.1.xxx，08:23~10:24）
  ├─ R-NGX-001   08:23  /actuator/* 探测          P2
  ├─ R-NGX-008   08:31  POST /api/login 异常 body  P1
  └─ PLB-CE-006  08:31  fastjson '@type' 特征      P0  ← 升级
  ↓
簇终点: 升 P0 → 转 ir 取证
```

**audit 形态** — 跨源异常链：

```
[nginx]  src_ip=X  /api/login fastjson 特征   08:31
  ↓ 同源 IP 关联
[auth]   X → root@host  ssh 成功登录          08:34  (R-AUTH-002)
  ↓ 同账号关联
[nginx]  root UA 访问 /admin/ 导出            08:40
  ↓
链终点: web 入口 → 主机登录 → 越权访问
```

**traffic 形态** — flow + C2 通道图：

```
<src_ip> ──HTTP POST @type──→ <oa_host>:8080   R-TRAF-004  (fastjson)
<oa_host> ──TLS JA3=72T──→ <external-ip>:443    R-TRAF-055  (C2 beacon)
<oa_host> ──DNS TXT A记录──→ <c2-domain>        R-TRAF-064  (DNS 隧道)
  ↓
通道终点: C2 心跳 + DNS 隧道双通道
```

**remote 形态** — 采集→发现链 + 已执行 Tier 命令：

```
remote 采集 (Tier 1 只读)
  ├─ ssh_probe: ps auxf          → 发现 tomcat 异常子进程
  ├─ ssh_probe: netstat -tnp     → <external-ip>:443 ESTABLISHED
  └─ ssh_probe: cat /etc/cron.d/ → .update 异常任务
  ↓
发现链终点: 转 ir 分析（remote 拉数据 → ir 定性）
  ↓ (若 ir 定性入侵 + 二次授权)
remote Tier 3 处置（每条记审计）:
  ├─ kill <pid>          R-REM-DISP-KILL  SESSION-AUDIT-*
  └─ iptables block-ip   R-REM-DISP-NNN   SESSION-AUDIT-*
```

---

## 4. 分层发现详情（Tiered Findings）

> 每条发现 = 现有 **8 字段契约**（`id` / `severity` / `category` / `evidence` / `rule_id` / `false_positive_prob` / `recommended_action` / `iocs`）+ `blast_radius` + `confidence` + `mode`。本节是 `findings.json` 的 `findings[]` 直接来源。仅列 P0/P1 全文；P2/P3 汇总计数，明细见附件。

### 🔴 P0 — Critical（立即可利用 / 确认入侵）

#### [P0-001] {{p0_001_title}}

| 字段 | 值 |
|---|---|
| `id` | {{p0_001_id}} |
| `severity` | P0 |
| `category` | {{p0_001_category}} |
| `rule_id` | {{p0_001_rule_id}}（如 PLB-CE-006 / R-NGX-001） |
| `evidence`（脱敏后原文 + 行号） | {{p0_001_evidence}} |
| `false_positive_prob` | {{p0_001_fp_prob}} |
| `recommended_action` | {{p0_001_action}} |
| `iocs`（可空） | {{p0_001_iocs}} |
| `blast_radius` | {{p0_001_blast}}（如：完整服务器控制 / 10万+用户 PII） |
| `confidence` | {{p0_001_confidence}} |

**攻击路径评分**（借参考模板，防御者用于排处置优先级）：

| 维度 | 取值 | 加分 |
|---|---|---|
| 认证要求 | 无需登录 / 普通用户 / 管理员 | +3 / +2 / +1 |
| 请求复杂度 | 单请求 / 多步骤 | +3 / +2 |
| 关联证据 | 多规则命中 / 单规则 | +3 / +1 |
| 利用门槛 | curl 即可 / 需工具 | +3 / +2 |
| **总分** | → 映射 P0(≥9) / P1(≥7) / P2(≥5) / P3(<5) | {{p0_001_score}}/12 |

> 评分仅用于优先级排序，不替代人工研判；与 `grading.md §四` 加权公式一致。

**修复优先级**：🔴 24h 内 · **修复成本**：{{p0_001_fix_cost}}

---

#### [P0-002] {{p0_002_title}}
…（同结构）

### 🟠 P1 — High（疑似命中 / 高价值线索）

#### [P1-001] {{p1_001_title}}
…（同 8 字段卡 + 评分；可简化 blast_radius 描述）

### 🟡 P2 / ⚪ P3 汇总

| 级别 | 数量 | 主要 rule_id 簇 | 处置 |
|---|---|---|---|
| P2 | {{p2_count}} | {{p2_rule_clusters}} | 观察名单，关联升级触发即升 P1 |
| P3 | {{p3_count}} | {{p3_rule_clusters}} | 批量归档 |

---

## 5. 证据与时间线（Evidence & Timeline）

### 5.1 关键时间节点

| 时间 | 事件 | 证据来源 | 模式 |
|---|---|---|---|
| {{t1}} | {{t1_event}} | {{t1_source}} | {{t1_mode}} |
| {{t2}} | {{t2_event}} | {{t2_source}} | {{t2_mode}} |
| … | | | |

### 5.2 攻击时间线模拟（防御者视角）

> 借参考模板的 T+0:00 模拟，但框定为 **time-to-compromise vs time-to-detect**，量化检测空窗。

```
T+0:00  攻击者首次侦察（nginx /actuator/* 探测）         ← 攻击起点
T+0:08  Initial Access 成功（fastjson RCE）              ← 沦陷点
T+0:12  持久化部署（cron.d + authorized_keys）
T+0:40  横向探测开始
T+18.7h C2 心跳末次活动
---
T+1.2h  蓝队首次告警（基于 SIEM）                        ← 检测点
T+1.5h  封堵完成
T+5.3h  取证完成
---
检测空窗(detection_gap): 1.2h  ← 攻击成功到首次告警的差值
MTTD: 1.2h   MTTR(封堵): 18min
```

**检测空窗分析**：{{detection_gap_analysis}}（例：「fastjson 单次请求未触发 SIEM 规则，直至 C2 长连接 1h 后才告警——建议补 RCE 单请求检测规则」）

### 5.3 证据完整性

- [ ] 所有 evidence 行号可回溯到原始日志 / 采集包
- [ ] 时间线已用 `timeline_build.py` 合并去重
- [ ] 证据副本已脱敏（`desensitize.py --mode strict`）

---

## 6. IOC 清单

完整 IOC 列表见附件 `iocs-{{case_id}}.json`，遵循 `assets/ioc-extract.md` 7 字段 schema。本案核心 IOC 汇总：

| type | value（脱敏） | confidence | tag | 关联 finding |
|---|---|---|---|---|
| ip | `<external-ip>` | high | c2:confirmed | P0-001 |
| domain | `<external-domain>` | high | c2:confirmed | P0-001 |
| path | `/tmp/.X11-lock` | high | persistence:backdoor | P0-001 |
| ua | `Apache-HttpClient` | medium | tool:suspect | P1-001 |
| … | | | | |

| 类型汇总 | 数量 |
|---|---|
| ip / cidr | {{ioc_ip_n}} |
| domain / url | {{ioc_dom_n}} |
| hash | {{ioc_hash_n}} |
| ua / tool | {{ioc_ua_n}} |
| path / file | {{ioc_path_n}} |
| **合计** | {{ioc_total}} |

> **导入 SIEM**：`iocs-*.json` 直接 import Splunk lookup / ELK `_source` / QRadar CSV（见 `ioc-extract.md §5`）。

---

## 7. 处置建议与优先级（Remediation & Priority）

### 7.1 最小修复集（MRS — Minimum Remediation Set）

> 借参考模板：如果只能处置 N 项，优先这些——阻断最高 ROI 的攻击路径。

1. **[P0-001] {{mrs_1}}** —— 阻断公开 RCE 入口
2. **[P0-002] {{mrs_2}}** —— 阻断横向 / 数据泄露
3. **[P1-001] {{mrs_3}}** —— 收口高价值线索

**修复这 N 项可消除 {{mrs_coverage}}% 的关键攻击面。**

### 7.2 模式变体

**ir 形态** — 完整 止血 / 根除 / 恢复（最厚）：

| 阶段 | # | 动作 | 状态 | owner | 截止 |
|---|---|---|---|---|---|
| 止血 | 1 | 出口防火墙封禁 `<external-ip>` | done | 客户网络组 | {{t}} |
| 止血 | 2 | 8080 对外封禁 / 加 WAF | done | 客户网络组 | {{t}} |
| 止血 | 3 | kill 异常 PID + 关停 tomcat | done | 客户主机组 | {{t}} |
| 根除 | 1 | 删除 `/tmp/.X11-lock` / `/etc/cron.d/.update` | done | 客户主机组 | |
| 根除 | 2 | 清理 authorized_keys 未知公钥 | done | 客户主机组 | |
| 根除 | 3 | 升级 fastjson / 上 patch | in_progress | 客户应用组 | {{t}} |
| 恢复 | 1 | 保留快照 → 清洁备份恢复 | done | | |
| 恢复 | 2 | 灰度恢复对外（内网 1h → 外网） | planned | | {{t}} |

**monitor 形态** — 待跟进列表：

| # | 关联告警 ID | 主题 | 阶段 | 责任方 | 截止 |
|---|---|---|---|---|---|
| 1 | MON-001 | fastjson → ir 取证 | 取证中 | 蓝队 + 客户 OA owner | {{t}} |
| 2 | MON-005 | sqli 疑似命中 | 待客户复核 | 客户应用组 | {{t}} |

**audit / traffic 形态** — 修复 / 封堵建议（清单，未执行）：
- {{fix_1}}（owner: 客户运维 / 截止 {{t}}）
- {{fix_2}}（owner: 客户应用组）

**remote 形态** — Tier 处置（需二次授权 + 审计 + 录制四要素）：

| Tier | 命令 | rule_id | 审计 ID | 授权状态 |
|---|---|---|---|---|
| 3 | kill `<pid>` | R-REM-DISP-KILL | SESSION-AUDIT-* | ✅ 已二次授权 |
| 3 | iptables block `<ip>` | R-REM-DISP-NNN | SESSION-AUDIT-* | ✅ 已二次授权 |

> remote Tier 3 默认关；触发需 `--allow-mutating` + 客户书面授权 + 每命令审计 + 会话录制。见 `references/compliance.md §红线 4`。

### 7.3 验证清单（恢复服务前逐项 PASS）

- [ ] 入口端口 / 暴露面已收敛
- [ ] 异常进程 / 子进程已清除
- [ ] 持久化点（cron / systemd / authorized_keys）全账户已审查
- [ ] /tmp /var/tmp /dev/shm 无异常文件
- [ ] 外联 30 天滚动监控无 IOC 命中
- [ ] 审计日志完整性已启用

---

## 8. 检测改进（Detection Improvement）

> 蓝队专属（参考模板无）。把本次发现转化为可落地的检测能力增量。

### 8.1 SIEM 规则缺口

| 缺口 | 建议规则 | 关联 finding |
|---|---|---|
| fastjson 单请求未告警 | `'@type'` 字段 + 200 状态 触发 P0 | P0-001 |
| C2 长连接检测滞后 | 同 src-dst TLS 连接 > 1h 且无业务域名 | P0-001 |
| {{gap_3}} | {{rule_3}} | {{f_3}} |

### 8.2 内置 IOC 库增量

需追加到 `data/ioc-builtin.json`（供 `ioc_match.py --builtin` 加载）：

| type | value | tag | confidence |
|---|---|---|---|
| ip | `<external-ip>` | c2:confirmed | high |
| domain | `<external-domain>` | c2:confirmed | high |
| hash:sha256 | `<sha256>` | malware:dropper | medium |

### 8.3 Playbook / 核查清单引用

- 处置剧本：`references/playbooks/{{playbook_ref}}.md`（如 `command-exec.md` / `webshell.md`）
- 主机核查：`references/ioc-checklist/{{checklist_ref}}.md`
- 规则学习：{{rule_learning_note}}

---

## 9. 元数据与签字

| 字段 | 值 |
|---|---|
| `case_id` | {{case_id}} |
| `mode` | {{mode}} |
| `customer` | `<customer>`（脱敏） |
| `skill_version` | hvv-defender@{{skill_version}} |
| `report_version` | v{{report_version}} |
| `report_date` | {{report_date}} |
| `desensitized` | ✅ true（已过 `desensitize.py --mode strict`） |
| `findings_json` | `findings-{{case_id}}.json`（schema: `assets/findings-schema.md`） |
| `analyst` | `<analyst>` |
| `reviewer` | `<reviewer>` |

| 角色 | 姓名 | 日期 | 签字 |
|---|---|---|---|
| 起草（蓝队） | `<analyst>` | {{report_date}} | |
| 复核（蓝队 lead） | `<reviewer>` | {{report_date}} | |
| 客户对接人 | `<customer_pm>` | {{report_date}} | |
| 客户合规复核 | `<customer_compliance>` | {{report_date}} | |

---

## 10. 附件

| 附件 | 说明 | 适用模式 |
|---|---|---|
| `incident-report.md` | ir 完整 12 节详尽报告（本终报为封面，此为详尽附件） | ir |
| `daily-report.md` | monitor 运营日报（告警分级统计 / 时序趋势 / 交接备忘） | monitor |
| `ioc-extract.md` | IOC JSON schema 规范（`iocs-{{case_id}}.json` 遵此） | 全模式 |
| `handover.md` | 值守交接备忘录（24h 滚动交班） | monitor |
| `findings-{{case_id}}.json` | 机器可读伴生文件（schema: `assets/findings-schema.md`） | 全模式 |
| `timeline-merged.ndjson` | `timeline_build.py` 合并时间线 | ir / audit |
| `hvv-collect-<host>-<ts>.tar.gz` | `linux_quick_check.sh` / `windows_quick_check.ps1` 原始采集包 | ir / remote |
| `webshell-scan.json` / `traffic-anomaly.json` / `evtx-hunt.json` | 各检测脚本原始输出 | audit / traffic / ir |
| `sessions/*.log` | remote 会话录制（Tier 3 处置审计） | remote |
| `evidence-images/` | 截图证据（如有） | 全模式 |

---

> **脱敏自证**：本报告所有 IP / 用户名 / 域名 / 客户名 / 内部路径已通过 `scripts/desensitize.py --mode strict` 强制脱敏；`desensitized=true`。未脱敏版本仅在客户加密渠道（密码学保护）内流转。
>
> **红线遵守**：本报告不含可复现的攻击 PoC payload（识别特征只写到"触发字段 + 关键词"层级）；不做破坏性 / 不可逆操作（处置动作清单仅供客户执行）；不做横移；不反向探测攻击者。
>
> 本报告由 `hvv-defender` v{{skill_version}} 生成草稿，攻击链还原 / 告警分诊 / 日志分析使用 `agents/{ir-investigator,alert-triage,log-analyzer}` 子 agent，蓝队人工二次复核 + 修订定稿。

---

## 模板变量速查

| 变量 | 含义 | 来源 |
|---|---|---|
| `{{case_id}}` | 案件编号 | 模式前缀+日期（MON-/AUD-/TRAF-/IR-/REM-） |
| `{{mode}}` | 来源模式 | monitor / audit / traffic / ir / remote |
| `{{customer}}` | 客户标识（脱敏） | `<customer>` |
| `{{report_date}}` `{{report_version}}` | 报告日期 / 版本 | |
| `{{skill_version}}` | skill 版本 | 当前 v0.4-M1 |
| `{{verdict}}` `{{confidence}}` | 判定 / 置信度 | verdict 枚举 + 0.0-1.0 |
| `{{dwell_time_hours}}` | 驻留时长 | ir-investigator.kill_chain 首末差 |
| `{{mean_time_to_detect}}` `{{detection_gap}}` | MTTD / 检测空窗 | §5.2 推导 |
| `{{p0_count}}` `{{p1_count}}` `{{p2_count}}` `{{p3_count}}` | 分层计数 | findings[] 聚合 |
| `{{compromised_count}}` | 失陷主机数 | ir-investigator.scope_assessment |
| `{{public_attack_surface}}` | 公开攻击面数 | 无需认证的 finding 数 |
| `{{desensitized}}` | 脱敏标记 | 恒 true |
| `{{attack_path_map}}` | §3 路径地图正文 | 按模式渲染 |
| `{{executive_summary}}` `{{verdict_one_liner}}` | 摘要 / 一句话结论 | |
| `{{mrs_1..3}}` `{{mrs_coverage}}` | 最小修复集 | §7.1 |
| `{{ioc_total}}` 等 | IOC 计数 | iocs-*.json 聚合 |
