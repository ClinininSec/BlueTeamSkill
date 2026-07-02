# findings.json 标准输出格式

> 本模板定义 `hvv-defender` skill 在**任意模式收尾阶段**与 `final-report.md` 同生的机器可读伴生文件 `findings.json` 的统一 schema。
>
> 它是 `final-report.md §4 分层发现详情` + `§3 攻击路径地图` + `§2 判定与影响` 的机器可读镜像，二者字段一一对应。
>
> - `findings[]` 每条严格遵循 `references/rule-id-namespaces.md §三` 的 **8 字段告警契约**
> - `attack_paths[]` 直接消费 `agents/ir-investigator.md` emit 的 `kill_chain` 结构
> - `ioc_ref` 指向 `assets/ioc-extract.md` 定义的 IOC 文件
>
> 与主流 SIEM（Splunk lookup / ELK `_source` / QRadar CSV）及工单系统兼容，可直接 import。

---

## 1. 顶层结构

```json
{
  "version": "0.1",
  "generated_at": "2026-06-30T18:00:00+08:00",
  "case_id": "IR-2026-06-30-<host_hash>",
  "mode": "monitor | audit | traffic | ir | remote",
  "customer": "<customer>",
  "skill_version": "hvv-defender@0.4-M1",
  "desensitized": true,
  "verdict": "confirmed_intrusion",
  "confidence": 0.85,
  "dwell_time_hours": 18.7,
  "summary": { "p0": 3, "p1": 12, "p2": 40, "p3": 120, "total": 175 },
  "findings": [ ... ],
  "attack_paths": [ ... ],
  "ioc_ref": "iocs-IR-2026-06-30-<host_hash>.json",
  "attachments": [ "incident-report.md", "timeline-merged.ndjson" ]
}
```

### 顶层字段说明

| 字段 | 必填 | 取值 | 说明 |
|---|---|---|---|
| `version` | ✅ | string | findings schema 版本，当前 "0.1" |
| `generated_at` | ✅ | ISO 8601 | 生成时间，含时区 |
| `case_id` | ✅ | string | 案件号，与 `final-report.md` `case_id` 一致 |
| `mode` | ✅ | enum | 来源模式（5 选 1） |
| `customer` | ✅ | string | 客户标识（脱敏后） |
| `skill_version` | ✅ | string | 用于回溯规则版本 |
| `desensitized` | ✅ | bool | 必须为 true（已过 `desensitize.py`） |
| `verdict` | ✅ | enum | 见下"verdict 取值" |
| `confidence` | ✅ | float 0.0-1.0 | 判定置信度 |
| `dwell_time_hours` | ⛔ | float | ir/audit 必填；monitor/remote 可空 |
| `summary` | ✅ | object | 分层计数聚合 |
| `findings` | ✅ | array | 详见 §2（8 字段契约 + 扩展） |
| `attack_paths` | ⛔ | array | ir/traffic/audit 必填；monitor/remote 可空。详见 §3 |
| `ioc_ref` | ✅ | string | 指向 `iocs-<case_id>.json`（ioc-extract.md schema） |
| `attachments` | ✅ | array | 附件文件名清单（与 final-report.md §10 一致） |

### verdict 取值（与 final-report.md §2 一致）

| verdict | 含义 |
|---|---|
| `confirmed_intrusion` | 已确认入侵 |
| `high_suspicion` | 高度疑似，证据待补 |
| `inconclusive` | 证据不足，列出还需采集什么 |
| `no_intrusion` | 未发现入侵（批次正常 / 异常为误报） |

---

## 2. findings[] —— 单条发现 schema（8 字段契约 + 3 扩展）

```json
{
  "id": "P0-001",
  "severity": "P0",
  "category": "rce",
  "evidence": "ts=2026-06-30T08:31:47 src_ip=192.168.1.xxx uri=/api/login method=POST status=200 ua=Apache-HttpClient payload_excerpt=...'@type'...",
  "rule_id": "PLB-CE-006",
  "false_positive_prob": 0.05,
  "recommended_action": "封禁 src_ip + 升 ir 取证 + 升级 fastjson",
  "iocs": [
    {"type": "ip", "value": "192.168.1.xxx", "tag": "c2:suspect"}
  ],
  "blast_radius": "完整服务器控制 + 数据库凭证泄露",
  "confidence": "high",
  "mode": "ir"
}
```

### 字段定义

| 字段 | 必填 | 取值 | 说明 |
|---|---|---|---|
| `id` | ✅ | string | 发现 ID，如 `P0-001` / `MON-018` |
| `severity` | ✅ | `P0`/`P1`/`P2`/`P3` | 分级，见 `references/grading.md §一` |
| `category` | ✅ | string | 攻击类型（`rce`/`sqli`/`webshell`/`brute-force`/`lateral`/`recon`/`c2`/`persistence`/`data-exfil`/`anomaly` 等） |
| `evidence` | ✅ | string | 脱敏后原文 + 行号（如 `nginx-access.log:14523` 前缀 + 片段） |
| `rule_id` | ✅ | string | 命中规则 ID（`R-*`/`PLB-*`/`SIG-*`/`CHECK-*`/`VENDOR-*` 等，命名空间见 `rule-id-namespaces.md §一`） |
| `false_positive_prob` | ✅ | float 0.0-1.0 | 误报概率，计算见 `grading.md §四` |
| `recommended_action` | ✅ | string | 处置建议（不含破坏性操作；处置由客户执行） |
| `iocs` | ⛔ | array | 关联 IOC（可空）；每条含 `type`/`value`/`tag`，完整 schema 见 `ioc-extract.md §2` |
| `blast_radius` | ✅ | string | 影响范围（如"完整服务器控制"/"10万+用户 PII"） |
| `confidence` | ✅ | `high`/`medium`/`low` | 本发现置信度（与 IOC 的 confidence 评定标准一致） |
| `mode` | ✅ | enum | 发现来源模式（便于跨模式聚合时溯源） |

> 前 8 字段 = `rule-id-namespaces.md §三` 的跨模式统一告警契约，**严格一致**；后 3 字段（`blast_radius`/`confidence`/`mode`）为终报伴生扩展。

---

## 3. attack_paths[] —— 攻击路径 schema

> 直接消费 `agents/ir-investigator.md` emit 的 `kill_chain` 结构，归一为路径节点。ir 模式必填；traffic/audit 有链时填；monitor/remote 可空。

```json
{
  "id": "PATH-1",
  "label": "公开接口 → RCE → C2",
  "tactic_chain": ["T1592", "T1190", "T1059.004", "TA0003", "TA0011"],
  "nodes": [
    {
      "tactic": "TA0001_Initial_Access",
      "technique": "T1190_Exploit_Public_Facing_App",
      "narrative": "8080 端口 OA fastjson 反序列化获得 web 容器权限",
      "evidence": [
        {"source": "nginx-access.log:14523", "ts": "2026-06-30T08:31:47+08:00", "snippet": "POST /api/login ... '@type' ..."}
      ],
      "finding_ref": "P0-001"
    }
  ],
  "complexity": "low",
  "status": "confirmed"
}
```

### 字段定义

| 字段 | 必填 | 取值 | 说明 |
|---|---|---|---|
| `id` | ✅ | string | 路径 ID，如 `PATH-1` |
| `label` | ⛔ | string | 路径一句话标签（如"公开接口→RCE→C2"） |
| `tactic_chain` | ✅ | array | MITRE ATT&CK 战术/技术 ID 序列（T-XXXX / TA-XXXX） |
| `nodes` | ✅ | array | 路径节点，结构 = ir-investigator `kill_chain[]` 单节点 |
| `nodes[].tactic` `technique` `narrative` `evidence` | ✅ | | 与 ir-investigator emit 结构一致 |
| `nodes[].finding_ref` | ⛔ | string | 关联到 `findings[]` 的 `id`，便于双向追溯 |
| `complexity` | ✅ | `low`/`medium`/`high` | 攻击复杂度（借参考模板评分映射） |
| `status` | ✅ | `confirmed`/`suspect`/`attempted` | 路径确认状态 |

### 模式形态

- **ir**：`tactic_chain` 完整 MITRE kill chain（最多 13 节点）
- **traffic**：`nodes` 为 flow/conn 节点（src→dst + 检测规则），`tactic_chain` 多为 `[TA0011_C2]`
- **audit**：`nodes` 为跨日志源异常节点（nginx→auth→nginx）
- **monitor**：通常无 `attack_paths`，用 `findings[]` 的关联簇（CLU-*）替代
- **remote**：`nodes` 为采集→发现节点；Tier 3 处置节点带 `rule_id=R-REM-DISP-*`

---

## 4. 与 final-report.md 的字段对应

| final-report.md 章节 | findings.json 字段 |
|---|---|
| §1 执行摘要 分层计数表 | `summary` |
| §2 判定与影响 | `verdict` / `confidence` / `dwell_time_hours` |
| §3 攻击路径地图 | `attack_paths` |
| §4 分层发现详情（P0/P1 卡 + P2/P3 汇总） | `findings` |
| §6 IOC 清单 | `ioc_ref`（指向 iocs-*.json） |
| §10 附件 | `attachments` |
| meta 块 | `case_id` / `mode` / `customer` / `skill_version` / `desensitized` / `generated_at` |

---

## 5. 文件存储约定

| 模式 | 文件命名 | 位置 |
|---|---|---|
| monitor | `findings-MON-<date>.json` | 客户值守目录 |
| audit | `findings-AUD-<date>-<system>.json` | 审计案件目录 |
| traffic | `findings-TRAF-<date>-<pcap>.json` | 流量案件目录 |
| ir | `findings-<case_id>.json` | incident 案件目录 |
| remote | `findings-REM-<date>-<host>.json` | remote 案件目录 |

文件后缀必须为 `.json`，UTF-8 无 BOM，`indent=2`。与 `iocs-<case_id>.json` 同目录存放。

---

## 6. SIEM / 工单系统导入

- **Splunk**：`findings[]` 每条转 event，`rule_id` 作 `tag`，`evidence` 作 `_raw` 上下文
- **ELK**：整体作为 `_source` 索引；`findings` 为 nested 类型，便于按 `severity`/`rule_id` 聚合
- **QRadar / 工单系统**：拍平 `findings[]` 为 CSV `id,severity,category,rule_id,false_positive_prob,recommended_action`
- **SIEM 联动**：`ioc_ref` 指向的 IOC 文件 import 为 lookup 表，`findings[].iocs` 与之 join 形成"发现 → IOC → 持续监控"闭环

`hvv-defender` v0.4-M1 不提供自动导入脚本（属"厂商对接"，v0.3+ 引入）。值守班可手工转换或写桥接脚本。

---

## 7. 校验清单（写入前自查）

- [ ] `version` `generated_at` `case_id` `mode` `customer` `summary` `findings` `ioc_ref` `attachments` 顶层字段齐全
- [ ] `desensitized` 为 `true`，且确实跑过 `desensitize.py`
- [ ] `mode` 在 5 枚举内
- [ ] `verdict` 在 4 枚举内
- [ ] 每条 `findings[]` 含 8 契约字段 + `blast_radius` + `confidence` + `mode`
- [ ] `severity` 仅 P0/P1/P2/P3；`confidence` 仅 high/medium/low
- [ ] `false_positive_prob` ∈ [0.0, 1.0]
- [ ] `summary` 的 p0/p1/p2/p3 计数 = `findings[]` 按 severity 聚合的结果
- [ ] `attack_paths[].nodes[].finding_ref`（若有）能在 `findings[]` 中找到对应 `id`
- [ ] `ioc_ref` 指向的文件存在且符合 `ioc-extract.md` schema
- [ ] `evidence` 字段无未脱敏的私网 IP / 内部域名 / 用户名 / 客户名

---

## 8. 示例（完整 mini 文件 · ir 形态）

```json
{
  "version": "0.1",
  "generated_at": "2026-06-30T18:00:00+08:00",
  "case_id": "IR-2026-06-30-a1b2c3",
  "mode": "ir",
  "customer": "<customer>",
  "skill_version": "hvv-defender@0.4-M1",
  "desensitized": true,
  "verdict": "confirmed_intrusion",
  "confidence": 0.9,
  "dwell_time_hours": 18.7,
  "summary": { "p0": 1, "p1": 1, "p2": 0, "p3": 0, "total": 2 },
  "findings": [
    {
      "id": "P0-001",
      "severity": "P0",
      "category": "rce",
      "evidence": "nginx-access.log:14523 | ts=2026-06-30T08:31:47 src_ip=192.168.1.xxx uri=/api/login method=POST status=200 ua=Apache-HttpClient payload_excerpt=...'@type'...",
      "rule_id": "PLB-CE-006",
      "false_positive_prob": 0.05,
      "recommended_action": "封禁 src_ip + 升 ir 取证 + 升级 fastjson",
      "iocs": [{"type": "ip", "value": "192.168.1.xxx", "tag": "c2:suspect"}],
      "blast_radius": "完整服务器控制 + 数据库凭证泄露",
      "confidence": "high",
      "mode": "ir"
    },
    {
      "id": "P1-001",
      "severity": "P1",
      "category": "persistence",
      "evidence": "09-persistence.txt:42 | /etc/cron.d/.update 内容 * * * * * root /tmp/.X11-lock",
      "rule_id": "CHECK-LX-7.3",
      "false_positive_prob": 0.1,
      "recommended_action": "删除 cron 任务（客户执行）+ 审计所有 cron.d",
      "iocs": [{"type": "path", "value": "/etc/cron.d/.update", "tag": "persistence:cron"}],
      "blast_radius": "root 级持久化后门",
      "confidence": "high",
      "mode": "ir"
    }
  ],
  "attack_paths": [
    {
      "id": "PATH-1",
      "label": "公开接口 → RCE → 持久化 → C2",
      "tactic_chain": ["T1190", "T1059.004", "TA0003", "TA0011"],
      "nodes": [
        {
          "tactic": "TA0001_Initial_Access",
          "technique": "T1190_Exploit_Public_Facing_App",
          "narrative": "8080 端口 OA fastjson 反序列化获得 web 容器权限",
          "evidence": [{"source": "nginx-access.log:14523", "ts": "2026-06-30T08:31:47+08:00", "snippet": "POST /api/login ... '@type' ..."}],
          "finding_ref": "P0-001"
        }
      ],
      "complexity": "low",
      "status": "confirmed"
    }
  ],
  "ioc_ref": "iocs-IR-2026-06-30-a1b2c3.json",
  "attachments": ["incident-report.md", "timeline-merged.ndjson", "hvv-collect-oa-host-20260630.tar.gz"]
}
```

---

## 9. 示例（monitor 形态轻量）

```json
{
  "version": "0.1",
  "generated_at": "2026-06-30T18:00:00+08:00",
  "case_id": "MON-2026-06-30",
  "mode": "monitor",
  "customer": "<customer>",
  "skill_version": "hvv-defender@0.4-M1",
  "desensitized": true,
  "verdict": "no_intrusion",
  "confidence": 0.8,
  "summary": { "p0": 0, "p1": 2, "p2": 12, "p3": 45, "total": 59 },
  "findings": [
    {
      "id": "MON-005",
      "severity": "P1",
      "category": "sqli",
      "evidence": "vendor-qax-ngsoc alert | src_ip=192.168.1.xxx uri=/search?keyword=' UNION SELECT...",
      "rule_id": "PLB-SQ-003",
      "false_positive_prob": 0.3,
      "recommended_action": "转 audit 深挖该 IP nginx 完整足迹",
      "iocs": [{"type": "ip", "value": "192.168.1.xxx", "tag": "scanner:tool"}],
      "blast_radius": "疑似数据泄露（待复核）",
      "confidence": "medium",
      "mode": "monitor"
    }
  ],
  "attack_paths": [],
  "ioc_ref": "iocs-MON-2026-06-30.json",
  "attachments": ["daily-report.md", "handover.md"]
}
```
